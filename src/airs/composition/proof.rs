//! Four-proof bundle for one canonical composite Texas Poker transition.

use bincode::Options;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use super::air::{
    BetCollectionAir, ComponentTexasAir, RoundAdvanceAir, SeatUpdateAir, SettlementAir,
};
use super::{
    CompositeTransitionPlan, StageKind, derive_composite_transition_plan_from_task,
    supports_composite_proof,
};
use crate::airs::TexasAir;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::prover::{MethodProof, prove_method};
use crate::public_inputs::TexasPublicInputs;
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::{
    BATCH_LOG_SIZE, SINGLE_METHOD_LOG_SIZE, gen_method_trace, is_tagged_batch_log_size,
    tagged_batch_log_size,
};
use crate::verifier::verify_method_against;

/// Durable composition-proof bundle schema version.
pub const COMPOSITION_PROOF_BUNDLE_VERSION: u8 = 1;

/// Durable tagged-union batched composition-proof bundle schema version.
///
/// Version 6 binds the proof to the actor-less crypto command stream and durable batch id. Older
/// canonical payload layouts are intentionally rejected.
pub const COMPOSITION_BATCH_PROOF_BUNDLE_VERSION: u8 = 6;

/// Conservative maximum transitions packed into one 1024-row tagged Stage proof.
///
/// One transition can activate all four canonical stages, so reserving four rows per task keeps
/// service-side chunking deterministic. Batches with fewer active stages still use only their
/// actual rows; the remainder is canonical zero padding.
pub const MAX_COMPOSITION_BATCH_TASKS: usize = (1 << BATCH_LOG_SIZE) / 4;

const TAGGED_STAGE_PAYLOAD_COLUMNS: usize = super::settlement::NUM_COLUMNS;
const TAGGED_STAGE_NUM_COLUMNS: usize = TAGGED_STAGE_PAYLOAD_COLUMNS + 2;

const MAX_COMPONENT_STARK_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMPOSITION_BUNDLE_BYTES: usize = 4 * MAX_COMPONENT_STARK_BYTES + 64 * 1024;
const MAX_COMPOSITION_BATCH_BUNDLE_BYTES: usize = MAX_COMPONENT_STARK_BYTES + 64 * 1024;

/// One independently committed STARK proof inside a four-stage bundle.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedComponentProof {
    stage_kind: StageKind,
    log_size: u32,
    num_columns: u32,
    stark_proof_bytes: Vec<u8>,
    root_binding: crate::state_root_binding::ArchivedStateRootBindingProof,
}

impl ArchivedComponentProof {
    /// Component discriminator committed by this proof envelope.
    #[must_use]
    pub const fn stage_kind(&self) -> StageKind {
        self.stage_kind
    }

    /// Number of original trace columns committed by this proof envelope.
    pub fn num_columns(&self) -> TexasAirResult<usize> {
        usize::try_from(self.num_columns).map_err(|_| {
            TexasAirError::SerializationError(
                "component proof column count does not fit usize".into(),
            )
        })
    }

    fn from_stark(
        stage_kind: StageKind,
        log_size: u32,
        num_columns: usize,
        proof: &StarkProof<Poseidon252MerkleHasher>,
        root_binding: crate::state_root_binding::ArchivedStateRootBindingProof,
    ) -> TexasAirResult<Self> {
        let num_columns = u32::try_from(num_columns).map_err(|_| {
            TexasAirError::SerializationError("component column count exceeds u32".into())
        })?;
        let stark_proof_bytes = bincode_options().serialize(proof).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "component Stwo proof serialization failed: {error}"
            ))
        })?;
        let archive = Self {
            stage_kind,
            log_size,
            num_columns,
            stark_proof_bytes,
            root_binding,
        };
        archive.validate()?;
        Ok(archive)
    }

    fn decode_stark(&self) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
        self.validate()?;
        bincode_options()
            .reject_trailing_bytes()
            .deserialize(&self.stark_proof_bytes)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "component Stwo proof decoding failed: {error}"
                ))
            })
    }

    fn validate(&self) -> TexasAirResult<()> {
        if self.log_size != SINGLE_METHOD_LOG_SIZE || self.num_columns == 0 {
            return Err(TexasAirError::SerializationError(
                "invalid component proof trace shape".into(),
            ));
        }
        if self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > MAX_COMPONENT_STARK_BYTES
        {
            return Err(TexasAirError::SerializationError(
                "invalid component Stwo proof length".into(),
            ));
        }
        Ok(())
    }
}

/// Four independent STARK proofs linked by one canonical transition-plan digest.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCompositionProofBundle {
    version: u8,
    method_kind: MethodKind,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
    plan_digest: [u8; 32],
    stages: [ArchivedComponentProof; 4],
}

impl ArchivedCompositionProofBundle {
    /// Composite plan digest shared by every child proof.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Child proofs in SeatUpdate, BetCollection, RoundAdvance, Settlement order.
    #[must_use]
    pub const fn stages(&self) -> &[ArchivedComponentProof; 4] {
        &self.stages
    }

    /// Validate the bounded archive envelope without trusting proof-carried task scope.
    ///
    /// Full verification must still call [`verify_composition_bundle`] with the canonical task.
    pub fn validate(&self) -> TexasAirResult<()> {
        self.validate_envelope()
    }

    /// Encode the complete bounded bundle as canonical Borsh bytes.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_envelope()?;
        borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition proof bundle Borsh encoding failed: {error}"
            ))
        })
    }

    /// Decode a complete bounded bundle and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_COMPOSITION_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid composition proof bundle length".into(),
            ));
        }
        let bundle = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition proof bundle Borsh decoding failed: {error}"
            ))
        })?;
        bundle.validate_envelope()?;
        Ok(bundle)
    }

    fn validate_envelope(&self) -> TexasAirResult<()> {
        if self.version != COMPOSITION_PROOF_BUNDLE_VERSION
            || !supports_composite_proof(self.method_kind)
        {
            return Err(TexasAirError::SerializationError(
                "unsupported composition proof bundle envelope".into(),
            ));
        }
        for (index, stage) in self.stages.iter().enumerate() {
            stage.validate()?;
            if usize::from(stage.stage_kind as u8) != index {
                return Err(TexasAirError::SerializationError(
                    "component proofs are not in canonical stage order".into(),
                ));
            }
        }
        Ok(())
    }
}

/// One tagged-union Stage proof over an ordered batch of canonical transitions.
///
/// The verifier receives the exact tasks separately, replays each transition, rebuilds all
/// active Stage rows (including deterministic padding), and recomputes the complete trace
/// commitment. Proof-carried rows and task metadata are never trusted. Rows are ordered by task,
/// then by `SeatUpdate -> BetCollection -> RoundAdvance -> Settlement`; inactive stages consume
/// no row.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCompositionBatchProofBundle {
    version: u8,
    batch_id: [u8; 32],
    table_id: u64,
    hand_id: u32,
    first_call_seq: u32,
    last_call_seq: u32,
    task_count: u16,
    stage_row_count: u16,
    batch_digest: [u8; 32],
    stage_proof: ArchivedTaggedStageProof,
}

/// Durable single-proof envelope for a heterogeneous tagged Stage trace.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedTaggedStageProof {
    log_size: u32,
    num_columns: u32,
    stark_proof_bytes: Vec<u8>,
}

impl ArchivedTaggedStageProof {
    /// Number of columns in the tagged-union trace.
    pub fn num_columns(&self) -> TexasAirResult<usize> {
        usize::try_from(self.num_columns).map_err(|_| {
            TexasAirError::SerializationError(
                "tagged Stage proof column count does not fit usize".into(),
            )
        })
    }

    fn from_stark(
        log_size: u32,
        num_columns: usize,
        proof: &StarkProof<Poseidon252MerkleHasher>,
    ) -> TexasAirResult<Self> {
        let num_columns = u32::try_from(num_columns).map_err(|_| {
            TexasAirError::SerializationError("tagged Stage width exceeds u32".into())
        })?;
        let stark_proof_bytes = bincode_options().serialize(proof).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged Stage Stwo proof serialization failed: {error}"
            ))
        })?;
        let archive = Self {
            log_size,
            num_columns,
            stark_proof_bytes,
        };
        archive.validate()?;
        Ok(archive)
    }

    fn decode_stark(&self) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
        self.validate()?;
        bincode_options()
            .reject_trailing_bytes()
            .deserialize(&self.stark_proof_bytes)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "tagged Stage Stwo proof decoding failed: {error}"
                ))
            })
    }

    fn validate(&self) -> TexasAirResult<()> {
        if !is_tagged_batch_log_size(self.log_size)
            || usize::try_from(self.num_columns).ok() != Some(TAGGED_STAGE_NUM_COLUMNS)
            || self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > MAX_COMPONENT_STARK_BYTES
        {
            return Err(TexasAirError::SerializationError(
                "invalid tagged Stage proof envelope".into(),
            ));
        }
        Ok(())
    }
}

impl ArchivedCompositionBatchProofBundle {
    /// Domain-separated identifier shared by tagged method and Stage proofs.
    #[must_use]
    pub const fn batch_id(&self) -> [u8; 32] {
        self.batch_id
    }

    /// Number of canonical transitions packed into each Stage proof.
    #[must_use]
    pub const fn task_count(&self) -> u16 {
        self.task_count
    }

    /// Number of actual active Stage rows before deterministic padding.
    #[must_use]
    pub const fn stage_row_count(&self) -> u16 {
        self.stage_row_count
    }

    /// Digest of the ordered authenticated task commitments.
    #[must_use]
    pub const fn batch_digest(&self) -> [u8; 32] {
        self.batch_digest
    }

    /// The single tagged-union Stage proof.
    #[must_use]
    pub const fn stage_proof(&self) -> &ArchivedTaggedStageProof {
        &self.stage_proof
    }

    /// Rebuild durable per-method references into this batch.
    ///
    /// References are never trusted from the archive alone: every Stage span is recomputed from
    /// canonical VM replay and the normalized transition plan.
    pub fn method_references(
        &self,
        tasks: &[crate::prove_task::ProveTask],
    ) -> TexasAirResult<Vec<crate::prove_task::MethodBatchReferenceV2>> {
        self.validate()?;
        validate_batch_tasks(tasks)?;
        let row_count = u16::try_from(tasks.len()).map_err(|_| {
            TexasAirError::SpecViolation("method batch row count exceeds u16".into())
        })?;
        let mut stage_start_row = 0u16;
        let mut references = Vec::with_capacity(tasks.len());
        for (row_index, task) in tasks.iter().enumerate() {
            let stage_row_count = if supports_composite_proof(task.method_kind) {
                let plan = derive_composite_transition_plan_from_task(task)?;
                [
                    plan.seat_update.active,
                    plan.bet_collection.active,
                    plan.round_advance.active,
                    plan.settlement.active,
                ]
                .into_iter()
                .filter(|active| *active)
                .count()
            } else {
                0
            };
            let stage_row_count = u8::try_from(stage_row_count).expect("four fixed stages");
            let reference = crate::prove_task::MethodBatchReferenceV2 {
                batch_id: self.batch_id,
                row_index: u16::try_from(row_index).map_err(|_| {
                    TexasAirError::SpecViolation("method batch row index exceeds u16".into())
                })?,
                row_count,
                stage_start_row,
                stage_row_count,
            };
            reference.validate()?;
            stage_start_row = stage_start_row
                .checked_add(u16::from(stage_row_count))
                .ok_or_else(|| {
                    TexasAirError::SpecViolation("tagged Stage row offset overflow".into())
                })?;
            references.push(reference);
        }
        let (_, batch_id, _) =
            crate::prove_task::MethodBatchV2::commitment_from_replayed_tasks(tasks)?;
        if batch_id != self.batch_id || row_count != self.task_count {
            return Err(TexasAirError::SpecViolation(
                "method-batch reference scope does not match the Stage archive".into(),
            ));
        }
        if stage_start_row != self.stage_row_count {
            return Err(TexasAirError::SpecViolation(
                "reconstructed Stage spans do not cover the archived Stage row count".into(),
            ));
        }
        Ok(references)
    }

    /// Validate the bounded archive envelope without trusting proof-carried task scope.
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.version != COMPOSITION_BATCH_PROOF_BUNDLE_VERSION
            || self.batch_id == [0; 32]
            || self.task_count == 0
            || usize::from(self.task_count) > MAX_COMPOSITION_BATCH_TASKS
            || usize::from(self.stage_row_count) > (1 << BATCH_LOG_SIZE)
            || usize::from(self.stage_row_count) > usize::from(self.task_count) * 4
            || self.first_call_seq > self.last_call_seq
        {
            return Err(TexasAirError::SerializationError(
                "invalid composition batch proof envelope".into(),
            ));
        }
        self.stage_proof.validate()?;
        Ok(())
    }

    /// Encode the complete bounded bundle as canonical Borsh bytes.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition batch proof Borsh encoding failed: {error}"
            ))
        })?;
        if bytes.len() > MAX_COMPOSITION_BATCH_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "composition batch proof bundle exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Decode a complete bounded bundle and reject trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_COMPOSITION_BATCH_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid composition batch proof bundle length".into(),
            ));
        }
        let bundle = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "composition batch proof Borsh decoding failed: {error}"
            ))
        })?;
        bundle.validate()?;
        Ok(bundle)
    }
}

/// Prove and independently verify all four components for a supported task.
///
/// Methods outside the composition pipeline return `Ok(None)`. Supported methods always return
/// four proofs, including deterministic inactive proofs for stages not executed by that dispatch.
pub fn prove_composition_bundle(
    task: &crate::prove_task::ProveTask,
) -> TexasAirResult<Option<ArchivedCompositionProofBundle>> {
    if !supports_composite_proof(task.method_kind) {
        return Ok(None);
    }
    let plan = derive_composite_transition_plan_from_task(task)?;
    let base = base_public_inputs(task)?;
    let airs = build_airs(&plan, &base);
    let ((seat_update, bet_collection), (round_advance, settlement)) = rayon::join(
        || {
            rayon::join(
                || prove_stage(StageKind::SeatUpdate, airs.0, &base),
                || prove_stage(StageKind::BetCollection, airs.1, &base),
            )
        },
        || {
            rayon::join(
                || prove_stage(StageKind::RoundAdvance, airs.2, &base),
                || prove_stage(StageKind::Settlement, airs.3, &base),
            )
        },
    );
    let stages = [seat_update?, bet_collection?, round_advance?, settlement?];
    let bundle = ArchivedCompositionProofBundle {
        version: COMPOSITION_PROOF_BUNDLE_VERSION,
        method_kind: task.method_kind,
        table_id: task.table_id,
        hand_id: task.hand_id,
        call_seq: task.call_seq,
        plan_digest: plan.plan_digest,
        stages,
    };
    bundle.validate_envelope()?;
    Ok(Some(bundle))
}

/// Reconstruct a canonical task and verify every independent component proof and stage link.
pub fn verify_composition_bundle(
    task: &crate::prove_task::ProveTask,
    bundle: &ArchivedCompositionProofBundle,
) -> TexasAirResult<()> {
    bundle.validate_envelope()?;
    if bundle.method_kind != task.method_kind
        || bundle.table_id != task.table_id
        || bundle.hand_id != task.hand_id
        || bundle.call_seq != task.call_seq
    {
        return Err(TexasAirError::SpecViolation(
            "composition proof bundle scope does not match canonical task".into(),
        ));
    }
    let plan = derive_composite_transition_plan_from_task(task)?;
    plan.validate_composition()?;
    if bundle.plan_digest != plan.plan_digest {
        return Err(TexasAirError::SpecViolation(
            "composition proof bundle plan digest mismatch".into(),
        ));
    }
    let base = base_public_inputs(task)?;
    let airs = build_airs(&plan, &base);
    let ((seat_update, bet_collection), (round_advance, settlement)) = rayon::join(
        || {
            rayon::join(
                || verify_stage(&bundle.stages[0], StageKind::SeatUpdate, airs.0, &base),
                || verify_stage(&bundle.stages[1], StageKind::BetCollection, airs.1, &base),
            )
        },
        || {
            rayon::join(
                || verify_stage(&bundle.stages[2], StageKind::RoundAdvance, airs.2, &base),
                || verify_stage(&bundle.stages[3], StageKind::Settlement, airs.3, &base),
            )
        },
    );
    seat_update?;
    bet_collection?;
    round_advance?;
    settlement
}

fn base_public_inputs(task: &crate::prove_task::ProveTask) -> TexasAirResult<TexasPublicInputs> {
    let mut public_inputs = TexasPublicInputs::from_tables(
        &task.pre_table,
        &task.post_table,
        task.method_kind,
        task.table_id,
        task.hand_id,
        task.call_seq,
    )?;
    public_inputs.bind_dispatch_call(
        task.context.clone(),
        task.selector(),
        task.raw_args.clone(),
    )?;
    Ok(public_inputs)
}

fn build_airs(
    plan: &CompositeTransitionPlan,
    public_inputs: &TexasPublicInputs,
) -> (
    SeatUpdateAir,
    BetCollectionAir,
    RoundAdvanceAir,
    SettlementAir,
) {
    (
        SeatUpdateAir::new(
            SINGLE_METHOD_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.seat_update.clone(),
            plan.link(StageKind::SeatUpdate).clone(),
        ),
        BetCollectionAir::new(
            SINGLE_METHOD_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.bet_collection.clone(),
            plan.link(StageKind::BetCollection).clone(),
        ),
        RoundAdvanceAir::new(
            SINGLE_METHOD_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.round_advance.clone(),
            plan.link(StageKind::RoundAdvance).clone(),
        ),
        SettlementAir::new(
            SINGLE_METHOD_LOG_SIZE,
            plan.method_kind,
            public_inputs,
            plan.settlement.clone(),
            plan.link(StageKind::Settlement).clone(),
        ),
    )
}

fn stage_public_inputs<A: TexasAir>(
    base: &TexasPublicInputs,
    air: &A,
    row: &[M31],
) -> TexasAirResult<TexasPublicInputs> {
    let mut public_inputs = base.clone();
    public_inputs.expected_trace_row = None;
    public_inputs.component = air.statement().component;
    public_inputs.bind_expected_trace_row(row)?;
    Ok(public_inputs)
}

fn prove_stage<A: ComponentTexasAir>(
    stage_kind: StageKind,
    air: A,
    base: &TexasPublicInputs,
) -> TexasAirResult<ArchivedComponentProof> {
    let row = air.canonical_row();
    let public_inputs = stage_public_inputs(base, &air, &row)?;
    let padding = vec![M31::from(0u32); row.len()];
    let trace = gen_method_trace(row.len(), &row, &padding)?;
    let proof = prove_method(&trace, air.clone(), row.len(), public_inputs.clone())?;
    let archive = ArchivedComponentProof::from_stark(
        stage_kind,
        proof.log_size,
        proof.num_columns,
        &proof.stark_proof,
        proof.root_binding.clone(),
    )?;
    verify_method_against(proof, air, &public_inputs)?;
    Ok(archive)
}

fn verify_stage<A: ComponentTexasAir>(
    archive: &ArchivedComponentProof,
    stage_kind: StageKind,
    air: A,
    base: &TexasPublicInputs,
) -> TexasAirResult<()> {
    let row = air.canonical_row();
    if archive.stage_kind != stage_kind
        || archive.log_size != air.log_size()
        || archive.num_columns()? != row.len()
        || row.len() != air.trace_num_columns()
    {
        return Err(TexasAirError::SerializationError(
            "component proof shape does not match canonical AIR".into(),
        ));
    }
    let public_inputs = stage_public_inputs(base, &air, &row)?;
    let proof = MethodProof {
        stark_proof: archive.decode_stark()?,
        air: air.clone(),
        log_size: air.log_size(),
        num_columns: row.len(),
        root_binding: archive.root_binding.clone(),
        public_inputs: public_inputs.clone(),
    };
    verify_method_against(proof, air, &public_inputs)
}

/// Prove one tagged-union Stage trace for an ordered contiguous batch of transitions.
///
/// The trace has exactly 1024 rows. Every active stage receives one row in canonical task/stage
/// order; inactive stages are omitted and the remaining rows are all zero. This reduces four
/// fixed Stage prover startups to one startup per batch.
///
/// # Errors
///
/// Rejects empty, oversized, cross-table, cross-hand, out-of-order, or state-chain discontinuous
/// batches. Methods outside the four-stage pipeline own zero Stage rows but remain committed by
/// the shared stream statement and tagged method proof. Every task is fully replayed before
/// proving.
pub fn prove_composition_batch(
    tasks: &[crate::prove_task::ProveTask],
) -> TexasAirResult<ArchivedCompositionBatchProofBundle> {
    prove_composition_batch_impl(tasks, true)
}

/// Produce one tagged Stage archive while deferring verification to the enclosing package.
///
/// The tagged composite prover verifies the Stage and method proofs together before issuing any
/// receipt, so verifying this child proof once more inside its constructor would duplicate the
/// same verifier-owned trace reconstruction.
pub(crate) fn prove_composition_batch_without_self_verify(
    tasks: &[crate::prove_task::ProveTask],
) -> TexasAirResult<ArchivedCompositionBatchProofBundle> {
    prove_composition_batch_impl(tasks, false)
}

fn prove_composition_batch_impl(
    tasks: &[crate::prove_task::ProveTask],
    verify_after_prove: bool,
) -> TexasAirResult<ArchivedCompositionBatchProofBundle> {
    let (trace, stage_row_count) = build_tagged_batch_trace(tasks)?;
    let statement = CompositionBatchStatement::from_tasks(
        tasks,
        stage_row_count,
        COMPOSITION_BATCH_PROOF_BUNDLE_VERSION,
    )?;
    let stage_proof = prove_tagged_batch_stage_without_self_verify(&statement, &trace)?;
    let bundle = ArchivedCompositionBatchProofBundle {
        version: COMPOSITION_BATCH_PROOF_BUNDLE_VERSION,
        batch_id: statement.batch_id,
        table_id: statement.table_id,
        hand_id: statement.hand_id,
        first_call_seq: statement.first_call_seq,
        last_call_seq: statement.last_call_seq,
        task_count: statement.task_count,
        stage_row_count: statement.stage_row_count,
        batch_digest: statement.batch_digest,
        stage_proof,
    };
    bundle.validate()?;
    if verify_after_prove {
        verify_tagged_batch_stage(&bundle.stage_proof, &statement, &trace)?;
    }
    Ok(bundle)
}

/// Replay an ordered transition batch and verify its single tagged Stage proof.
///
/// Verification recomputes each expected Stwo trace commitment from verifier-owned canonical
/// tasks and compares it with the proof commitment before invoking Stwo. This is the per-row
/// trusted binding that replaces single-row [`crate::airs::bound::BoundAir`] in batch mode.
pub fn verify_composition_batch(
    tasks: &[crate::prove_task::ProveTask],
    bundle: &ArchivedCompositionBatchProofBundle,
) -> TexasAirResult<()> {
    bundle.validate()?;
    let (trace, stage_row_count) = build_tagged_batch_trace(tasks)?;
    let statement = CompositionBatchStatement::from_tasks(tasks, stage_row_count, bundle.version)?;
    if bundle.batch_id != statement.batch_id
        || bundle.table_id != statement.table_id
        || bundle.hand_id != statement.hand_id
        || bundle.first_call_seq != statement.first_call_seq
        || bundle.last_call_seq != statement.last_call_seq
        || bundle.task_count != statement.task_count
        || bundle.stage_row_count != statement.stage_row_count
        || bundle.batch_digest != statement.batch_digest
    {
        return Err(TexasAirError::SpecViolation(
            "composition batch proof scope does not match canonical tasks".into(),
        ));
    }
    verify_tagged_batch_stage(&bundle.stage_proof, &statement, &trace)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompositionBatchStatement {
    version: u8,
    batch_id: [u8; 32],
    table_id: u64,
    hand_id: u32,
    first_call_seq: u32,
    last_call_seq: u32,
    task_count: u16,
    stage_row_count: u16,
    batch_digest: [u8; 32],
}

impl CompositionBatchStatement {
    fn from_tasks(
        tasks: &[crate::prove_task::ProveTask],
        stage_row_count: usize,
        version: u8,
    ) -> TexasAirResult<Self> {
        validate_batch_tasks(tasks)?;
        if version != COMPOSITION_BATCH_PROOF_BUNDLE_VERSION {
            return Err(TexasAirError::SpecViolation(format!(
                "unsupported composition batch statement version {version}"
            )));
        }
        if stage_row_count > (1 << BATCH_LOG_SIZE) {
            return Err(TexasAirError::SpecViolation(
                "tagged Stage batch exceeds 1024 active rows".into(),
            ));
        }
        let first = tasks.first().expect("non-empty batch validated");
        let last = tasks.last().expect("non-empty batch validated");
        let (_, batch_id, encoded) =
            crate::prove_task::MethodBatchV2::commitment_from_replayed_tasks(tasks)?;
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        hasher.update(b"zchain.texas.composition_batch.v3");
        hasher.update(&batch_id);
        hasher.update(&encoded);
        let mut batch_digest = [0u8; 32];
        hasher
            .finalize_variable(&mut batch_digest)
            .expect("32 <= 64");
        Ok(Self {
            version,
            batch_id,
            table_id: first.table_id,
            hand_id: first.hand_id,
            first_call_seq: first.call_seq,
            last_call_seq: last.call_seq,
            task_count: u16::try_from(tasks.len()).map_err(|_| {
                TexasAirError::SpecViolation("composition batch task count exceeds u16".into())
            })?,
            stage_row_count: u16::try_from(stage_row_count).map_err(|_| {
                TexasAirError::SpecViolation("tagged Stage row count exceeds u16".into())
            })?,
            batch_digest,
        })
    }

    fn mix_into<C: Channel>(&self, channel: &mut C, num_columns: usize) {
        channel.mix_u32s(&[
            0x5a43_4241,
            u32::from(self.version),
            u32::from(self.task_count),
            u32::from(self.stage_row_count),
            u32::try_from(num_columns).expect("Stage width fits u32"),
            self.hand_id,
            self.first_call_seq,
            self.last_call_seq,
        ]);
        channel.mix_u64(self.table_id);
        channel.mix_u32s(
            &self
                .batch_id
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4-byte batch-id word")))
                .collect::<Vec<_>>(),
        );
        channel.mix_u32s(
            &self
                .batch_digest
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4-byte digest word")))
                .collect::<Vec<_>>(),
        );
    }
}

fn validate_batch_tasks(tasks: &[crate::prove_task::ProveTask]) -> TexasAirResult<()> {
    if tasks.is_empty() || tasks.len() > MAX_COMPOSITION_BATCH_TASKS {
        return Err(TexasAirError::SpecViolation(format!(
            "composition batch must contain 1..={MAX_COMPOSITION_BATCH_TASKS} tasks"
        )));
    }
    let first = &tasks[0];
    for (index, task) in tasks.iter().enumerate() {
        if task.table_id != first.table_id || task.hand_id != first.hand_id {
            return Err(TexasAirError::SpecViolation(
                "composition batch crosses table or hand scope".into(),
            ));
        }
        if let Some(previous) = index.checked_sub(1).map(|i| &tasks[i]) {
            if task.call_seq
                != previous.call_seq.checked_add(1).ok_or_else(|| {
                    TexasAirError::SpecViolation("composition batch call_seq overflow".into())
                })?
            {
                return Err(TexasAirError::SpecViolation(
                    "composition batch tasks are not call_seq-contiguous".into(),
                ));
            }
            let previous_post = crate::state_root::compute_state_root(&previous.post_table)?;
            let current_pre = crate::state_root::compute_state_root(&task.pre_table)?;
            if previous_post != current_pre {
                return Err(TexasAirError::SpecViolation(
                    "composition batch tasks are not state-root-contiguous".into(),
                ));
            }
        }
    }
    Ok(())
}

fn build_tagged_batch_trace(
    tasks: &[crate::prove_task::ProveTask],
) -> TexasAirResult<(MethodTrace, usize)> {
    validate_batch_tasks(tasks)?;
    let mut active_rows = Vec::new();
    for task in tasks {
        if !supports_composite_proof(task.method_kind) {
            continue;
        }
        let plan = derive_composite_transition_plan_from_task(task)?;
        let base = base_public_inputs(task)?;
        let airs = build_airs(&plan, &base);
        let rows = [
            (
                StageKind::SeatUpdate,
                plan.seat_update.active,
                airs.0.canonical_row(),
            ),
            (
                StageKind::BetCollection,
                plan.bet_collection.active,
                airs.1.canonical_row(),
            ),
            (
                StageKind::RoundAdvance,
                plan.round_advance.active,
                airs.2.canonical_row(),
            ),
            (
                StageKind::Settlement,
                plan.settlement.active,
                airs.3.canonical_row(),
            ),
        ];
        for (stage_kind, active, mut row) in rows {
            if !active {
                continue;
            }
            if active_rows.len() >= (1 << BATCH_LOG_SIZE) {
                return Err(TexasAirError::SpecViolation(
                    "tagged Stage batch exceeds 1024 active rows".into(),
                ));
            }
            row.resize(TAGGED_STAGE_NUM_COLUMNS, M31::from(0u32));
            let tag = stage_kind as u8;
            row[TAGGED_STAGE_PAYLOAD_COLUMNS] = M31::from(u32::from(tag & 1));
            row[TAGGED_STAGE_PAYLOAD_COLUMNS + 1] = M31::from(u32::from((tag >> 1) & 1));
            active_rows.push(row);
        }
    }
    // A non-empty task batch may contain only non-composite methods. Keep one
    // canonical all-zero row capacity in that case; the AIR accepts padding.
    let log_size = tagged_batch_log_size(active_rows.len().max(1))?;
    let mut trace = MethodTrace::new(log_size, TAGGED_STAGE_NUM_COLUMNS);
    for (row_index, row) in active_rows.iter().enumerate() {
        trace.write_row(row_index, row)?;
    }
    let padding = vec![M31::from(0u32); TAGGED_STAGE_NUM_COLUMNS];
    for padding_index in active_rows.len()..(1 << log_size) {
        trace.write_row(padding_index, &padding)?;
    }
    Ok((trace, active_rows.len()))
}

#[derive(Debug, Clone)]
struct TaggedBatchStageAir {
    num_columns: usize,
    log_size: u32,
}

impl FrameworkEval for TaggedBatchStageAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.next_trace_mask();
        let stage_kind = eval.next_trace_mask();
        let stage_index = eval.next_trace_mask();
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        eval.add_constraint(stage_index.clone() - stage_kind.clone());
        eval.add_constraint((one.clone() - active.clone()) * stage_kind.clone());
        eval.add_constraint((one.clone() - active.clone()) * stage_index);
        for _ in 3..self.num_columns - 2 {
            let value = eval.next_trace_mask();
            eval.add_constraint((one.clone() - active.clone()) * value);
        }
        let tag_bit_0 = eval.next_trace_mask();
        let tag_bit_1 = eval.next_trace_mask();
        eval.add_constraint(tag_bit_0.clone() * (tag_bit_0.clone() - one.clone()));
        eval.add_constraint(tag_bit_1.clone() * (tag_bit_1.clone() - one.clone()));
        let two: E::F = M31::from(2u32).into();
        eval.add_constraint(stage_kind - tag_bit_0 - two * tag_bit_1);
        eval
    }
}

fn prove_tagged_batch_stage_without_self_verify(
    statement: &CompositionBatchStatement,
    trace: &MethodTrace,
) -> TexasAirResult<ArchivedTaggedStageProof> {
    let timing_start = crate::prove_timing::enabled().then(std::time::Instant::now);
    let config = crate::prover_context::protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = crate::prover_context::simd_twiddles(trace.log_size + blowup_log);
    let mut channel = Poseidon252Channel::default();
    statement.mix_into(&mut channel, trace.num_columns);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace.to_evaluations());
        tree_builder.commit(&mut channel);
    }
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        TaggedBatchStageAir {
            num_columns: trace.num_columns,
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))?;
    if let Some(start) = timing_start {
        crate::prove_timing::record(
            format!(
                "batch-stage:Tagged[{} tasks/{} rows]",
                statement.task_count, statement.stage_row_count
            ),
            crate::prove_timing::TimingKind::Prove,
            start,
            Some(trace.num_columns),
        );
    }
    let archive =
        ArchivedTaggedStageProof::from_stark(trace.log_size, trace.num_columns, &stark_proof)?;
    Ok(archive)
}

fn verify_tagged_batch_stage(
    archive: &ArchivedTaggedStageProof,
    statement: &CompositionBatchStatement,
    trace: &MethodTrace,
) -> TexasAirResult<()> {
    let timing_start = crate::prove_timing::enabled().then(std::time::Instant::now);
    if archive.log_size != trace.log_size || archive.num_columns()? != trace.num_columns {
        return Err(TexasAirError::SerializationError(
            "batched component proof shape does not match canonical trace".into(),
        ));
    }
    let stark_proof = archive.decode_stark()?;
    let config = crate::prover_context::protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = crate::prover_context::simd_twiddles(trace.log_size + blowup_log);

    // Recompute the exact original-trace commitment from verifier-owned rows. This closes the
    // dynamic-row gap without doubling every Stage width with matching preprocessed columns.
    let mut trusted_channel = Poseidon252Channel::default();
    let mut trusted_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree_builder = trusted_scheme.tree_builder();
        tree_builder.extend_evals(trace.to_evaluations());
        tree_builder.commit(&mut trusted_channel);
    }
    let trusted_root = trusted_scheme.roots()[0];
    let proof_trace_root = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::SerializationError("batched proof is missing trace commitment".into())
    })?;
    if proof_trace_root != trusted_root {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "batched proof trace commitment differs from verifier-reconstructed rows".into(),
        ));
    }

    let mut channel = Poseidon252Channel::default();
    statement.mix_into(&mut channel, trace.num_columns);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let preprocessed_root = *stark_proof.commitments.first().ok_or_else(|| {
        TexasAirError::SerializationError("batched proof is missing preprocessed commitment".into())
    })?;
    commitment_scheme.commit(preprocessed_root, &[], &mut channel);
    commitment_scheme.commit(
        trusted_root,
        &vec![trace.log_size; trace.num_columns],
        &mut channel,
    );
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        TaggedBatchStageAir {
            num_columns: trace.num_columns,
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
    .map_err(|error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()))?;
    if let Some(start) = timing_start {
        crate::prove_timing::record(
            format!(
                "batch-stage:Tagged[{} tasks/{} rows]",
                statement.task_count, statement.stage_row_count
            ),
            crate::prove_timing::TimingKind::Verify,
            start,
            Some(trace.num_columns),
        );
    }
    Ok(())
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_COMPONENT_STARK_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root_binding() -> crate::state_root_binding::ArchivedStateRootBindingProof {
        use crate::state_root_binding::StateRootEndpointStatement;
        let endpoint = StateRootEndpointStatement::from_preimage(vec![1, 2, 3]);
        crate::state_root_binding::prove_state_root_binding(endpoint.clone(), endpoint)
            .expect("test binding proves")
    }

    fn stage(stage_kind: StageKind, num_columns: usize) -> ArchivedComponentProof {
        ArchivedComponentProof {
            stage_kind,
            log_size: SINGLE_METHOD_LOG_SIZE,
            num_columns: u32::try_from(num_columns).unwrap(),
            stark_proof_bytes: vec![1],
            root_binding: test_root_binding(),
        }
    }

    fn envelope() -> ArchivedCompositionProofBundle {
        ArchivedCompositionProofBundle {
            version: COMPOSITION_PROOF_BUNDLE_VERSION,
            method_kind: MethodKind::Check,
            table_id: 7,
            hand_id: 3,
            call_seq: 9,
            plan_digest: [4; 32],
            stages: [
                stage(
                    StageKind::SeatUpdate,
                    super::super::seat_update::NUM_COLUMNS,
                ),
                stage(
                    StageKind::BetCollection,
                    super::super::bet_collection::NUM_COLUMNS,
                ),
                stage(
                    StageKind::RoundAdvance,
                    super::super::round_advance::NUM_COLUMNS,
                ),
                stage(StageKind::Settlement, super::super::settlement::NUM_COLUMNS),
            ],
        }
    }

    fn batch_envelope() -> ArchivedCompositionBatchProofBundle {
        ArchivedCompositionBatchProofBundle {
            version: COMPOSITION_BATCH_PROOF_BUNDLE_VERSION,
            batch_id: [7; 32],
            table_id: 7,
            hand_id: 3,
            first_call_seq: 9,
            last_call_seq: 34,
            task_count: 26,
            stage_row_count: 63,
            batch_digest: [8; 32],
            stage_proof: ArchivedTaggedStageProof {
                log_size: SINGLE_METHOD_LOG_SIZE,
                num_columns: u32::try_from(TAGGED_STAGE_NUM_COLUMNS).unwrap(),
                stark_proof_bytes: vec![1],
            },
        }
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn archive_roundtrip_preserves_canonical_stage_order() {
        let bundle = envelope();
        let bytes = bundle.to_bytes().unwrap();
        let decoded = ArchivedCompositionProofBundle::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[ignore = "slow prove (~6s); full gate runs `--include-ignored`"]
    #[test]
    fn archive_rejects_reordered_or_duplicated_stages() {
        let mut bundle = envelope();
        bundle.stages.swap(0, 1);
        assert!(bundle.to_bytes().is_err());
        let mut bundle = envelope();
        bundle.stages[3].stage_kind = StageKind::RoundAdvance;
        assert!(bundle.to_bytes().is_err());
    }

    #[test]
    fn batch_archive_roundtrip_preserves_scope_and_tagged_stage_shape() {
        let bundle = batch_envelope();
        let bytes = bundle.to_bytes().unwrap();
        let decoded = ArchivedCompositionBatchProofBundle::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn old_batch_versions_are_rejected() {
        let mut bundle = batch_envelope();
        bundle.version = COMPOSITION_BATCH_PROOF_BUNDLE_VERSION - 1;
        assert!(bundle.to_bytes().is_err());
    }

    #[test]
    fn batch_archive_rejects_empty_or_invalid_tagged_envelope() {
        let mut bundle = batch_envelope();
        bundle.task_count = 0;
        assert!(bundle.to_bytes().is_err());

        let mut bundle = batch_envelope();
        bundle.stage_proof.num_columns = 1;
        assert!(bundle.to_bytes().is_err());
    }
}
