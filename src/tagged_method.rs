//! One heterogeneous tagged method STARK over narrow method-payload v2 rows.
//!
//! The host verifier still replays the complete VM transition and native admin/Mental Poker
//! verification before constructing each [`MethodPayloadV2`]. The STARK commits the ordered
//! authorization/orchestration rows once per batch; checked amount and settlement witnesses stay
//! in the separately linked tagged Stage proof.

use bincode::Options;
use blake2::Blake2bVar;
use starknet_crypto::Felt;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::precompile::{
    build_reconstruction_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::TranscriptId;
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

use crate::airs::composition::ArchivedCompositionBatchProofBundle;
use crate::error::{TexasAirError, TexasAirResult};
use crate::prove_task::{
    MAX_METHOD_BATCH_ROWS, MethodBatchV2, MethodInput, MethodPayloadV2, ProveTask,
};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::{is_tagged_batch_log_size, tagged_batch_log_size};

/// Tagged method proof envelope schema.
pub const TAGGED_METHOD_PROOF_VERSION: u8 = 2;
const MAX_TAGGED_METHOD_PROOF_BYTES: usize = 16 * 1024 * 1024;
const MAX_TAGGED_METHOD_BUNDLE_BYTES: usize = MAX_TAGGED_METHOD_PROOF_BYTES + 64 * 1024;
const MAX_TAGGED_BATCH_PACKAGE_BYTES: usize = 2 * MAX_TAGGED_METHOD_PROOF_BYTES + 256 * 1024;

const ACTIVE: usize = 0;
const FAMILY: usize = 1;
const ACTOR: usize = 3;
const TABLE_ID: usize = ACTOR + 10;
const HAND_ID: usize = TABLE_ID + 4;
const PRE_CALL_SEQ: usize = HAND_ID + 2;
const POST_CALL_SEQ: usize = PRE_CALL_SEQ + 2;
const PRE_ROOT: usize = POST_CALL_SEQ + 2;
const POST_ROOT: usize = PRE_ROOT + 16;
const COMMAND_DIGEST: usize = POST_ROOT + 16;
const ADMIN_TAG: usize = COMMAND_DIGEST + 16;
const ADMIN_REQUEST: usize = ADMIN_TAG + 1;
const ADMIN_RECEIPT: usize = ADMIN_REQUEST + 16;
const CRYPTO_TAG: usize = ADMIN_RECEIPT + 16;
const CRYPTO_REQUEST: usize = CRYPTO_TAG + 1;
const CRYPTO_RECEIPT: usize = CRYPTO_REQUEST + 16;
const BATCH_ID: usize = CRYPTO_RECEIPT + 16;
const ROW_INDEX: usize = BATCH_ID + 16;
const ROW_COUNT: usize = ROW_INDEX + 1;
const STAGE_START: usize = ROW_COUNT + 1;
const STAGE_COUNT: usize = STAGE_START + 1;
const PLAN_DIGEST: usize = STAGE_COUNT + 1;
const FAMILY_BITS: usize = PLAN_DIGEST + 16;
const CRYPTO_ONE_HOT: usize = FAMILY_BITS + 3;
const SEQ_CARRY: usize = CRYPTO_ONE_HOT + 5;
/// Fixed narrow tagged method trace width.
pub const TAGGED_METHOD_NUM_COLUMNS: usize = SEQ_CARRY + 1;

/// One durable single-proof envelope for ordered method payload v2 rows.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedTaggedMethodProofBundle {
    version: u8,
    batch_id: [u8; 32],
    row_count: u16,
    payload_digest: [u8; 32],
    log_size: u32,
    num_columns: u32,
    stark_proof_bytes: Vec<u8>,
}

/// Complete throughput-oriented replacement for per-task method + component proofs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedTaggedBatchProofPackage {
    version: u8,
    stream: MethodBatchV2,
    method: ArchivedTaggedMethodProofBundle,
    stages: ArchivedCompositionBatchProofBundle,
}

/// Host-issued receipt capabilities required to construct one tagged method row.
#[derive(Debug, Clone)]
pub struct VerifiedMethodReceipts {
    /// Creator authorization, present only for administrator commands.
    admin: Option<crate::authorization_binding::AdminAuthorizationBinding>,
    /// Native Mental Poker verification, present only for proof-bearing crypto commands.
    crypto: Option<crate::precompile_binding::PrecompileCallBinding>,
}

impl ArchivedTaggedBatchProofPackage {
    /// Canonical continuous command stream carried by this self-contained package.
    #[must_use]
    pub const fn stream(&self) -> &MethodBatchV2 {
        &self.stream
    }

    /// Replay the embedded command stream and reconstruct every canonical task.
    pub fn replay_tasks(&self) -> TexasAirResult<Vec<ProveTask>> {
        self.stream.replay_tasks()
    }

    /// Replay the command stream once and validate every package scope against those tasks.
    ///
    /// Callers that need both the canonical tasks and the validated envelope should prefer this
    /// method over calling [`Self::replay_tasks`] followed by another package validation.
    pub fn validate_and_replay_tasks(&self) -> TexasAirResult<Vec<ProveTask>> {
        let tasks = self.stream.replay_tasks()?;
        self.validate_with_replayed_tasks(&tasks)?;
        Ok(tasks)
    }

    /// Validate the package envelope against an already replayed copy of its command stream.
    ///
    /// This checks that rebuilding the compact stream from `tasks` produces the exact embedded
    /// stream. Native dispatch validity must therefore already have been established by replaying
    /// that stream or by the production receipt verifier.
    pub fn validate_with_replayed_tasks(&self, tasks: &[ProveTask]) -> TexasAirResult<()> {
        let expected_stream = MethodBatchV2::from_replayed_tasks(tasks)?;
        let batch_id = self.stream.batch_id_from_replayed_tasks(tasks)?;
        self.method.validate()?;
        self.stages.validate()?;
        if self.version != TAGGED_METHOD_PROOF_VERSION
            || expected_stream != self.stream
            || batch_id != self.method.batch_id
            || self.method.batch_id != self.stages.batch_id()
            || usize::from(self.method.row_count) != tasks.len()
            || self.method.row_count != self.stages.task_count()
        {
            return Err(TexasAirError::SerializationError(
                "tagged method and Stage proof scopes differ".into(),
            ));
        }
        Ok(())
    }

    /// Single heterogeneous tagged method proof.
    #[must_use]
    pub const fn method(&self) -> &ArchivedTaggedMethodProofBundle {
        &self.method
    }

    /// Single heterogeneous tagged Stage proof.
    #[must_use]
    pub const fn stages(&self) -> &ArchivedCompositionBatchProofBundle {
        &self.stages
    }

    /// Strict canonical package encoding.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged batch package Borsh encoding failed: {error}"
            ))
        })?;
        if bytes.len() > MAX_TAGGED_BATCH_PACKAGE_BYTES {
            return Err(TexasAirError::SerializationError(
                "tagged batch package exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Strict canonical package decoding with trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_TAGGED_BATCH_PACKAGE_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid tagged batch package length".into(),
            ));
        }
        let package = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged batch package Borsh decoding failed: {error}"
            ))
        })?;
        package.validate()?;
        Ok(package)
    }

    fn validate(&self) -> TexasAirResult<()> {
        self.validate_and_replay_tasks().map(drop)
    }
}

impl ArchivedTaggedMethodProofBundle {
    /// Batch identifier shared with the tagged Stage proof.
    #[must_use]
    pub const fn batch_id(&self) -> [u8; 32] {
        self.batch_id
    }

    /// Number of active heterogeneous method rows.
    #[must_use]
    pub const fn row_count(&self) -> u16 {
        self.row_count
    }

    /// Strict canonical encoding.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        let bytes = borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged method proof Borsh encoding failed: {error}"
            ))
        })?;
        if bytes.len() > MAX_TAGGED_METHOD_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "tagged method proof bundle exceeds size limit".into(),
            ));
        }
        Ok(bytes)
    }

    /// Strict canonical decoding with trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_TAGGED_METHOD_BUNDLE_BYTES {
            return Err(TexasAirError::SerializationError(
                "invalid tagged method proof bundle length".into(),
            ));
        }
        let bundle = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged method proof Borsh decoding failed: {error}"
            ))
        })?;
        bundle.validate()?;
        Ok(bundle)
    }

    fn validate(&self) -> TexasAirResult<()> {
        if self.version != TAGGED_METHOD_PROOF_VERSION
            || self.batch_id == [0; 32]
            || self.row_count == 0
            || usize::from(self.row_count) > MAX_METHOD_BATCH_ROWS
            || self.payload_digest == [0; 32]
            || !is_tagged_batch_log_size(self.log_size)
            || usize::from(self.row_count) > (1 << self.log_size)
            || usize::try_from(self.num_columns).ok() != Some(TAGGED_METHOD_NUM_COLUMNS)
            || self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > MAX_TAGGED_METHOD_PROOF_BYTES
        {
            return Err(TexasAirError::SerializationError(
                "invalid tagged method proof envelope".into(),
            ));
        }
        Ok(())
    }

    fn decode_stark(&self) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
        self.validate()?;
        bincode_options()
            .reject_trailing_bytes()
            .deserialize(&self.stark_proof_bytes)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "tagged method Stwo proof decoding failed: {error}"
                ))
            })
    }

    /// Decode only the commitment roots from the embedded Stwo proof.
    ///
    /// `StarkProof` wraps `CommitmentSchemeProof`, whose serde field order is
    /// `config, commitments, sampled_values, decommitments, queried_values,
    /// proof_of_work, fri_proof`. Bincode is not self-describing, so
    /// deserializing this two-field prefix consumes exactly the bytes of
    /// `config` + `commitments` and stops before the megabyte-scale FRI tail.
    ///
    /// Behavior-equivalent to `decode_stark()?.commitments` because the derive
    /// serializes struct fields in declaration order. Receipt issuance runs
    /// only after the full proof was already decoded and verified, so the
    /// trailing bytes are known to be well formed.
    fn decode_commitments(&self) -> TexasAirResult<Vec<starknet_crypto::Felt>> {
        self.validate()?;
        // Stream the prefix so the reader stops right after `commitments`;
        // full-buffer `deserialize` would reject the (well-formed) trailing
        // proof bytes.
        let mut deserializer =
            bincode::Deserializer::from_slice(&self.stark_proof_bytes, bincode_options());
        let prefix: StarkProofCommitmentsPrefix =
            serde::Deserialize::deserialize(&mut deserializer).map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "tagged method Stwo proof commitment decoding failed: {error}"
                ))
            })?;
        Ok(prefix.commitments)
    }
}

/// Bincode prefix of `CommitmentSchemeProof` stopping right after the
/// `commitments` field (see [`ArchivedTaggedMethodProofBundle::decode_commitments`]).
///
/// 字节兼容性注记：stwo 2.3 的 `Poseidon252MerkleHasher::Hash` 是旧 ff
/// 库（0.3）的 FieldElement，其 serde 形态是 **Display 十进制字符串**
/// （bincode 二进制下也是长度前缀字符串）。本仓的 Felt 载体已统一为
/// types-core，其默认 serde 形态（定长剥离前导零的 bytes）与之不同——
/// 因此这里手写字符串访问器按原 wire 格式解码，归档字节布局保持逐位不变。
#[derive(serde::Deserialize)]
struct StarkProofCommitmentsPrefix {
    #[allow(dead_code)]
    config: stwo::core::pcs::PcsConfig,
    #[serde(deserialize_with = "decode_wire_felt_vec")]
    commitments: Vec<Felt>,
}

/// Decode one felt in the legacy ff wire form: its `Serialize` emits
/// `serialize_str(Display)`, i.e. a **decimal** string (`"0"` for zero,
/// decimal digits otherwise), length-prefixed under bincode.
fn decode_wire_felt_vec<'de, D>(deserializer: D) -> Result<Vec<Felt>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct WireFeltVisitor;
    impl serde::de::Visitor<'_> for WireFeltVisitor {
        type Value = Felt;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a decimal felt252 string (legacy ff wire form)")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Felt, E> {
            Felt::from_dec_str(value).map_err(serde::de::Error::custom)
        }
    }

    struct WireFeltSeed;
    impl<'de> serde::de::DeserializeSeed<'de> for WireFeltSeed {
        type Value = Felt;
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Felt, D::Error> {
            deserializer.deserialize_str(WireFeltVisitor)
        }
    }

    struct WireFeltVecVisitor;
    impl<'de> serde::de::Visitor<'de> for WireFeltVecVisitor {
        type Value = Vec<Felt>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence of decimal felt252 strings")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Vec<Felt>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(felt) = seq.next_element_seed(WireFeltSeed)? {
                out.push(felt);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_seq(WireFeltVecVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaggedMethodStatement {
    batch_id: [u8; 32],
    row_count: u16,
    payload_digest: [u8; 32],
}

impl TaggedMethodStatement {
    fn from_payloads(payloads: &[MethodPayloadV2]) -> TexasAirResult<Self> {
        validate_payload_chain(payloads)?;
        let bytes = borsh::to_vec(payloads).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "tagged method payload encoding failed: {error}"
            ))
        })?;
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        hasher.update(b"zchain.texas_poker.tagged_method_payloads.v1");
        hasher.update(&bytes);
        let mut payload_digest = [0; 32];
        hasher
            .finalize_variable(&mut payload_digest)
            .expect("32 <= 64");
        Ok(Self {
            batch_id: payloads[0].batch.batch_id,
            row_count: u16::try_from(payloads.len()).map_err(|_| {
                TexasAirError::SpecViolation("tagged method row count exceeds u16".into())
            })?,
            payload_digest,
        })
    }

    fn mix_into<C: Channel>(&self, channel: &mut C) {
        channel.mix_u32s(&[
            0x5a54_4d42,
            u32::from(TAGGED_METHOD_PROOF_VERSION),
            u32::from(self.row_count),
            TAGGED_METHOD_NUM_COLUMNS as u32,
        ]);
        mix_digest(channel, self.batch_id);
        mix_digest(channel, self.payload_digest);
    }
}

/// Prove a tagged method trace using the smallest vetted domain for its rows.
pub fn prove_tagged_method_batch(
    payloads: &[MethodPayloadV2],
) -> TexasAirResult<ArchivedTaggedMethodProofBundle> {
    let bundle = prove_tagged_method_batch_without_self_verify(payloads)?;
    verify_tagged_method_batch(payloads, &bundle)?;
    Ok(bundle)
}

/// Produce the proof archive while deferring verification to an enclosing package boundary.
fn prove_tagged_method_batch_without_self_verify(
    payloads: &[MethodPayloadV2],
) -> TexasAirResult<ArchivedTaggedMethodProofBundle> {
    let timing_start = crate::prove_timing::enabled().then(std::time::Instant::now);
    let statement = TaggedMethodStatement::from_payloads(payloads)?;
    let log_size = tagged_batch_log_size(payloads.len())?;
    let trace = build_trace(payloads, log_size)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    statement.mix_into(&mut channel);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(vec![]);
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(trace.to_evaluations());
        tree.commit(&mut channel);
    }
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        TaggedMethodAir { log_size },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))?;
    if let Some(start) = timing_start {
        crate::prove_timing::record(
            format!("batch-method:Tagged[{} tasks]", statement.row_count),
            crate::prove_timing::TimingKind::Prove,
            start,
            Some(TAGGED_METHOD_NUM_COLUMNS),
        );
    }
    let stark_proof_bytes = bincode_options().serialize(&proof).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "tagged method Stwo proof serialization failed: {error}"
        ))
    })?;
    let bundle = ArchivedTaggedMethodProofBundle {
        version: TAGGED_METHOD_PROOF_VERSION,
        batch_id: statement.batch_id,
        row_count: statement.row_count,
        payload_digest: statement.payload_digest,
        log_size,
        num_columns: TAGGED_METHOD_NUM_COLUMNS as u32,
        stark_proof_bytes,
    };
    bundle.validate()?;
    Ok(bundle)
}

/// Verify a tagged method proof against verifier-reconstructed payload rows.
pub fn verify_tagged_method_batch(
    payloads: &[MethodPayloadV2],
    bundle: &ArchivedTaggedMethodProofBundle,
) -> TexasAirResult<()> {
    let timing_start = crate::prove_timing::enabled().then(std::time::Instant::now);
    bundle.validate()?;
    let statement = TaggedMethodStatement::from_payloads(payloads)?;
    if bundle.batch_id != statement.batch_id
        || bundle.row_count != statement.row_count
        || bundle.payload_digest != statement.payload_digest
    {
        return Err(TexasAirError::SpecViolation(
            "tagged method proof scope differs from canonical payloads".into(),
        ));
    }
    let trace = build_trace(payloads, bundle.log_size)?;
    let proof = bundle.decode_stark()?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(bundle.log_size + config.fri_config.log_blowup_factor);

    let mut trusted_channel = Poseidon252Channel::default();
    let mut trusted_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree = trusted_scheme.tree_builder();
        tree.extend_evals(trace.to_evaluations());
        tree.commit(&mut trusted_channel);
    }
    let trusted_root = trusted_scheme.roots()[0];
    if proof.commitments.get(1).copied() != Some(trusted_root) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "tagged method trace commitment differs from verifier-reconstructed payloads".into(),
        ));
    }

    let mut channel = Poseidon252Channel::default();
    statement.mix_into(&mut channel);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let preprocessed_root = *proof.commitments.first().ok_or_else(|| {
        TexasAirError::SerializationError(
            "tagged method proof is missing preprocessed commitment".into(),
        )
    })?;
    scheme.commit(preprocessed_root, &[], &mut channel);
    scheme.commit(
        trusted_root,
        &vec![bundle.log_size; TAGGED_METHOD_NUM_COLUMNS],
        &mut channel,
    );
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        TaggedMethodAir {
            log_size: bundle.log_size,
        },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof).map_err(
        |error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()),
    )?;
    if let Some(start) = timing_start {
        crate::prove_timing::record(
            format!("batch-method:Tagged[{} tasks]", statement.row_count),
            crate::prove_timing::TimingKind::Verify,
            start,
            Some(TAGGED_METHOD_NUM_COLUMNS),
        );
    }
    Ok(())
}

/// Prove one complete heterogeneous batch with exactly two Stwo startups: one method proof and
/// one Stage proof. No legacy per-task method/component proof is generated.
pub fn prove_tagged_composite_batch(
    tasks: &[ProveTask],
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
) -> TexasAirResult<ArchivedTaggedBatchProofPackage> {
    let stream = MethodBatchV2::from_tasks(tasks)?;
    let (package, payloads) = prove_tagged_composite_batch_with_replayed_tasks(
        tasks,
        stream,
        admin_bindings,
        crypto_bindings,
    )?;
    verify_tagged_composite_batch_with_validated_payloads(tasks, &payloads, &package)?;
    Ok(package)
}

fn prove_tagged_composite_batch_with_replayed_tasks(
    tasks: &[ProveTask],
    stream: MethodBatchV2,
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
) -> TexasAirResult<(ArchivedTaggedBatchProofPackage, Vec<MethodPayloadV2>)> {
    let stages = crate::airs::composition::prove_composition_batch_without_self_verify(tasks)?;
    let payloads = build_verified_payloads_from_replayed_tasks(
        tasks,
        &stages,
        admin_bindings,
        crypto_bindings,
    )?;
    let method = prove_tagged_method_batch_without_self_verify(&payloads)?;
    let package = ArchivedTaggedBatchProofPackage {
        version: TAGGED_METHOD_PROOF_VERSION,
        stream,
        method,
        stages,
    };
    package.validate_with_replayed_tasks(tasks)?;
    Ok((package, payloads))
}

/// Production convenience entry: replay every task, issue all required host-native receipts and
/// produce the two-proof tagged package without per-task Stwo proofs.
pub fn prove_verified_tagged_composite_batch(
    tasks: &[ProveTask],
) -> TexasAirResult<ArchivedTaggedBatchProofPackage> {
    prove_verified_tagged_composite_batch_with_receipts(tasks).map(|(package, _)| package)
}

pub(crate) fn prove_verified_tagged_composite_batch_with_receipts(
    tasks: &[ProveTask],
) -> TexasAirResult<(
    ArchivedTaggedBatchProofPackage,
    Vec<crate::verified_chain::VerificationReceipt>,
)> {
    // Establish the canonical continuous stream exactly once. From this point onward every
    // internal package/payload check consumes the replayed tasks instead of dispatching again.
    let stream = MethodBatchV2::from_tasks(tasks)?;
    let receipts = tasks
        .iter()
        .map(verify_method_receipts_for_replayed_task)
        .collect::<TexasAirResult<Vec<_>>>()?;
    let admin = receipts
        .iter()
        .map(|receipt| receipt.admin.clone())
        .collect::<Vec<_>>();
    let crypto = receipts
        .iter()
        .map(|receipt| receipt.crypto.clone())
        .collect::<Vec<_>>();
    let (package, payloads) =
        prove_tagged_composite_batch_with_replayed_tasks(tasks, stream, &admin, &crypto)?;
    verify_tagged_composite_batch_with_validated_payloads(tasks, &payloads, &package)?;
    let receipts = issue_tagged_receipts_after_verification(tasks, &package)?;
    Ok((package, receipts))
}

/// Reverify both tagged proofs from canonical tasks and verifier-issued receipt capabilities.
pub fn verify_tagged_composite_batch(
    tasks: &[ProveTask],
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    let embedded_tasks = package.validate_and_replay_tasks()?;
    if !same_task_slices(tasks, &embedded_tasks)? {
        return Err(TexasAirError::SpecViolation(
            "tagged batch package stream differs from verifier-owned tasks".into(),
        ));
    }
    verify_tagged_composite_batch_with_validated_stream(
        tasks,
        admin_bindings,
        crypto_bindings,
        package,
    )
}

fn verify_tagged_composite_batch_with_validated_stream(
    tasks: &[ProveTask],
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    let (stage_result, payload_result) = rayon::join(
        || crate::airs::composition::verify_composition_batch(tasks, &package.stages),
        || {
            build_verified_payloads_from_replayed_tasks(
                tasks,
                &package.stages,
                admin_bindings,
                crypto_bindings,
            )
        },
    );
    stage_result?;
    let payloads = payload_result?;
    verify_tagged_method_batch(&payloads, &package.method)
}

/// Verify a freshly proved package with the already canonical payloads used
/// to construct its method trace. This is an in-process optimization only:
/// restart/untrusted-package verification still rebuilds payloads from tasks
/// and verifier-issued capabilities in the function above.
fn verify_tagged_composite_batch_with_validated_payloads(
    tasks: &[ProveTask],
    payloads: &[MethodPayloadV2],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    let (stage_result, method_result) = rayon::join(
        || crate::airs::composition::verify_composition_batch(tasks, &package.stages),
        || verify_tagged_method_batch(payloads, &package.method),
    );
    stage_result?;
    method_result
}

/// Production restart verifier: regenerate every authorization/crypto capability from canonical
/// task data, then verify both tagged proofs.
pub fn verify_verified_tagged_composite_batch(
    tasks: &[ProveTask],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    let embedded_tasks = package.validate_and_replay_tasks()?;
    if !same_task_slices(tasks, &embedded_tasks)? {
        return Err(TexasAirError::SpecViolation(
            "tagged batch package stream differs from verifier-owned tasks".into(),
        ));
    }
    verify_verified_tagged_composite_batch_with_replayed_tasks(tasks, package)
}

/// Verify both tagged proofs using canonical tasks already replayed from this package.
///
/// The production receipt verifier revalidates every task's full dispatch semantics. Comparing
/// the rebuilt compact stream against the embedded stream then avoids replaying the entire stream
/// again solely for package scope validation.
pub(crate) fn verify_verified_tagged_composite_batch_with_replayed_tasks(
    tasks: &[ProveTask],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    package.validate_with_replayed_tasks(tasks)?;
    let receipts = tasks
        .iter()
        .map(verify_method_receipts_for_replayed_task)
        .collect::<TexasAirResult<Vec<_>>>()?;
    let admin = receipts
        .iter()
        .map(|receipt| receipt.admin.clone())
        .collect::<Vec<_>>();
    let crypto = receipts
        .iter()
        .map(|receipt| receipt.crypto.clone())
        .collect::<Vec<_>>();
    verify_tagged_composite_batch_with_validated_stream(tasks, &admin, &crypto, package)
}

/// Verify a self-contained tagged package by replaying its embedded continuous command stream.
///
/// This proves only the validity of that stream. Production callers must still bind the stream's
/// endpoints and dispatch digests to authenticated consensus data.
pub fn verify_verified_tagged_composite_package(
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<()> {
    let tasks = package.validate_and_replay_tasks()?;
    verify_verified_tagged_composite_batch_with_replayed_tasks(&tasks, package)
}

pub(crate) fn verify_and_issue_tagged_receipts_with_replayed_tasks(
    tasks: &[ProveTask],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<Vec<crate::verified_chain::VerificationReceipt>> {
    verify_verified_tagged_composite_batch_with_replayed_tasks(tasks, package)?;
    issue_tagged_receipts_after_verification(tasks, package)
}

fn issue_tagged_receipts_after_verification(
    tasks: &[ProveTask],
    package: &ArchivedTaggedBatchProofPackage,
) -> TexasAirResult<Vec<crate::verified_chain::VerificationReceipt>> {
    let commitments = package.method.decode_commitments()?;
    tasks
        .iter()
        .map(|task| {
            crate::verified_chain::issue_tagged_batch_receipt(
                task,
                commitments.clone(),
                package.method.log_size,
                TAGGED_METHOD_NUM_COLUMNS,
            )
        })
        .collect()
}

/// Replay one task and issue the exact admin/Mental Poker capabilities required by its tagged row.
pub fn verify_method_receipts(task: &ProveTask) -> TexasAirResult<VerifiedMethodReceipts> {
    crate::orchestrator::validate_full_dispatch_task(task)?;
    verify_method_receipts_for_replayed_task(task)
}

/// Issue receipt capabilities for a task already established by canonical VM replay.
///
/// Native crypto verification still runs once here to create the opaque precompile capability;
/// only the duplicate state-machine dispatch is skipped.
fn verify_method_receipts_for_replayed_task(
    task: &ProveTask,
) -> TexasAirResult<VerifiedMethodReceipts> {
    let pre_root = crate::state_root::compute_state_root(&task.pre_table)?;
    let post_root = crate::state_root::compute_state_root(&task.post_table)?;
    let dispatch_digest =
        crate::prove_task::dispatch_call_digest(&task.context, &task.selector(), &task.raw_args)?;
    let admin = if matches!(
        task.method_kind,
        crate::method_kind::MethodKind::StartHand
            | crate::method_kind::MethodKind::ForceFold
            | crate::method_kind::MethodKind::KickPlayer
    ) {
        Some(
            crate::authorization_binding::AdminAuthorizationBinding::verify_table_creator(
                task.method_kind,
                &task.context,
                &task.selector(),
                &task.raw_args,
                task.pre_table.creator,
                task.table_id,
                task.hand_id,
                task.call_seq,
                u64::from(task.pre_table.call_seq),
                u64::from(task.post_table.call_seq),
                pre_root,
                post_root,
                dispatch_digest,
            )?,
        )
    } else {
        None
    };
    let crypto = verify_crypto_receipt(task, pre_root, post_root, dispatch_digest)?;
    Ok(VerifiedMethodReceipts { admin, crypto })
}

fn verify_crypto_receipt(
    task: &ProveTask,
    pre_root: crate::state_root::StateRoot,
    post_root: crate::state_root::StateRoot,
    dispatch_digest: [u8; 32],
) -> TexasAirResult<Option<crate::precompile_binding::PrecompileCallBinding>> {
    use crate::method_kind::MethodKind;
    use crate::precompile_binding::{
        LeaveDleqVerifyRequest, PrecompileCallBinding, RevealTokenVerifyRequest,
        precompile_call_context,
    };

    let method_input = task.method_input()?;
    let seat_index = match &method_input {
        MethodInput::FoldWithProof { seat_index }
        | MethodInput::SubmitShuffleV2 { seat_index }
        | MethodInput::SubmitPlayerRevealTokens { seat_index }
        | MethodInput::SubmitReconstructDeck { seat_index } => *seat_index,
        _ => return Ok(None),
    };
    let call_context = precompile_call_context(
        task.method_kind,
        seat_index,
        task.table_id,
        task.hand_id,
        task.call_seq,
        u64::from(task.pre_table.call_seq),
        u64::from(task.post_table.call_seq),
        pre_root,
        post_root,
        dispatch_digest,
    );
    let replay_args = task.replay_args()?;
    let binding = match task.method_kind {
        MethodKind::FoldWithProof => {
            let args: poker_l1::contracts::texas_poker::dispatch::FoldWithProofArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "fold_with_proof tagged receipt args: {error}"
                    ))
                })?;
            let player_pk = live_player_pk(task, seat_index, "fold_with_proof")?;
            let request = LeaveDleqVerifyRequest::new(
                call_context,
                task.pre_table.deck_state.encrypted.to_vec(),
                args.output_cards,
                player_pk,
                args.fold_proof,
            );
            PrecompileCallBinding::verify_leave_dleq(&request)?
        }
        MethodKind::SubmitShuffleV2 => {
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitShuffleV2Args =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit_shuffle_v2 tagged receipt args: {error}"
                    ))
                })?;
            let aggregate = task
                .pre_table
                .derived_aggregated_pk()
                .map_err(|error| TexasAirError::SpecViolation(error.to_string()))?
                .ok_or_else(|| {
                    TexasAirError::SpecViolation(
                        "submit_shuffle_v2 requires aggregate Mental Poker key".into(),
                    )
                })?;
            let request = build_bls12381_shuffle_request(
                poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
                &call_context,
                TranscriptId::Poseidon252,
                &aggregate.0,
                &task.pre_table.deck_state.encrypted,
                &args.output_cards,
                &args.shuffle_proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit_shuffle_v2 tagged request construction failed: {error}"
                ))
            })?;
            PrecompileCallBinding::verify_shuffle(&request)?
        }
        MethodKind::SubmitPlayerRevealTokens => {
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitRevealTokensArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit reveal tagged receipt args: {error}"
                    ))
                })?;
            let request =
                RevealTokenVerifyRequest::from_dispatch(call_context, &task.pre_table, &args)?;
            PrecompileCallBinding::verify_reveal_tokens(&request)?
        }
        MethodKind::SubmitReconstructDeck => {
            let args: poker_l1::contracts::texas_poker::dispatch::SubmitReconstructDeckArgs =
                borsh::from_slice(&replay_args).map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "submit reconstruct tagged receipt args: {error}"
                    ))
                })?;
            let request = build_reconstruction_request(
                poker_protocol::transcript_domains::RECONSTRUCT_POSEIDON,
                &call_context,
                TranscriptId::Poseidon252,
                &args.statement,
                &args.proof,
            )
            .map_err(|error| {
                TexasAirError::SpecViolation(format!(
                    "submit reconstruct tagged request construction failed: {error}"
                ))
            })?;
            PrecompileCallBinding::verify_reconstruction_v3(&request)?
        }
        _ => return Ok(None),
    };
    Ok(Some(binding))
}

fn live_player_pk(
    task: &ProveTask,
    seat_index: u8,
    method: &str,
) -> TexasAirResult<poker_protocol::crypto::types::ECPoint> {
    task.pre_table
        .seats
        .get(usize::from(seat_index))
        .and_then(|seat| seat.pk().copied())
        .ok_or_else(|| {
            TexasAirError::SpecViolation(format!("{method} seat has no live Mental Poker key"))
        })
}

/// Rebuild narrow payloads for one composite Stage batch. Receipt capabilities must have been
/// issued by the host verifier; ordinary action rows pass `None` in both slices.
pub fn build_verified_payloads(
    tasks: &[ProveTask],
    stage_bundle: &ArchivedCompositionBatchProofBundle,
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
) -> TexasAirResult<Vec<MethodPayloadV2>> {
    if admin_bindings.len() != tasks.len() || crypto_bindings.len() != tasks.len() {
        return Err(TexasAirError::SpecViolation(
            "tagged method receipt vector length mismatch".into(),
        ));
    }
    let references = stage_bundle.method_references(tasks)?;
    tasks
        .iter()
        .zip(references)
        .zip(admin_bindings)
        .zip(crypto_bindings)
        .map(|(((task, reference), admin), crypto)| {
            MethodPayloadV2::from_verified_task(task, reference, admin.as_ref(), crypto.as_ref())
        })
        .collect()
}

/// Rebuild payloads from tasks whose exact dispatch sequence has already been replayed.
fn build_verified_payloads_from_replayed_tasks(
    tasks: &[ProveTask],
    stage_bundle: &ArchivedCompositionBatchProofBundle,
    admin_bindings: &[Option<crate::authorization_binding::AdminAuthorizationBinding>],
    crypto_bindings: &[Option<crate::precompile_binding::PrecompileCallBinding>],
) -> TexasAirResult<Vec<MethodPayloadV2>> {
    if admin_bindings.len() != tasks.len() || crypto_bindings.len() != tasks.len() {
        return Err(TexasAirError::SpecViolation(
            "tagged method receipt vector length mismatch".into(),
        ));
    }
    let references = stage_bundle.method_references(tasks)?;
    tasks
        .iter()
        .zip(references)
        .zip(admin_bindings)
        .zip(crypto_bindings)
        .map(|(((task, reference), admin), crypto)| {
            MethodPayloadV2::from_replayed_task(task, reference, admin.as_ref(), crypto.as_ref())
        })
        .collect()
}

fn validate_payload_chain(payloads: &[MethodPayloadV2]) -> TexasAirResult<()> {
    if payloads.is_empty() || payloads.len() > MAX_METHOD_BATCH_ROWS {
        return Err(TexasAirError::SpecViolation(format!(
            "tagged method batch must contain 1..={MAX_METHOD_BATCH_ROWS} payloads"
        )));
    }
    let first = &payloads[0];
    let row_count = u16::try_from(payloads.len()).expect("bounded payload count");
    let mut stage_cursor = 0u16;
    for (index, payload) in payloads.iter().enumerate() {
        payload.validate()?;
        if payload.batch.batch_id != first.batch.batch_id
            || payload.table_id != first.table_id
            || payload.hand_id != first.hand_id
            || payload.batch.row_index != u16::try_from(index).expect("bounded row index")
            || payload.batch.row_count != row_count
            || payload.batch.stage_start_row != stage_cursor
        {
            return Err(TexasAirError::SpecViolation(
                "tagged method payload chain scope is not canonical".into(),
            ));
        }
        if let Some(previous) = index.checked_sub(1).map(|previous| &payloads[previous]) {
            if payload.pre_call_seq != previous.post_call_seq
                || payload.pre_state_root != previous.post_state_root
            {
                return Err(TexasAirError::SpecViolation(
                    "tagged method payload state chain is discontinuous".into(),
                ));
            }
        }
        stage_cursor = stage_cursor
            .checked_add(u16::from(payload.batch.stage_row_count))
            .ok_or_else(|| TexasAirError::SpecViolation("Stage row cursor overflow".into()))?;
    }
    Ok(())
}

fn same_task_slices(left: &[ProveTask], right: &[ProveTask]) -> TexasAirResult<bool> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        if left.method_kind != right.method_kind
            || left.context != right.context
            || left.raw_args != right.raw_args
            || left.pre_table != right.pre_table
            || left.post_table != right.post_table
            || left.table_id != right.table_id
            || left.hand_id != right.hand_id
            || left.call_seq != right.call_seq
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn build_trace(payloads: &[MethodPayloadV2], log_size: u32) -> TexasAirResult<MethodTrace> {
    validate_payload_chain(payloads)?;
    if !is_tagged_batch_log_size(log_size) || payloads.len() > (1 << log_size) {
        return Err(TexasAirError::SpecViolation(
            "tagged method trace shape does not cover its payloads".into(),
        ));
    }
    let mut trace = MethodTrace::new(log_size, TAGGED_METHOD_NUM_COLUMNS);
    for (index, payload) in payloads.iter().enumerate() {
        trace.write_row(index, &payload_row(payload))?;
    }
    let padding = vec![M31::from(0u32); TAGGED_METHOD_NUM_COLUMNS];
    for index in payloads.len()..(1 << log_size) {
        trace.write_row(index, &padding)?;
    }
    Ok(trace)
}

fn payload_row(payload: &MethodPayloadV2) -> Vec<M31> {
    let mut row = Vec::with_capacity(TAGGED_METHOD_NUM_COLUMNS);
    row.push(M31::from(1u32));
    row.push(M31::from(u32::from(payload.family)));
    row.push(M31::from(u32::from(payload.subtag)));
    push_bytes_as_u16(&mut row, &payload.actor);
    push_u64(&mut row, payload.table_id);
    push_u32(&mut row, payload.hand_id);
    push_u32(&mut row, payload.pre_call_seq);
    push_u32(&mut row, payload.post_call_seq);
    push_bytes_as_u16(&mut row, &payload.pre_state_root);
    push_bytes_as_u16(&mut row, &payload.post_state_root);
    push_bytes_as_u16(&mut row, &payload.canonical_command_digest);
    row.push(M31::from(u32::from(payload.admin_receipt.tag)));
    push_bytes_as_u16(&mut row, &payload.admin_receipt.request_digest);
    push_bytes_as_u16(&mut row, &payload.admin_receipt.receipt_digest);
    row.push(M31::from(u32::from(payload.crypto_receipt.tag)));
    push_bytes_as_u16(&mut row, &payload.crypto_receipt.request_digest);
    push_bytes_as_u16(&mut row, &payload.crypto_receipt.receipt_digest);
    push_bytes_as_u16(&mut row, &payload.batch.batch_id);
    row.push(M31::from(u32::from(payload.batch.row_index)));
    row.push(M31::from(u32::from(payload.batch.row_count)));
    row.push(M31::from(u32::from(payload.batch.stage_start_row)));
    row.push(M31::from(u32::from(payload.batch.stage_row_count)));
    push_bytes_as_u16(&mut row, &payload.transition_plan_digest);
    for bit in 0..3 {
        row.push(M31::from(u32::from((payload.family >> bit) & 1)));
    }
    for tag in 1..=5 {
        row.push(M31::from(u32::from(payload.crypto_receipt.tag == tag)));
    }
    let carry = u32::from((payload.pre_call_seq & 0xffff) == 0xffff);
    row.push(M31::from(carry));
    debug_assert_eq!(row.len(), TAGGED_METHOD_NUM_COLUMNS);
    row
}

#[derive(Debug, Clone)]
struct TaggedMethodAir {
    log_size: u32,
}

impl FrameworkEval for TaggedMethodAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let columns = (0..TAGGED_METHOD_NUM_COLUMNS)
            .map(|_| eval.next_trace_mask())
            .collect::<Vec<_>>();
        let one: E::F = M31::from(1u32).into();
        let active = columns[ACTIVE].clone();
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        for value in columns.iter().skip(1) {
            eval.add_constraint((one.clone() - active.clone()) * value.clone());
        }

        let family_bits = &columns[FAMILY_BITS..FAMILY_BITS + 3];
        for bit in family_bits {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }
        let two: E::F = M31::from(2u32).into();
        let four: E::F = M31::from(4u32).into();
        eval.add_constraint(
            columns[FAMILY].clone()
                - family_bits[0].clone()
                - two * family_bits[1].clone()
                - four * family_bits[2].clone(),
        );
        eval.add_constraint(family_bits[1].clone() * family_bits[2].clone());

        let admin = columns[ADMIN_TAG].clone();
        eval.add_constraint(admin.clone() * (admin.clone() - one.clone()));
        for value in &columns[ADMIN_REQUEST..ADMIN_RECEIPT + 16] {
            eval.add_constraint((one.clone() - admin.clone()) * value.clone());
        }

        let crypto_bits = &columns[CRYPTO_ONE_HOT..CRYPTO_ONE_HOT + 5];
        let mut crypto_present: E::F = M31::from(0u32).into();
        let mut crypto_tag: E::F = M31::from(0u32).into();
        for (index, bit) in crypto_bits.iter().enumerate() {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            crypto_present = crypto_present + bit.clone();
            let coefficient: E::F = M31::from((index + 1) as u32).into();
            crypto_tag = crypto_tag + coefficient * bit.clone();
        }
        eval.add_constraint(crypto_present.clone() * (crypto_present.clone() - one.clone()));
        eval.add_constraint(columns[CRYPTO_TAG].clone() - crypto_tag);
        for value in &columns[CRYPTO_REQUEST..CRYPTO_RECEIPT + 16] {
            eval.add_constraint((one.clone() - crypto_present.clone()) * value.clone());
        }

        let carry = columns[SEQ_CARRY].clone();
        eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
        let limb_base: E::F = M31::from(65_536u32).into();
        eval.add_constraint(
            active.clone()
                * (columns[POST_CALL_SEQ].clone() - columns[PRE_CALL_SEQ].clone() - one.clone()
                    + limb_base * carry.clone()),
        );
        eval.add_constraint(
            active
                * (columns[POST_CALL_SEQ + 1].clone() - columns[PRE_CALL_SEQ + 1].clone() - carry),
        );
        eval
    }
}

fn push_u32(row: &mut Vec<M31>, value: u32) {
    row.push(M31::from(value & 0xffff));
    row.push(M31::from(value >> 16));
}

fn push_u64(row: &mut Vec<M31>, value: u64) {
    for shift in [0, 16, 32, 48] {
        row.push(M31::from(((value >> shift) & 0xffff) as u32));
    }
}

fn push_bytes_as_u16(row: &mut Vec<M31>, bytes: &[u8]) {
    debug_assert_eq!(bytes.len() % 2, 0);
    row.extend(
        bytes
            .chunks_exact(2)
            .map(|chunk| M31::from(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])))),
    );
}

fn mix_digest<C: Channel>(channel: &mut C, digest: [u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4-byte digest word")))
            .collect::<Vec<_>>(),
    );
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_TAGGED_METHOD_PROOF_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prove_task::{MethodBatchReferenceV2, MethodReceiptDigestV2};

    fn payload(index: u16, pre: u32) -> MethodPayloadV2 {
        MethodPayloadV2 {
            version: crate::prove_task::METHOD_PAYLOAD_VERSION,
            family: 3,
            subtag: 1,
            actor: [1; 20],
            table_id: 7,
            hand_id: 9,
            pre_call_seq: pre,
            post_call_seq: pre + 1,
            pre_state_root: [u8::try_from(index + 1).unwrap(); 32],
            post_state_root: [u8::try_from(index + 2).unwrap(); 32],
            canonical_command_digest: [3; 32],
            admin_receipt: MethodReceiptDigestV2::NONE,
            crypto_receipt: MethodReceiptDigestV2::NONE,
            batch: MethodBatchReferenceV2 {
                batch_id: [8; 32],
                row_index: index,
                row_count: 2,
                stage_start_row: index,
                stage_row_count: 1,
            },
            transition_plan_digest: [4; 32],
        }
    }

    #[test]
    fn payload_trace_has_fixed_narrow_width_and_checks_continuity() {
        let payloads = vec![payload(0, 10), payload(1, 11)];
        assert_eq!(payload_row(&payloads[0]).len(), TAGGED_METHOD_NUM_COLUMNS);
        validate_payload_chain(&payloads).unwrap();
        let mut broken = payloads;
        broken[1].pre_state_root = [9; 32];
        assert!(validate_payload_chain(&broken).is_err());
    }
}
