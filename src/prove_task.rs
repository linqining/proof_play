//! 证明任务（Prove Task）— Post-commit Prover 的数据契约。
//!
//! ## 角色
//!
//! 合约执行层（`poker_l1` dispatch）每次成功执行一个 method 后，产出一个
//! [`ProveTask`]，序列化进 `DispatchResult.return_value`（与 events 一起）。
//! 链下 Orchestrator（[`crate::orchestrator`]）消费任务队列，为每个任务
//! 生成 method proof，并可立即封装为单方法 recursive STWO proof。最终 application-aware
//! verifier 不接收 inner method proof；批量 final aggregate proof 仍未完成。
//!
//! ## 设计原则
//!
//! - **不阻塞执行**：合约层只记录任务，不生成 proof（prove 是重计算，异步做）
//! - **依赖方向保持 air → l1**：本模块只定义数据结构，由 Orchestrator 消费；
//!   合约层填充任务时依赖此结构（通过 `poker_texas_air` crate），但这只在
//!   测试/PoC 场景；生产中合约层用一个等价的纯数据结构，Orchestrator 反序列化
//! - **pre/post table 快照**：Orchestrator 从两个快照算 pre/post state_root，
//!   无需合约层暴露 state_root 计算逻辑
//!
//! ## 与 DispatchResult.return_value 的关系
//!
//! `return_value` = borsh([`DispatchOutput`])，其中 `DispatchOutput` 含
//! `events` + `prove_task`。旧格式（仅 events）通过版本前缀区分。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

// MethodInput remains a transient decoded view. It is no longer persisted in ProveTask.
pub use vm_common::prove_task::MethodInput;

use crate::method_kind::MethodKind;

/// Current continuous method-batch stream schema.
pub const METHOD_BATCH_STREAM_VERSION: u8 = 4;
/// Current canonical tagged method-row payload schema.
pub const METHOD_PAYLOAD_VERSION: u8 = 4;
/// Maximum method rows in one 1024-row Stage batch.
pub const MAX_METHOD_BATCH_ROWS: usize = 256;

/// One canonical command in a continuous method-batch state stream.
///
/// Intermediate table snapshots are deliberately absent. Replaying this command against the
/// preceding state produces the only accepted post-state and the next command's pre-state.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MethodBatchCommandV2 {
    /// Canonical legacy command tag used only at the dispatch boundary.
    pub method_kind: MethodKind,
    /// Authenticated VM execution context.
    pub context: poker_l1::contracts::dispatch::DispatchContext,
    /// Sole canonical command payload.
    pub raw_args: Vec<u8>,
}

/// Compact durable stream for a contiguous heterogeneous method batch.
///
/// The wire representation is exactly:
/// `initial_state + [context, method_tag, canonical_args]* + final_state`.
/// Old per-task `pre_table + post_table` archives are intentionally not accepted.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MethodBatchV2 {
    version: u8,
    initial_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
    commands: Vec<MethodBatchCommandV2>,
    final_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
}

/// Durable reference from one tagged method row to its method and Stage batch scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MethodBatchReferenceV2 {
    /// Domain-separated identifier of the exact ordered continuous state stream.
    pub batch_id: [u8; 32],
    /// Zero-based method row in the heterogeneous method trace.
    pub row_index: u16,
    /// Number of active method rows in the batch.
    pub row_count: u16,
    /// First active tagged Stage row owned by this method.
    pub stage_start_row: u16,
    /// Number of consecutive active Stage rows owned by this method.
    pub stage_row_count: u8,
}

/// Optional verifier-issued receipt commitment carried by one tagged method row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MethodReceiptDigestV2 {
    /// Receipt family tag. Zero means absent and requires both digests to be zero.
    pub tag: u8,
    /// Canonical verifier request digest.
    pub request_digest: [u8; 32],
    /// Successful verifier receipt digest.
    pub receipt_digest: [u8; 32],
}

impl MethodReceiptDigestV2 {
    /// Canonical absent receipt.
    pub const NONE: Self = Self {
        tag: 0,
        request_digest: [0; 32],
        receipt_digest: [0; 32],
    };

    fn validate(self, label: &str) -> crate::error::TexasAirResult<()> {
        if self.tag == 0 && (self.request_digest != [0; 32] || self.receipt_digest != [0; 32]) {
            return Err(crate::error::TexasAirError::SpecViolation(format!(
                "absent {label} receipt must have zero digests"
            )));
        }
        if self.tag != 0 && (self.request_digest == [0; 32] || self.receipt_digest == [0; 32]) {
            return Err(crate::error::TexasAirError::SpecViolation(format!(
                "present {label} receipt must have non-zero digests"
            )));
        }
        Ok(())
    }
}

/// Canonical narrow row committed by the heterogeneous tagged method proof.
///
/// Business amount witnesses live only in the referenced tagged Stage rows. This row binds
/// command authorization, optional native-verifier receipts, state endpoints and the exact Stage
/// suffix owned by the command.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct MethodPayloadV2 {
    /// Payload schema. Only [`METHOD_PAYLOAD_VERSION`] is accepted.
    pub version: u8,
    /// Six-way canonical command family.
    pub family: u8,
    /// Family-local command discriminator.
    pub subtag: u8,
    /// Authenticated caller/actor.
    pub actor: [u8; 20],
    /// Table scope.
    pub table_id: u64,
    /// Post-dispatch hand scope.
    pub hand_id: u32,
    /// Canonical pre-state command sequence.
    pub pre_call_seq: u32,
    /// Canonical post-state command sequence.
    pub post_call_seq: u32,
    /// Hot-state root before execution.
    pub pre_state_root: [u8; 32],
    /// Hot-state root after execution.
    pub post_state_root: [u8; 32],
    /// Digest of authenticated context + canonical command.
    pub canonical_command_digest: [u8; 32],
    /// Optional administrator authorization receipt.
    pub admin_receipt: MethodReceiptDigestV2,
    /// Optional Mental Poker native-verifier receipt.
    pub crypto_receipt: MethodReceiptDigestV2,
    /// Durable method/Stage batch location.
    pub batch: MethodBatchReferenceV2,
    /// Digest of the bounded normalized transition plan, or zero for methods outside the Stage
    /// composition pipeline.
    pub transition_plan_digest: [u8; 32],
}

/// Domain-separated digest of the exact VM dispatch call carried by a task.
///
/// The digest commits to the task-carried dispatch context, command tag, and canonical
/// Borsh payload. Method proofs mix it into Fiat-Shamir public inputs so a
/// receipt cannot be detached from the VM call replayed by the host. The digest
/// does not by itself authenticate that the task came from a consensus block.
pub fn dispatch_call_digest(
    context: &poker_l1::contracts::dispatch::DispatchContext,
    selector: &[u8; 32],
    canonical_args: &[u8],
) -> crate::error::TexasAirResult<[u8; 32]> {
    let method_tag =
        poker_l1::contracts::texas_poker::dispatch::CanonicalCommand::from_archive_selector(
            selector,
        )
        .ok_or_else(|| {
            crate::error::TexasAirError::SerializationError(
                "unknown selector for canonical dispatch digest".into(),
            )
        })? as u8;
    let encoded =
        borsh::to_vec(&(context.clone(), method_tag, canonical_args.to_vec())).map_err(|e| {
            crate::error::TexasAirError::SerializationError(format!(
                "dispatch call context borsh: {e}"
            ))
        })?;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.texas_poker.dispatch_call.v4");
    hasher.update(&encoded);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    Ok(digest)
}

/// Normalize a transaction-bound legacy ABI payload before computing the canonical digest.
///
/// Consensus anchors authenticate external transaction bytes, while proof tasks persist the
/// slimmer actor-less payload. This is the only conversion path between those representations.
pub fn dispatch_call_digest_from_legacy_args(
    context: &poker_l1::contracts::dispatch::DispatchContext,
    selector: &[u8; 32],
    legacy_args: &[u8],
) -> crate::error::TexasAirResult<[u8; 32]> {
    let (_, canonical_args) =
        poker_l1::contracts::texas_poker::dispatch::canonical_command_parts(
            selector,
            legacy_args,
        )
        .map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "legacy dispatch command cannot canonicalize: {error}"
            ))
        })?;
    dispatch_call_digest(context, selector, &canonical_args)
}

/// 单次 method 调用的证明任务。
///
/// 合约执行成功后产出，Orchestrator 据此生成一个 method proof。
#[derive(Debug, Clone)]
pub struct ProveTask {
    /// 方法种类（选 AIR）。
    pub method_kind: MethodKind,
    /// VM dispatch 记录的完整调用上下文。
    ///
    /// Orchestrator 会据此重放权限和业务逻辑，但不会独立证明该上下文已被交易层或
    /// 共识层认证；生产调用方必须通过外部 block/receipt 锚提供来源保证。
    pub context: poker_l1::contracts::dispatch::DispatchContext,
    /// Canonical Borsh command payload selected by `method_kind`.
    ///
    /// Selector and typed [`MethodInput`] are derived views and are deliberately not stored.
    pub raw_args: Vec<u8>,
    /// 调用前表台快照（算 pre_state_root + 派生 pre 字段）。
    pub pre_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
    /// 调用后表台快照（算 post_state_root + 派生 post 字段）。
    pub post_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
    /// 表台 ID（公开输入，防跨表台聚合攻击）。
    pub table_id: u64,
    /// 手牌序号（同一 table 内递增）。
    pub hand_id: u32,
    /// 方法调用序号（同一 hand 内递增，Aggregator 据此排序）。
    pub call_seq: u32,
}

impl ProveTask {
    /// 构造新的证明任务。
    #[must_use]
    pub fn new(
        method_kind: MethodKind,
        context: poker_l1::contracts::dispatch::DispatchContext,
        raw_args: Vec<u8>,
        pre_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
        post_table: poker_l1::contracts::texas_poker::types::TexasPokerTable,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        poker_l1::contracts::texas_poker::dispatch::derive_authenticated_method_input(
            method_kind as u8,
            &raw_args,
            &context,
            &pre_table,
        )
        .expect("ProveTask requires a validated canonical command");
        Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        }
    }

    /// Selector deterministically derived from the canonical command tag.
    #[must_use]
    pub fn selector(&self) -> [u8; 32] {
        self.method_kind.selector()
    }

    /// Decode the transient typed input from the only persisted command payload.
    pub fn method_input(&self) -> crate::error::TexasAirResult<MethodInput> {
        poker_l1::contracts::texas_poker::dispatch::derive_authenticated_method_input(
            self.method_kind as u8,
            &self.raw_args,
            &self.context,
            &self.pre_table,
        )
        .map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "canonical command input decode failed: {error}"
            ))
        })
    }

    /// Reconstruct the native legacy execution ABI from this authenticated canonical command.
    ///
    /// Proof consumers must use this view when decoding full crypto statements. `raw_args`
    /// deliberately omits actor fields and is only the persisted digest-bound representation.
    pub fn replay_args(&self) -> crate::error::TexasAirResult<Vec<u8>> {
        poker_l1::contracts::texas_poker::dispatch::replay_dispatch_args(
            self.method_kind as u8,
            &self.raw_args,
            &self.context,
            &self.pre_table,
        )
        .map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "canonical command replay payload failed: {error}"
            ))
        })
    }

    /// Stable bytes committed by method and batch proofs.
    pub fn canonical_command_bytes(&self) -> crate::error::TexasAirResult<Vec<u8>> {
        borsh::to_vec(&(self.method_kind as u8, self.raw_args.clone())).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "canonical command borsh encoding failed: {error}"
            ))
        })
    }
}

impl MethodBatchReferenceV2 {
    /// Validate canonical method and Stage row bounds.
    pub fn validate(&self) -> crate::error::TexasAirResult<()> {
        let row_count = usize::from(self.row_count);
        if row_count == 0
            || row_count > MAX_METHOD_BATCH_ROWS
            || usize::from(self.row_index) >= row_count
        {
            return Err(crate::error::TexasAirError::SpecViolation(
                "invalid method-batch row scope".into(),
            ));
        }
        if self.stage_row_count > 4
            || usize::from(self.stage_start_row)
                .checked_add(usize::from(self.stage_row_count))
                .is_none_or(|end| end > (1 << crate::trace_gen::generic_trace::BATCH_LOG_SIZE))
        {
            return Err(crate::error::TexasAirError::SpecViolation(
                "invalid tagged Stage row scope".into(),
            ));
        }
        if self.batch_id == [0; 32] {
            return Err(crate::error::TexasAirError::SpecViolation(
                "method-batch id must not be zero".into(),
            ));
        }
        Ok(())
    }
}

impl MethodBatchV2 {
    /// Build a compact continuous stream from canonical contiguous tasks.
    pub fn from_tasks(tasks: &[ProveTask]) -> crate::error::TexasAirResult<Self> {
        let batch = Self::from_replayed_tasks(tasks)?;
        let replayed = batch.replay_tasks()?;
        for (index, (expected, actual)) in tasks.iter().zip(&replayed).enumerate() {
            if !same_task(expected, actual)? {
                return Err(crate::error::TexasAirError::SpecViolation(format!(
                    "method batch task {index} differs from continuous VM replay"
                )));
            }
        }
        Ok(batch)
    }

    pub(crate) fn from_replayed_tasks(tasks: &[ProveTask]) -> crate::error::TexasAirResult<Self> {
        if tasks.is_empty() || tasks.len() > MAX_METHOD_BATCH_ROWS {
            return Err(crate::error::TexasAirError::SpecViolation(format!(
                "method batch must contain 1..={MAX_METHOD_BATCH_ROWS} tasks"
            )));
        }
        let first = &tasks[0];
        for (index, task) in tasks.iter().enumerate() {
            if task.table_id != first.table_id || task.hand_id != first.hand_id {
                return Err(crate::error::TexasAirError::SpecViolation(
                    "method batch crosses table or post-dispatch hand scope".into(),
                ));
            }
            if let Some(previous) = index.checked_sub(1).map(|previous| &tasks[previous]) {
                if task.call_seq
                    != previous.call_seq.checked_add(1).ok_or_else(|| {
                        crate::error::TexasAirError::SpecViolation(
                            "method batch call_seq overflow".into(),
                        )
                    })?
                    || task.pre_table != previous.post_table
                {
                    return Err(crate::error::TexasAirError::SpecViolation(
                        "method batch tasks are not exact-state contiguous".into(),
                    ));
                }
            }
        }
        Ok(Self {
            version: METHOD_BATCH_STREAM_VERSION,
            initial_table: tasks[0].pre_table.clone(),
            commands: tasks
                .iter()
                .map(|task| MethodBatchCommandV2 {
                    method_kind: task.method_kind,
                    context: task.context.clone(),
                    raw_args: task.raw_args.clone(),
                })
                .collect(),
            final_table: tasks
                .last()
                .expect("non-empty method batch")
                .post_table
                .clone(),
        })
    }

    /// Build, replay-validate and commit one stream without repeating expensive VM/crypto replay.
    pub fn commitment_from_tasks(
        tasks: &[ProveTask],
    ) -> crate::error::TexasAirResult<(Self, [u8; 32], Vec<u8>)> {
        let batch = Self::from_tasks(tasks)?;
        let batch_id = batch.batch_id_from_replayed_tasks(tasks)?;
        let bytes = borsh::to_vec(&batch).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method batch v2 Borsh encoding failed: {error}"
            ))
        })?;
        Ok((batch, batch_id, bytes))
    }

    pub(crate) fn commitment_from_replayed_tasks(
        tasks: &[ProveTask],
    ) -> crate::error::TexasAirResult<(Self, [u8; 32], Vec<u8>)> {
        let batch = Self::from_replayed_tasks(tasks)?;
        let batch_id = batch.batch_id_from_replayed_tasks(tasks)?;
        let bytes = borsh::to_vec(&batch).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method batch v2 Borsh encoding failed: {error}"
            ))
        })?;
        Ok((batch, batch_id, bytes))
    }

    /// Strict canonical encoding. Historical task-list layouts are not supported.
    pub fn to_bytes(&self) -> crate::error::TexasAirResult<Vec<u8>> {
        self.replay_tasks()?;
        borsh::to_vec(self).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method batch v2 Borsh encoding failed: {error}"
            ))
        })
    }

    /// Strict canonical decoding with version and trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::TexasAirResult<Self> {
        let batch = Self::try_from_slice(bytes).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method batch v2 Borsh decoding failed: {error}"
            ))
        })?;
        batch.replay_tasks()?;
        Ok(batch)
    }

    /// Replay every command from the single initial state and rebuild canonical tasks.
    pub fn replay_tasks(&self) -> crate::error::TexasAirResult<Vec<ProveTask>> {
        if self.version != METHOD_BATCH_STREAM_VERSION {
            return Err(crate::error::TexasAirError::SerializationError(format!(
                "unsupported method batch stream version {}",
                self.version
            )));
        }
        if self.commands.is_empty() || self.commands.len() > MAX_METHOD_BATCH_ROWS {
            return Err(crate::error::TexasAirError::SpecViolation(format!(
                "method batch must contain 1..={MAX_METHOD_BATCH_ROWS} commands"
            )));
        }
        let mut table = self.initial_table.clone();
        let mut tasks: Vec<ProveTask> = Vec::with_capacity(self.commands.len());
        for (index, command) in self.commands.iter().enumerate() {
            let selector = command.method_kind.selector();
            let replay_args = poker_l1::contracts::texas_poker::dispatch::replay_dispatch_args(
                command.method_kind as u8,
                &command.raw_args,
                &command.context,
                &table,
            )
            .map_err(|error| {
                crate::error::TexasAirError::SpecViolation(format!(
                    "method batch command {index} canonical replay payload failed: {error}"
                ))
            })?;
            let result = poker_l1::contracts::texas_poker::dispatch::dispatch(
                &command.context,
                &mut table,
                &selector,
                &replay_args,
            )
            .map_err(|error| {
                crate::error::TexasAirError::SpecViolation(format!(
                    "method batch command {index} VM replay failed: {error}"
                ))
            })?;
            let output: DispatchOutput =
                borsh::from_slice(&result.return_value).map_err(|error| {
                    crate::error::TexasAirError::SerializationError(format!(
                        "method batch command {index} dispatch output decoding failed: {error}"
                    ))
                })?;
            let task = output.prove_task.ok_or_else(|| {
                crate::error::TexasAirError::SpecViolation(format!(
                    "method batch command {index} did not change state"
                ))
            })?;
            if task.method_kind != command.method_kind
                || task.context != command.context
                || task.raw_args != command.raw_args
            {
                return Err(crate::error::TexasAirError::SpecViolation(format!(
                    "method batch command {index} does not match replayed task"
                )));
            }
            if let Some(first) = tasks.first() {
                if task.table_id != first.table_id || task.hand_id != first.hand_id {
                    return Err(crate::error::TexasAirError::SpecViolation(
                        "method batch crosses table or post-dispatch hand scope".into(),
                    ));
                }
            }
            tasks.push(task);
        }
        if table != self.final_table {
            return Err(crate::error::TexasAirError::SpecViolation(
                "method batch final state differs from continuous VM replay".into(),
            ));
        }
        Ok(tasks)
    }

    /// Domain-separated identifier of the exact stream and state endpoints.
    pub fn batch_id(&self) -> crate::error::TexasAirResult<[u8; 32]> {
        let tasks = self.replay_tasks()?;
        self.batch_id_from_replayed_tasks(&tasks)
    }

    pub(crate) fn batch_id_from_replayed_tasks(
        &self,
        tasks: &[ProveTask],
    ) -> crate::error::TexasAirResult<[u8; 32]> {
        let first = tasks.first().expect("non-empty batch replayed");
        let last = tasks.last().expect("non-empty batch replayed");
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        hasher.update(b"zchain.texas_poker.method_batch_stream.v2");
        hasher.update(&[self.version]);
        hasher.update(&first.table_id.to_le_bytes());
        hasher.update(&first.hand_id.to_le_bytes());
        hasher.update(&first.call_seq.to_le_bytes());
        hasher.update(&last.call_seq.to_le_bytes());
        hasher.update(&crate::state_root::compute_state_root(&self.initial_table)?.bytes());
        hasher.update(&crate::state_root::compute_state_root(&self.final_table)?.bytes());
        for task in tasks {
            let command =
                poker_l1::contracts::texas_poker::dispatch::CanonicalCommand::from_u8(
                    task.method_kind as u8,
                )
                .ok_or_else(|| {
                    crate::error::TexasAirError::SpecViolation(
                        "unknown canonical method tag".into(),
                    )
                })?;
            let tag = command.batch_tag();
            hasher.update(&[tag.family as u8, tag.subtag]);
            hasher.update(&dispatch_call_digest(
                &task.context,
                &task.selector(),
                &task.raw_args,
            )?);
        }
        let mut digest = [0; 32];
        hasher.finalize_variable(&mut digest).expect("32 <= 64");
        Ok(digest)
    }

    /// Initial canonical state of the stream.
    #[must_use]
    pub const fn initial_table(
        &self,
    ) -> &poker_l1::contracts::texas_poker::types::TexasPokerTable {
        &self.initial_table
    }

    /// Final canonical state of the stream.
    #[must_use]
    pub const fn final_table(
        &self,
    ) -> &poker_l1::contracts::texas_poker::types::TexasPokerTable {
        &self.final_table
    }

    /// Canonical commands without duplicated intermediate states.
    #[must_use]
    pub fn commands(&self) -> &[MethodBatchCommandV2] {
        &self.commands
    }
}

impl MethodPayloadV2 {
    /// Build one narrow tagged method row after host-native receipt verification.
    pub fn from_verified_task(
        task: &ProveTask,
        batch: MethodBatchReferenceV2,
        admin_binding: Option<&crate::authorization_binding::AdminAuthorizationBinding>,
        crypto_binding: Option<&crate::precompile_binding::PrecompileCallBinding>,
    ) -> crate::error::TexasAirResult<Self> {
        crate::orchestrator::validate_full_dispatch_task(task)?;
        Self::from_replayed_task(task, batch, admin_binding, crypto_binding)
    }

    /// Build one narrow tagged method row from a task already established by canonical VM replay.
    ///
    /// This is crate-private because skipping dispatch here is sound only while the caller owns
    /// the replay result and verifier-issued receipt capabilities. Public callers must use
    /// [`Self::from_verified_task`], which establishes that boundary itself.
    pub(crate) fn from_replayed_task(
        task: &ProveTask,
        batch: MethodBatchReferenceV2,
        admin_binding: Option<&crate::authorization_binding::AdminAuthorizationBinding>,
        crypto_binding: Option<&crate::precompile_binding::PrecompileCallBinding>,
    ) -> crate::error::TexasAirResult<Self> {
        batch.validate()?;
        let command = poker_l1::contracts::texas_poker::dispatch::CanonicalCommand::from_u8(
            task.method_kind as u8,
        )
        .ok_or_else(|| {
            crate::error::TexasAirError::SpecViolation("unknown canonical method tag".into())
        })?;
        let tag = command.batch_tag();
        let admin_expected = matches!(
            task.method_kind,
            MethodKind::StartHand | MethodKind::ForceFold | MethodKind::KickPlayer
        );
        let crypto_expected = matches!(
            task.method_kind,
            MethodKind::SubmitShuffleV2
                | MethodKind::SubmitPlayerRevealTokens
                | MethodKind::SubmitReconstructDeck
                | MethodKind::FoldWithProof
        );
        if admin_expected != admin_binding.is_some() {
            return Err(crate::error::TexasAirError::SpecViolation(
                "tagged method payload administrator receipt presence mismatch".into(),
            ));
        }
        if crypto_expected != crypto_binding.is_some() {
            return Err(crate::error::TexasAirError::SpecViolation(
                "tagged method payload crypto receipt presence mismatch".into(),
            ));
        }
        if let Some(binding) = crypto_binding {
            binding.validate_issued()?;
        }
        let admin_receipt = admin_binding.map_or(MethodReceiptDigestV2::NONE, |binding| {
            MethodReceiptDigestV2 {
                tag: 1,
                request_digest: binding.request_digest(),
                receipt_digest: binding.receipt_digest(),
            }
        });
        let crypto_receipt = crypto_binding.map_or(MethodReceiptDigestV2::NONE, |binding| {
            MethodReceiptDigestV2 {
                tag: binding.precompile_id() as u8,
                request_digest: binding.request_digest(),
                receipt_digest: binding.receipt_digest(),
            }
        });
        let transition_plan_digest =
            if crate::airs::composition::supports_composite_proof(task.method_kind) {
                let plan =
                    crate::airs::composition::derive_composite_transition_plan_from_task(task)?;
                let active_count = [
                    plan.seat_update.active,
                    plan.bet_collection.active,
                    plan.round_advance.active,
                    plan.settlement.active,
                ]
                .into_iter()
                .filter(|active| *active)
                .count();
                if usize::from(batch.stage_row_count) != active_count {
                    return Err(crate::error::TexasAirError::SpecViolation(
                        "tagged method payload Stage row count differs from transition plan".into(),
                    ));
                }
                plan.plan_digest
            } else {
                if batch.stage_row_count != 0 {
                    return Err(crate::error::TexasAirError::SpecViolation(
                        "non-composite method cannot reference tagged Stage rows".into(),
                    ));
                }
                [0; 32]
            };
        let payload = Self {
            version: METHOD_PAYLOAD_VERSION,
            family: tag.family as u8,
            subtag: tag.subtag,
            actor: task.context.caller,
            table_id: task.table_id,
            hand_id: task.hand_id,
            pre_call_seq: task.pre_table.call_seq,
            post_call_seq: task.post_table.call_seq,
            pre_state_root: crate::state_root::compute_state_root(&task.pre_table)?.bytes(),
            post_state_root: crate::state_root::compute_state_root(&task.post_table)?.bytes(),
            canonical_command_digest: dispatch_call_digest(
                &task.context,
                &task.selector(),
                &task.raw_args,
            )?,
            admin_receipt,
            crypto_receipt,
            batch,
            transition_plan_digest,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Strict canonical encoding for durable method-row statements.
    pub fn to_bytes(&self) -> crate::error::TexasAirResult<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method payload v2 Borsh encoding failed: {error}"
            ))
        })
    }

    /// Strict canonical decoding with trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> crate::error::TexasAirResult<Self> {
        let payload = Self::try_from_slice(bytes).map_err(|error| {
            crate::error::TexasAirError::SerializationError(format!(
                "method payload v2 Borsh decoding failed: {error}"
            ))
        })?;
        payload.validate()?;
        Ok(payload)
    }

    /// Validate version, sequence and optional tagged-receipt canonicality.
    pub fn validate(&self) -> crate::error::TexasAirResult<()> {
        let valid_subtag = match self.family {
            0 => self.subtag == 0,
            1 => self.subtag <= 3,
            2 => self.subtag <= 1,
            3 => self.subtag <= 2,
            4 => self.subtag <= 5,
            5 => self.subtag <= 2,
            _ => false,
        };
        if self.version != METHOD_PAYLOAD_VERSION
            || !valid_subtag
            || self.admin_receipt.tag > 1
            || self.crypto_receipt.tag > 5
            || self.post_call_seq
                != self.pre_call_seq.checked_add(1).ok_or_else(|| {
                    crate::error::TexasAirError::SpecViolation(
                        "method payload call_seq overflow".into(),
                    )
                })?
            || self.post_state_root == [0; 32]
            || self.canonical_command_digest == [0; 32]
        {
            return Err(crate::error::TexasAirError::SpecViolation(
                "invalid canonical method payload v2".into(),
            ));
        }
        self.batch.validate()?;
        self.admin_receipt.validate("administrator")?;
        self.crypto_receipt.validate("crypto")?;
        Ok(())
    }
}

fn same_task(left: &ProveTask, right: &ProveTask) -> crate::error::TexasAirResult<bool> {
    // `canonical_command_bytes` is a pure function of `method_kind` and
    // `raw_args`, both compared field-wise here, so serializing both tasks
    // again would be redundant.
    Ok(left.method_kind == right.method_kind
        && left.context == right.context
        && left.raw_args == right.raw_args
        && left.pre_table == right.pre_table
        && left.post_table == right.post_table
        && left.table_id == right.table_id
        && left.hand_id == right.hand_id
        && left.call_seq == right.call_seq)
}

impl BorshSerialize for ProveTask {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.method_kind.serialize(writer)?;
        self.context.serialize(writer)?;
        self.raw_args.serialize(writer)?;
        self.pre_table.serialize(writer)?;
        self.post_table.serialize(writer)?;
        self.table_id.serialize(writer)?;
        self.hand_id.serialize(writer)?;
        self.call_seq.serialize(writer)
    }
}

impl BorshDeserialize for ProveTask {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let method_kind = MethodKind::deserialize_reader(reader)?;
        let context =
            poker_l1::contracts::dispatch::DispatchContext::deserialize_reader(reader)?;
        let raw_args = Vec::<u8>::deserialize_reader(reader)?;
        let pre_table =
            poker_l1::contracts::texas_poker::types::TexasPokerTable::deserialize_reader(
                reader,
            )?;
        let post_table =
            poker_l1::contracts::texas_poker::types::TexasPokerTable::deserialize_reader(
                reader,
            )?;
        let table_id = u64::deserialize_reader(reader)?;
        let hand_id = u32::deserialize_reader(reader)?;
        let call_seq = u32::deserialize_reader(reader)?;
        poker_l1::contracts::texas_poker::dispatch::derive_authenticated_method_input(
            method_kind as u8,
            &raw_args,
            &context,
            &pre_table,
        )
        .map_err(|error| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error.to_string())
        })?;
        Ok(Self {
            method_kind,
            context,
            raw_args,
            pre_table,
            post_table,
            table_id,
            hand_id,
            call_seq,
        })
    }
}

/// dispatch 输出结构（return_value 的新格式）。
///
/// 包含 state_machine 产生的 events + 证明任务。
/// Orchestrator 从链层取回 return_value 后反序列化此结构。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DispatchOutput {
    /// 事件日志（40 种 TexasPokerEvent）。
    pub events: Vec<poker_l1::contracts::texas_poker::events::TexasPokerEvent>,
    /// 证明任务（None 表示此次 dispatch 无需证明，如 tick 无状态变更时）。
    pub prove_task: Option<ProveTask>,
}

impl DispatchOutput {
    /// 仅含 events（无证明任务）的便捷构造。
    #[must_use]
    pub fn events_only(
        events: Vec<poker_l1::contracts::texas_poker::events::TexasPokerEvent>,
    ) -> Self {
        Self {
            events,
            prove_task: None,
        }
    }

    /// 含 events + 证明任务的构造。
    #[must_use]
    pub fn with_task(
        events: Vec<poker_l1::contracts::texas_poker::events::TexasPokerEvent>,
        prove_task: ProveTask,
    ) -> Self {
        Self {
            events,
            prove_task: Some(prove_task),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support as seat_fixture;
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::contracts::dispatch::DispatchContext;
    use poker_l1::contracts::texas_poker::constants::RIT_MODE_DISABLED;
    use poker_l1::contracts::texas_poker::dispatch::CreateTableArgs;

    fn dummy_table() -> poker_l1::contracts::texas_poker::types::TexasPokerTable {
        use poker_l1::object_model::ObjectID;
        let mut table = poker_l1::contracts::texas_poker::types::TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            [0xAA; 20],
            6,
            50,
            100,
        );
        seat_fixture::set_player(&mut table.seats[2], [0xAA; 20]);
        table.seats[2].set_status(poker_l1::contracts::texas_poker::types::SeatStatus::Active);
        table
    }

    fn dummy_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    fn canonical_create_task() -> ProveTask {
        use poker_l1::contracts::texas_poker::dispatch::{dispatch, selectors};

        let context = dummy_context();
        let mut table = dummy_table();
        let args = borsh::to_vec(&CreateTableArgs {
            max_players: 6,
            small_blind: 50,
            big_blind: 100,
            rit_mode: RIT_MODE_DISABLED,
        })
        .unwrap();
        let result = dispatch(&context, &mut table, &selectors::create_table(), &args).unwrap();
        let output: DispatchOutput = borsh::from_slice(&result.return_value).unwrap();
        output.prove_task.unwrap()
    }

    #[test]
    fn prove_task_borsh_roundtrip() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            vec![],
            dummy_table(),
            dummy_table(),
            42,
            1,
            3,
        );
        let bytes = borsh::to_vec(&task).unwrap();
        let recovered: ProveTask = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.method_kind, MethodKind::Fold);
        assert_eq!(recovered.table_id, 42);
        assert_eq!(recovered.hand_id, 1);
        assert_eq!(recovered.call_seq, 3);
        match recovered.method_input().unwrap() {
            MethodInput::SeatOnly { seat_index } => assert_eq!(seat_index, 2),
            other => panic!("expected SeatOnly, got {other:?}"),
        }
    }

    #[test]
    fn command_views_are_derived_from_the_canonical_payload() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            vec![],
            dummy_table(),
            dummy_table(),
            42,
            1,
            3,
        );
        let canonical = borsh::to_vec(&task).unwrap();
        let recovered: ProveTask = borsh::from_slice(&canonical).unwrap();
        assert_eq!(recovered.selector(), MethodKind::Fold.selector());
        assert_eq!(
            recovered.method_input().unwrap(),
            MethodInput::SeatOnly { seat_index: 2 }
        );
        assert_eq!(
            recovered.canonical_command_bytes().unwrap(),
            task.canonical_command_bytes().unwrap()
        );
    }

    #[test]
    fn malformed_canonical_payload_fails_deserialization() {
        let task = ProveTask::new(
            MethodKind::Fold,
            dummy_context(),
            vec![],
            dummy_table(),
            dummy_table(),
            42,
            1,
            3,
        );
        let mut malformed = task;
        malformed.raw_args.push(2);
        let bytes = borsh::to_vec(&malformed).unwrap();
        assert!(borsh::from_slice::<ProveTask>(&bytes).is_err());
    }

    #[test]
    fn canonical_deadline_payload_is_empty_and_timestamp_payloads_fail_closed() {
        use poker_l1::contracts::texas_poker::dispatch::{canonical_command_parts, selectors};

        let context = dummy_context();
        let (_, canonical) = canonical_command_parts(&selectors::advance_deadline(), &[]).unwrap();
        assert!(canonical.is_empty());
        assert!(
            canonical_command_parts(
                &selectors::advance_deadline(),
                &borsh::to_vec(&context.block_timestamp).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn dispatch_output_borsh_roundtrip() {
        let out = DispatchOutput::events_only(vec![]);
        let bytes = borsh::to_vec(&out).unwrap();
        let recovered: DispatchOutput = borsh::from_slice(&bytes).unwrap();
        assert!(recovered.events.is_empty());
        assert!(recovered.prove_task.is_none());

        let task = ProveTask::new(
            MethodKind::CreateTable,
            dummy_context(),
            borsh::to_vec(&CreateTableArgs {
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
                rit_mode: RIT_MODE_DISABLED,
            })
            .unwrap(),
            dummy_table(),
            dummy_table(),
            1,
            0,
            0,
        );
        let out2 = DispatchOutput::with_task(vec![], task);
        let bytes2 = borsh::to_vec(&out2).unwrap();
        let recovered2: DispatchOutput = borsh::from_slice(&bytes2).unwrap();
        assert!(recovered2.prove_task.is_some());
    }

    #[test]
    fn method_batch_v2_roundtrip_replays_without_intermediate_snapshots() {
        let task = canonical_create_task();
        let batch = MethodBatchV2::from_tasks(std::slice::from_ref(&task)).unwrap();
        assert_eq!(batch.commands().len(), 1);
        assert_eq!(batch.initial_table(), &task.pre_table);
        assert_eq!(batch.final_table(), &task.post_table);
        assert_ne!(batch.batch_id().unwrap(), [0; 32]);

        let bytes = batch.to_bytes().unwrap();
        let recovered = MethodBatchV2::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, batch);
        assert!(same_task(&recovered.replay_tasks().unwrap()[0], &task).unwrap());

        let mut trailing = bytes;
        trailing.push(0);
        assert!(MethodBatchV2::from_bytes(&trailing).is_err());
    }

    #[test]
    fn method_payload_v2_binds_call_seq_roots_and_batch_scope() {
        let task = canonical_create_task();
        let batch = MethodBatchV2::from_tasks(std::slice::from_ref(&task)).unwrap();
        let reference = MethodBatchReferenceV2 {
            batch_id: batch.batch_id().unwrap(),
            row_index: 0,
            row_count: 1,
            stage_start_row: 0,
            stage_row_count: 0,
        };
        let payload = MethodPayloadV2::from_verified_task(&task, reference, None, None).unwrap();
        assert_eq!(payload.pre_call_seq, task.pre_table.call_seq);
        assert_eq!(payload.post_call_seq, task.post_table.call_seq);
        assert_eq!(payload.batch, reference);
        assert_eq!(payload.transition_plan_digest, [0; 32]);

        let bytes = payload.to_bytes().unwrap();
        assert_eq!(MethodPayloadV2::from_bytes(&bytes).unwrap(), payload);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(MethodPayloadV2::from_bytes(&trailing).is_err());
    }
}
