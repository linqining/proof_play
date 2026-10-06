//! 公开输入定义 — Method AIR 与 Aggregator AIR 的 public inputs。
//!
//! ## 角色
//!
//! 每个 method AIR 的公开输入包含 `pre_state_root` 和 `post_state_root`。
//! Aggregator AIR 的核心约束为 `left.post_state_root == right.pre_state_root`。
//!
use starknet_crypto::Felt;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::{M31, P as M31_MODULUS};

use crate::airs::AirStatement;
use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;
use crate::precompile_binding::PrecompileCallBinding;
use crate::prove_task::dispatch_call_digest;
use crate::state_root::{
    StateRoot, field_element_to_u32_words, state_root_to_air_limbs, state_root_to_u32_words,
};

/// Exact VM dispatch call whose digest is part of a method statement.
///
/// The call preimage is verifier auxiliary data rather than an additional
/// Fiat--Shamir field: [`TexasPublicInputs::require_dispatch_call`] recomputes
/// [`TexasPublicInputs::dispatch_call_digest`] before any canonical VM replay.
/// This lets method validators recover permissions and opaque arguments while
/// consensus anchors continue authenticating one fixed-size digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCallPublicInput {
    /// Consensus/execution context supplied to the VM dispatch.
    pub context: poker_l1::contracts::dispatch::DispatchContext,
    /// Exact routed Texas Poker selector.
    pub selector: [u8; 32],
    /// Exact Borsh argument bytes consumed by the VM.
    pub raw_args: Vec<u8>,
}

/// 单方法 proof 的**完整公开输入**——用于把证明绑定到 state_root（soundness 关键）。
///
/// 背景（soundness 修复）：此前 `proof.air` 结构体里的 `pre_state_root`/`post_state_root`
/// 从未被 mix 进 Fiat-Shamir channel，导致证明与这些值之间无密码学绑定（攻击者可替换
/// state_root 而证明仍验证通过）。
///
/// 修复（路径 A）：把 pre/post table 的完整、变长 canonical Borsh **resolved image** +
/// hot-v30 `pre_state_root`/`post_state_root` + 元数据，按**固定顺序** mix 进 channel。
/// 验证方先从 image 解码完整 table，再生成与 ObjectDb 相同的 hot projection 并重算 root。
///
/// `pre_image` / `post_image` 必须与 `table_state_preimage(table)` 的输出逐字段一致
/// （阶段 1 已补全所有 9 个 stub，preimage 含完整状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TexasPublicInputs {
    /// 调用前表台的完整 canonical state-root preimage（变长）。
    pub pre_image: Vec<Felt>,
    /// 调用后表台的完整 canonical state-root preimage（变长）。
    pub post_image: Vec<Felt>,
    /// 调用前 ObjectDb hot-v30 state root（从 `pre_image` 解码后重算）。
    pub pre_state_root: StateRoot,
    /// 调用后 ObjectDb hot-v30 state root（从 `post_image` 解码后重算）。
    pub post_state_root: StateRoot,
    /// 方法种类。
    pub kind: MethodKind,
    /// 表台 ID（防跨表台聚合攻击）。
    pub table_id: u64,
    /// 手牌序号。
    pub hand_id: u32,
    /// 方法调用序号。
    pub call_seq: u32,
    /// State version before execution.
    pub pre_version: u64,
    /// State version after execution.
    pub post_version: u64,
    /// Digest of the replayed VM dispatch context + selector + raw args.
    /// Task provenance is authenticated only by an external consensus anchor.
    pub dispatch_call_digest: [u8; 32],
    /// Exact dispatch-call preimage used by production canonical validators.
    ///
    /// Synthetic mechanism tests may leave this absent because their verifier
    /// entry point deliberately skips canonical table validation. Production
    /// validators that need VM replay must call [`Self::require_dispatch_call`].
    pub dispatch_call: Option<DispatchCallPublicInput>,
    /// Verifier-issued cryptographic precompile binding for methods that carry
    /// shuffle, leave-layer, reveal-token, or reconstruction proofs. Production
    /// verification rejects a missing binding for those AIRs.
    pub precompile_binding: Option<PrecompileCallBinding>,
    /// Verifier-reconstructed values of every original trace column in the
    /// replicated business row.
    ///
    /// This is deliberately optional at the data-construction boundary so a
    /// caller can build roots before it has reconstructed the method row.  The
    /// production prover and verifier both reject `None`; only test-helper
    /// compatibility code may populate it from a locally supplied trace.
    /// Values are canonical M31 representatives (`0 <= value < 2^31 - 1`).
    pub expected_trace_row: Option<Vec<u32>>,
    /// Independent component-proof scope; absent for the original method proof.
    pub component: Option<crate::airs::composition::ComponentStatement>,
}

impl TexasPublicInputs {
    /// 从 pre/post table 与元数据构造完整公开输入。
    ///
    /// 计算变长 canonical `table_state_preimage` 并重算 state_root，确保 image 与 root 自洽。
    /// 供 orchestrator 与 e2e 测试使用。
    ///
    /// # Errors
    ///
    /// 当 preimage 编码失败（字段序列化异常）时返回错误。
    pub fn from_tables(
        pre_table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
        post_table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
        kind: MethodKind,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> TexasAirResult<Self> {
        use crate::state_root::{compute_state_root, table_state_preimage};
        let pre_image = table_state_preimage(pre_table)?;
        let post_image = table_state_preimage(post_table)?;
        let pre_state_root = compute_state_root(pre_table)?;
        let post_state_root = compute_state_root(post_table)?;
        Ok(Self {
            pre_image,
            post_image,
            pre_state_root,
            post_state_root,
            kind,
            table_id,
            hand_id,
            call_seq,
            pre_version: u64::from(pre_table.call_seq),
            post_version: u64::from(post_table.call_seq),
            dispatch_call_digest: [0u8; 32],
            dispatch_call: None,
            precompile_binding: None,
            expected_trace_row: None,
            component: None,
        })
    }

    /// 用显式 preimage 构造，并**自动重算** state_root 使其与 image 一致。
    ///
    /// 适用于机制测试（构造合成 trace 但无真实 table）：传入任意 24 元素 image，
    /// root 由域分隔 BLAKE3 over image 字节编码重算，确保配套的 proven binding 通过。
    #[must_use]
    pub fn with_consistent_roots(
        pre_image: Vec<Felt>,
        post_image: Vec<Felt>,
        kind: MethodKind,
        table_id: u64,
        hand_id: u32,
        call_seq: u32,
    ) -> Self {
        let synthetic_root = |image: &[Felt]| {
            StateRoot(crate::state_root::state_root_digest(
                &crate::state_root_binding::synthetic_image_message(image),
            ))
        };
        let pre_state_root = synthetic_root(&pre_image);
        let post_state_root = synthetic_root(&post_image);
        Self {
            pre_image,
            post_image,
            pre_state_root,
            post_state_root,
            kind,
            table_id,
            hand_id,
            call_seq,
            pre_version: 0,
            post_version: 1,
            dispatch_call_digest: [0u8; 32],
            dispatch_call: None,
            precompile_binding: None,
            expected_trace_row: None,
            component: None,
        }
    }

    /// Bind this statement to a complete, verifier-reconstructed trace row.
    ///
    /// Rebinding to a different row is rejected, which catches accidental use
    /// of a prover witness after a trusted row has already been installed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TexasAirError::SpecViolation`] when `row` is
    /// empty or conflicts with an existing binding.
    pub fn bind_expected_trace_row(&mut self, row: &[M31]) -> TexasAirResult<()> {
        use crate::error::TexasAirError;

        if row.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "expected trace row must not be empty".into(),
            ));
        }
        let words: Vec<u32> = row.iter().map(|value| value.0).collect();
        if let Some(existing) = &self.expected_trace_row {
            if existing != &words {
                return Err(TexasAirError::SpecViolation(
                    "attempted to replace an existing trusted trace-row binding".into(),
                ));
            }
            return Ok(());
        }
        self.expected_trace_row = Some(words);
        Ok(())
    }

    /// Return the complete trusted row as canonical M31 values.
    ///
    /// Production verification calls this before constructing the AIR, so a
    /// missing, malformed, or wrong-width row fails closed before Stwo parses
    /// the proof.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TexasAirError::SpecViolation`] if no trusted row
    /// is present, its width differs from `num_columns`, or any word is not a
    /// canonical M31 representative.
    pub fn require_expected_trace_row(&self, num_columns: usize) -> TexasAirResult<Vec<M31>> {
        let row = self.expected_trace_row.as_ref().ok_or_else(|| {
            TexasAirError::SpecViolation(
                "missing verifier-trusted expected trace row (fail-closed)".into(),
            )
        })?;
        if row.len() != num_columns {
            return Err(TexasAirError::SpecViolation(format!(
                "expected trace row width {} does not match AIR width {num_columns}",
                row.len()
            )));
        }
        row.iter()
            .enumerate()
            .map(|(column, &value)| {
                if value >= M31_MODULUS {
                    Err(TexasAirError::SpecViolation(format!(
                        "expected trace row column {column} is not canonical M31: {value}"
                    )))
                } else {
                    Ok(M31::from_u32_unchecked(value))
                }
            })
            .collect()
    }

    /// Bind the exact VM dispatch-call preimage and install its canonical digest.
    ///
    /// Rebinding to different call bytes is rejected. The digest, rather than
    /// this potentially large preimage, is mixed into the proof transcript and
    /// authenticated by consensus anchors.
    pub fn bind_dispatch_call(
        &mut self,
        context: poker_l1::contracts::dispatch::DispatchContext,
        selector: [u8; 32],
        raw_args: Vec<u8>,
    ) -> TexasAirResult<()> {
        let digest = dispatch_call_digest(&context, &selector, &raw_args)?;
        let call = DispatchCallPublicInput {
            context,
            selector,
            raw_args,
        };
        if let Some(existing) = &self.dispatch_call {
            if existing != &call || self.dispatch_call_digest != digest {
                return Err(TexasAirError::SpecViolation(
                    "attempted to replace an existing dispatch-call binding".into(),
                ));
            }
            return Ok(());
        }
        self.dispatch_call_digest = digest;
        self.dispatch_call = Some(call);
        Ok(())
    }

    /// Return the exact dispatch call after recomputing and checking its digest.
    pub fn require_dispatch_call(&self) -> TexasAirResult<&DispatchCallPublicInput> {
        let call = self.dispatch_call.as_ref().ok_or_else(|| {
            TexasAirError::SpecViolation(
                "missing verifier-trusted dispatch-call preimage (fail-closed)".into(),
            )
        })?;
        let digest = dispatch_call_digest(&call.context, &call.selector, &call.raw_args)?;
        if digest != self.dispatch_call_digest {
            return Err(TexasAirError::SpecViolation(
                "dispatch-call preimage does not match the transcript-bound digest".into(),
            ));
        }
        Ok(call)
    }

    /// 构造一个固定的、自洽的「占位」公开输入（机制测试用）。
    ///
    /// image 为测试专用的 24 个 `Felt::ONE`，root 为其真实 Poseidon 哈希（自洽）。
    /// 用于不需要真实 table 的 AIR 机制测试（仅验证 prove/verify 流程，不验证 state 绑定语义）。
    #[cfg(test)]
    #[must_use]
    pub fn synthetic_placeholder(kind: MethodKind) -> Self {
        let image = vec![Felt::ONE; 24];
        Self::with_consistent_roots(image.clone(), image, kind, 0, 0, 0)
    }

    /// 把公开输入 mix 进 Fiat-Shamir channel（prover 与 verifier 共用，顺序固定）。
    ///
    /// # 顺序契约（不可变更）
    ///
    /// 1. `pre_image` 的全部变长 Felt（每个分解为 8 个大端 u32 word）
    /// 2. `post_image` 的全部变长 Felt（同上）
    /// 3. `pre_state_root`（8 个 u32 word）
    /// 4. `post_state_root`（8 个 u32 word）
    /// 5. `kind`（u32）、`table_id`（u64）、`hand_id`（u32）、`call_seq`（u32）
    ///
    /// `Felt` → u32 word 用 [`field_element_to_u32_words`]（无损 8-word 大端分解）。
    /// 用 `mix_u32s`/`mix_u64`，而非 `mix_felts`，因为 Fr 是非原生域元素，按原始字节 mix
    /// 是标准做法（与 Starknet 把 252-bit 元素序列化为字节一致）。
    pub fn mix_into<C: Channel>(&self, channel: &mut C) {
        // 1-2. pre/post image：每个 Felt → 8 u32 word，扁平拼接后一次性 mix。
        let mut felts_u32: Vec<u32> =
            Vec::with_capacity((self.pre_image.len() + self.post_image.len()) * 8);
        for f in &self.pre_image {
            felts_u32.extend_from_slice(&field_element_to_u32_words(*f));
        }
        for f in &self.post_image {
            felts_u32.extend_from_slice(&field_element_to_u32_words(*f));
        }
        channel.mix_u32s(&felts_u32);

        // 3-4. pre/post state_root（各 8 u32 word）。
        let mut roots_u32: Vec<u32> = Vec::with_capacity(16);
        roots_u32.extend_from_slice(&state_root_to_u32_words(self.pre_state_root));
        roots_u32.extend_from_slice(&state_root_to_u32_words(self.post_state_root));
        channel.mix_u32s(&roots_u32);

        // 5. 完整业务 trace 行。长度与 presence tag 都进入 transcript，
        // 防止不同列布局或缺失绑定产生相同编码。
        match &self.expected_trace_row {
            Some(row) => {
                channel.mix_u32s(&[1, row.len() as u32]);
                channel.mix_u32s(row);
            }
            None => channel.mix_u32s(&[0, 0]),
        }

        // 6. 精确 VM dispatch 调用摘要。
        let dispatch_words: Vec<u32> = self
            .dispatch_call_digest
            .chunks_exact(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().expect("4-byte digest word")))
            .collect();
        channel.mix_u32s(&dispatch_words);

        // 7. Verifier-issued precompile binding. The full request is replayed
        // outside the circuit; these full-width digests bind its result to the
        // STARK statement without trusting a prover-provided boolean.
        match &self.precompile_binding {
            Some(binding) => {
                let air = binding.air_binding();
                channel.mix_u32s(&[1, u32::from(air.precompile_id), u32::from(air.abi_version)]);
                channel.mix_u32s(
                    &air.request_digest
                        .iter()
                        .chain(&air.receipt_digest)
                        .map(|limb| limb.0)
                        .collect::<Vec<_>>(),
                );
            }
            None => channel.mix_u32s(&[0, 0, 0]),
        }

        // 8. Independent composition-stage statement.
        match &self.component {
            Some(component) => {
                channel.mix_u32s(&[
                    1,
                    u32::from(component.plan_version),
                    u32::from(component.stage_kind as u8),
                    u32::from(component.stage_index),
                    u32::from(component.active),
                ]);
                for digest in [
                    component.plan_digest,
                    component.input_digest,
                    component.output_digest,
                ] {
                    let words = digest
                        .chunks_exact(4)
                        .map(|chunk| {
                            u32::from_be_bytes(chunk.try_into().expect("4-byte digest word"))
                        })
                        .collect::<Vec<_>>();
                    channel.mix_u32s(&words);
                }
            }
            None => channel.mix_u32s(&[0, 0, 0, 0, 0]),
        }

        // 9. 元数据。
        channel.mix_u32s(&[u32::from(self.kind as u8), self.hand_id, self.call_seq]);
        channel.mix_u64(self.table_id);
        channel.mix_u64(self.pre_version);
        channel.mix_u64(self.post_version);
    }

    /// Derive both endpoint statements deterministically from the public
    /// inputs: real tables encode through the hot-v30 projection; synthetic
    /// mechanism-test images (no dispatch call) use the canonical image-byte
    /// encoding.  Prover and verifier share this derivation, so the flock
    /// binding statement is never ambiguous.
    pub fn root_endpoint_statements(
        &self,
    ) -> TexasAirResult<(
        crate::state_root_binding::StateRootEndpointStatement,
        crate::state_root_binding::StateRootEndpointStatement,
    )> {
        use crate::error::TexasAirError;
        if self.pre_image.is_empty() || self.post_image.is_empty() {
            return Err(TexasAirError::StateRootError(
                "state-root preimage must not be empty".into(),
            ));
        }
        let endpoint = |image: &[Felt],
                        root: StateRoot,
                        label: &str|
         -> TexasAirResult<
            crate::state_root_binding::StateRootEndpointStatement,
        > {
            let preimage = match crate::state_root::table_from_state_preimage(image) {
                Ok(table) if crate::state_root::is_absent_table(&table) => {
                    crate::state_root::ABSENT_TABLE_PREIMAGE.to_vec()
                }
                Ok(table) => crate::state_root::hot_table_state_bytes(&table).map_err(|error| {
                    TexasAirError::StateRootError(format!(
                        "{label} state image hot projection failed: {error}"
                    ))
                })?,
                Err(_) if self.dispatch_call.is_none() => {
                    crate::state_root_binding::synthetic_image_message(image)
                }
                Err(error) => {
                    return Err(TexasAirError::StateRootError(format!(
                        "{label} state image is not a canonical resolved Texas table: {error}"
                    )));
                }
            };
            // The endpoint statement message is the domain-prefixed preimage,
            // matching `compute_state_root` and the flock chain exactly.
            let endpoint =
                crate::state_root_binding::StateRootEndpointStatement::from_preimage(preimage);
            if endpoint.root != root.bytes() {
                return Err(TexasAirError::StateRootError(format!(
                    "{label} claimed state root does not match the derived preimage"
                )));
            }
            Ok(endpoint)
        };
        let pre = endpoint(&self.pre_image, self.pre_state_root, "pre")?;
        let post = endpoint(&self.post_image, self.post_state_root, "post")?;
        Ok((pre, post))
    }

    /// 验证方建立 `root = H(preimage)` 绑定——host 哈希重算已移除。
    ///
    /// 这是 state_root 绑定的「验证」半边（mix_into 是「承诺」半边）。
    /// 验证方从 transcript 携带的 image 确定性导出两端点 statement
    /// （真实 table 走 hot-v30 编码，无 dispatch call 的 synthetic mechanism
    /// 测试走 image 字节编码），然后要求一个 flock 哈希证明恰好覆盖这两个
    /// `(message, root)` 语句——`root = BLAKE3(message)` 由证明承载，host
    /// 不再重算任何哈希。canonical table 解码失败且非 synthetic 场景时
    /// fail-closed。
    ///
    /// # Errors
    ///
    /// 当 pre/post_image 为空、image 不是 canonical table（且非 synthetic
    /// 场景）、或证明未恰好覆盖两个端点语句时返回错误。
    pub fn verify_roots(
        &self,
        binding: &crate::state_root_binding::ArchivedStateRootBindingProof,
    ) -> TexasAirResult<()> {
        let (pre_endpoint, post_endpoint) = self.root_endpoint_statements()?;
        crate::state_root_binding::verify_state_root_binding(binding, &pre_endpoint, &post_endpoint)
    }

    /// Check that an independently reconstructed AIR compiles exactly this
    /// verifier-trusted statement.
    pub fn verify_air_statement(&self, statement: &AirStatement) -> TexasAirResult<()> {
        use crate::error::TexasAirError;
        let matches = statement.kind == self.kind
            && statement.pre_state_root == state_root_to_air_limbs(self.pre_state_root)
            && statement.post_state_root == state_root_to_air_limbs(self.post_state_root)
            && statement.table_id == self.table_id
            && statement.hand_id == self.hand_id
            && statement.call_seq == self.call_seq
            && statement.pre_version == self.pre_version
            && statement.post_version == self.post_version
            && statement.component == self.component;
        if !matches {
            return Err(TexasAirError::SpecViolation(
                "AIR statement does not match verifier-trusted Texas public inputs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::channel::Poseidon252Channel;

    // ===== 阶段 2：state_root 绑定测试（soundness 关键）=====

    fn proven_binding(
        pi: &TexasPublicInputs,
    ) -> crate::state_root_binding::ArchivedStateRootBindingProof {
        crate::state_root_binding::prove_state_root_binding_for_inputs(pi)
            .expect("consistent synthetic inputs should prove")
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn test_verify_roots_accepts_consistent() {
        // 自洽 PI + 覆盖两端点的 flock 绑定证明 → verify_roots 必通过。
        let pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let binding = proven_binding(&pi);
        assert!(
            pi.verify_roots(&binding).is_ok(),
            "自洽 PI 的 verify_roots 应通过"
        );
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn test_verify_roots_rejects_tampered_root() {
        // 篡改 pre_state_root（不改 image、不改证明）→ 端点语句与证明脱钩 → 失败。
        // 这验证了「root = BLAKE3(preimage) 由证明承载」这条绑定生效。
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let binding = proven_binding(&pi);
        pi.pre_state_root = StateRoot::from_field(Felt::ONE);
        assert!(
            pi.verify_roots(&binding).is_err(),
            "篡改 root 后 verify_roots 应失败"
        );
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn test_verify_roots_rejects_tampered_image() {
        // 篡改 image（不改 root、不改证明）→ 端点语句与证明脱钩 → 失败。
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let binding = proven_binding(&pi);
        pi.pre_image[0] = Felt::from(12345u64);
        assert!(
            pi.verify_roots(&binding).is_err(),
            "篡改 image 后 verify_roots 应失败"
        );
    }

    #[test]
#[ignore = "slow prove (~10-25s); full gate runs --include-ignored"]
    fn test_verify_roots_rejects_empty_preimage() {
        let pi = TexasPublicInputs {
            pre_image: vec![],
            post_image: vec![Felt::ONE; 24],
            pre_state_root: StateRoot::zero(),
            post_state_root: StateRoot::zero(),
            kind: MethodKind::Call,
            table_id: 0,
            hand_id: 0,
            call_seq: 0,
            pre_version: 0,
            post_version: 1,
            dispatch_call_digest: [0u8; 32],
            dispatch_call: None,
            precompile_binding: None,
            expected_trace_row: None,
            component: None,
        };
        // The endpoint derivation must reject the empty image before any
        // binding is consulted; use an arbitrary valid binding.
        let endpoint =
            crate::state_root_binding::StateRootEndpointStatement::from_preimage(Vec::new());
        let binding =
            crate::state_root_binding::prove_state_root_binding(endpoint.clone(), endpoint)
                .expect("dummy binding proves");
        assert!(pi.verify_roots(&binding).is_err(), "empty image must fail");
    }

    #[test]
    fn test_mix_into_is_deterministic() {
        // 同样的 PI mix 进两个相同 channel，结果应相同（prover/verifier 对称性契约）。
        let pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let mut c1 = Poseidon252Channel::default();
        let mut c2 = Poseidon252Channel::default();
        pi.mix_into(&mut c1);
        pi.mix_into(&mut c2);
        // mix 后从两个 channel draw 相同数量的 random felt，应一致
        let r1 = c1.draw_secure_felts(4);
        let r2 = c2.draw_secure_felts(4);
        assert_eq!(r1, r2, "相同 PI 的 mix 应确定性（prover/verifier 对称）");
    }

    #[test]
    fn test_mix_into_distinguishes_different_pi() {
        // 不同 PI mix 后 channel 状态不同（draw 出不同值）。
        let pi_a = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        let pi_b = TexasPublicInputs::synthetic_placeholder(MethodKind::Raise);
        let mut c1 = Poseidon252Channel::default();
        let mut c2 = Poseidon252Channel::default();
        pi_a.mix_into(&mut c1);
        pi_b.mix_into(&mut c2);
        let r1 = c1.draw_secure_felts(4);
        let r2 = c2.draw_secure_felts(4);
        assert_ne!(r1, r2, "不同 PI 的 mix 应区分（绑定生效）");
    }

    #[test]
    fn trusted_trace_row_is_required_and_width_checked() {
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        assert!(pi.require_expected_trace_row(2).is_err());

        pi.bind_expected_trace_row(&[M31::from(7u32), M31::from(9u32)])
            .unwrap();
        assert_eq!(
            pi.require_expected_trace_row(2).unwrap(),
            vec![M31::from(7u32), M31::from(9u32)]
        );
        assert!(pi.require_expected_trace_row(1).is_err());
    }

    #[test]
    fn trusted_trace_row_rejects_noncanonical_words_and_rebinding() {
        let mut pi = TexasPublicInputs::synthetic_placeholder(MethodKind::Call);
        pi.bind_expected_trace_row(&[M31::from(7u32)]).unwrap();
        assert!(
            pi.bind_expected_trace_row(&[M31::from(8u32)]).is_err(),
            "a trusted binding must not be replaceable"
        );

        pi.expected_trace_row = Some(vec![M31_MODULUS]);
        assert!(
            pi.require_expected_trace_row(1).is_err(),
            "noncanonical M31 words must be rejected instead of reduced"
        );
    }
}
