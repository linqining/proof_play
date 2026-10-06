//! P2-M2 服务端接缝：`SettlementPrivateStatement` 构建 → prove-hand 电路
//! inputs 导出 → `STARKNET_PROVER_URL` 客户端（prove-settlement 管线）。
//!
//! 与 P2-M1/M2 的分工：
//! - 根 crate `settlement_private_circuit.rs`：语句/参考实现（starknet_crypto）；
//! - `proving-tool/src/settlement_private.cairo` + `scripts/prove-settlement.sh` +
//!   `scripts/prover_service.py`：Cairo1 电路与 Stwo 证明——**已迁 9 席**
//!   （2026-09-30 Span ABI 重构：单一 `Span<felt252>` wire 102 词，
//!   `[len, elements…]` 摊平，见 [`V2_CIRCUIT_INPUT_WORDS`]）；
//! - **本模块**：从结算明文（`HandSettlement` 同源的 players/deltas/digest）构建
//!   电路请求，async 读取赢家 payout commitment（vault），把 inputs JSON 导出到
//!   workload 目录（best-effort，绝不阻塞结算），并通过 HTTP 向 prover 服务
//!   （`STARKNET_PROVER_URL`，指向 `prover_service.py`）请求证明 attestation。
//!
//! 隐私模型：只有 inputs JSON 落盘（witness，operator 主机本地）；公开段
//! `[MAGIC, hand_id, digest, n, binding, cm_0..cm_8]`（16 词，9 人桌口径）
//! 由服务端独立重算校验——prover 返回的 digest 必须等于请求的
//! registered_digest，cms 必须等于本地推导，任何不匹配/失败都只告警
//! （结算路径不由本模块决定）。

use starknet::core::utils::starknet_keccak;
use starknet_crypto::Felt;

/// 参与者上限（9 人桌口径，与 combined 电路 / v2 单手电路（settlement_
/// private.cairo，2026-09-30 Span ABI 迁移后）/ 合约参与窗口 `2..=9`
/// 一致）。根 crate 参考实现（`src/settlement_private_circuit.rs`）
/// 同步 9 席。
pub const MAX_PARTICIPANTS: usize = 9;
/// Cairo 电路的 Magic 标记（'SP2M_OK' = 0x5350324d5f4f4b）。
pub fn prove_magic() -> Felt {
    const BYTES: [u8; 32] = {
        let mut b = [0u8; 32];
        // 'SP2M_OK' = 0x5350324d5f4f4b（大端尾对齐）
        b[25] = 0x53;
        b[26] = 0x50;
        b[27] = 0x32;
        b[28] = 0x4d;
        b[29] = 0x5f;
        b[30] = 0x4f;
        b[31] = 0x4b;
        b
    };
    Felt::from_bytes_be(&BYTES)
}

/// 32 字节 wire 词 → felt。types-core 的 `from_bytes_be` 无失败路径
/// （≥ P 输入静默归约），沿用原 Result 语义：非 canonical 输入拒绝。
fn wire_felt(bytes: &[u8; 32]) -> Result<Felt, String> {
    let felt = Felt::from_bytes_be(bytes);
    if felt.to_bytes_be() != *bytes {
        return Err("felt not in felt252 range".to_string());
    }
    Ok(felt)
}

/// 证明请求（明文只在 operator 主机内存在）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPrivateRequest {
    pub hand_id: u32,
    pub hand_binding: [u8; 32],
    pub registered_digest: [u8; 32],
    /// 固定 9 槽，未用槽位零 felt。
    pub players: [[u8; 32]; MAX_PARTICIPANTS],
    /// 规格分解 sign ∈ {0,1}（d ≥ 0 → 1）。
    pub signs: [u8; MAX_PARTICIPANTS],
    /// |delta|（wei，≤ u64）。
    pub magnitudes: [u64; MAX_PARTICIPANTS],
    pub n_participants: u32,
    /// 赢家 payout commitment；非赢家槽零。
    pub commitments: [[u8; 32]; MAX_PARTICIPANTS],
    /// 本手动作日志哈希（#18 Phase B，32 字节大端）——digest 吸收链尾词 +
    /// 公开段尾词（第 37 入参）。
    pub action_log_digest: [u8; 32],
    /// 本手动作日志词条对（每条 2 felt：[日志词, 合法性词]，切片 2：电路按
    /// 30 槽重放 + "合法默认"校验；空 = 无动作日志）。32 字节大端。
    pub action_entries: Vec<[u8; 32]>,
}

/// 从结算明文构建请求（digest 由同一公式重算——与 register calldata 中的
/// settlement_digest 逐字节一致）。
pub fn build_request(
    hand_id: u32,
    hand_binding: Felt,
    players: &[Felt],
    deltas_wei: &[i128],
    commitments: &[[u8; 32]; MAX_PARTICIPANTS],
    action_log_digest: Felt,
    action_entries: &[[Felt; 2]],
) -> Result<SettlementPrivateRequest, String> {
    use crate::pokergame::actions::ACTION_LOG_MAX_ENTRIES;
    if action_entries.len() > ACTION_LOG_MAX_ENTRIES {
        return Err(format!(
            "action log has {} entries, exceeds circuit maximum {ACTION_LOG_MAX_ENTRIES}",
            action_entries.len()
        ));
    }
    let mut padded_players = [[0u8; 32]; MAX_PARTICIPANTS];
    if players.len() > MAX_PARTICIPANTS || deltas_wei.len() > MAX_PARTICIPANTS {
        return Err("participants exceed circuit maximum of 9".into());
    }
    let mut sum: i128 = 0;
    let mut n_participants: u32 = 0;
    let mut signs = [0u8; MAX_PARTICIPANTS];
    let mut magnitudes = [0u64; MAX_PARTICIPANTS];
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        if delta.unsigned_abs() > u64::MAX as u128 {
            return Err(format!("|delta| at seat {i} exceeds u64"));
        }
        padded_players[i] = players
            .get(i)
            .map(|p| p.to_bytes_be())
            .unwrap_or([0u8; 32]);
        signs[i] = u8::from(delta >= 0);
        magnitudes[i] = delta.unsigned_abs() as u64;
        if delta != 0 {
            n_participants += 1;
        }
        sum = sum
            .checked_add(delta)
            .ok_or_else(|| format!("delta sum overflow at seat {i}"))?;
    }
    if sum != 0 {
        return Err("settlement is not zero-sum".into());
    }
    for (i, commitment) in commitments.iter().enumerate() {
        if deltas_wei.get(i).copied().unwrap_or(0) > 0 && *commitment == [0u8; 32] {
            return Err(format!("winner at seat {i} has no payout commitment"));
        }
    }

    // registered_digest = poseidon_hash_many([hand_id] ++ Σ(player, sign, |delta|)
    // ++ [action_log_digest])（与 submit.rs / 合约 compute_settlement_digest
    // 逐字段一致；#18 Phase B 尾词 = 动作日志哈希）。
    // 2026-09-06 修复：按**实际参与人数**折叠（此前补零到 8 槽，n<8 时
    // segment 摘要与链上注册值必然不匹配 → 零明文结算 revert）。
    let mut fields = Vec::with_capacity(2 + 3 * players.len());
    fields.push(Felt::from(hand_id));
    for i in 0..players.len() {
        fields.push(wire_felt(&padded_players[i])?);
        fields.push(Felt::from(u64::from(signs[i])));
        fields.push(Felt::from(magnitudes[i]));
    }
    fields.push(action_log_digest);
    let registered_digest = starknet_crypto::poseidon_hash_many(&fields).to_bytes_be();

    Ok(SettlementPrivateRequest {
        hand_id,
        hand_binding: hand_binding.to_bytes_be(),
        registered_digest,
        players: padded_players,
        signs,
        magnitudes,
        n_participants,
        commitments: *commitments,
        action_log_digest: action_log_digest.to_bytes_be(),
        action_entries: action_entries
            .iter()
            .flat_map(|pair| pair.iter().map(|w| w.to_bytes_be()))
            .collect(),
    })
}

/// async 读取赢家 payout commitment（vault.payout_commitment）。
/// 非赢家槽返回零；链不可用/查询失败/赢家未注册 → Err（best-effort 调用方忽略）。
pub async fn fetch_payout_commitments(
    players: &[Felt],
    deltas_wei: &[i128],
) -> Result<[[u8; 32]; MAX_PARTICIPANTS], String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let vault_addr = super::chain::parse_felt(&chain.config.vault_address)
        .ok_or("invalid vault address")?;
    let selector = starknet_keccak(b"payout_commitment");
    let mut commitments = [[0u8; 32]; MAX_PARTICIPANTS];
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        let Some(player) = players.get(i).copied() else { break };
        if delta <= 0 {
            continue;
        }
        let felts = chain
            .call_contract(vault_addr, selector, vec![player])
            .await
            .map_err(|e| format!("payout_commitment query failed for {player:#x}: {e}"))?;
        let value = felts.first().copied().ok_or("empty payout_commitment result")?;
        if value == starknet::core::types::Felt::ZERO {
            return Err(format!("winner {player:#x} has no payout commitment"));
        }
        commitments[i] = value.to_bytes_be();
    }
    Ok(commitments)
}

impl SettlementPrivateRequest {
    /// settle wire 的 102 词（布局与 settlement_stmt.cairo /
    /// settlement_private.cairo 的 Span wire 逐槽一致）：4 头词 + p/s/m/c×9 +
    /// ald@40（第 41 词，#18 Phase B）+ count@41 + 词条区 60 词。发往 v2
    /// 单手电路时按 Span ABI 摊平（[`Self::flat_inputs_hex`]：`[102] ++
    /// wire`）；combined 语句序列化（prove_combined）直接消费结构体字段，
    /// 不经本方法。
    pub fn inputs_felts(&self) -> Vec<Felt> {
        let mut felts = Vec::with_capacity(5 + 4 * MAX_PARTICIPANTS);
        felts.push(Felt::from(self.hand_id));
        felts.push(wire_felt(&self.registered_digest).expect("canonical digest"));
        felts.push(Felt::from(self.n_participants));
        felts.push(wire_felt(&self.hand_binding).expect("canonical binding"));
        for player in &self.players {
            felts.push(wire_felt(player).expect("canonical player"));
        }
        for sign in &self.signs {
            felts.push(Felt::from(u64::from(*sign)));
        }
        for magnitude in &self.magnitudes {
            felts.push(Felt::from(*magnitude));
        }
        for commitment in &self.commitments {
            felts.push(wire_felt(commitment).expect("canonical commitment"));
        }
        felts.push(
            wire_felt(&self.action_log_digest).expect("canonical action log digest"),
        );
        // #18 Phase C 切片 2：词条区 = [count] ++ 30×[日志词, 合法性词]
        // （不足补零）——与 Cairo 电路 Span wire 的 42..102 槽逐位对齐
        // （2026-09-30 Span ABI 重构后 standalone 100 参上限不再约束：
        // main 只有一个 Span 参数）。
        use crate::pokergame::actions::ACTION_LOG_MAX_ENTRIES;
        let count = self.action_entries.len() / 2; // 扁平存储：2 词/词条
        felts.push(Felt::from(count as u64));
        for slot in 0..ACTION_LOG_MAX_ENTRIES {
            let pair = match self.action_entries.get(slot * 2..slot * 2 + 2) {
                Some(pair) => [pair[0], pair[1]],
                None => [[0u8; 32]; 2],
            };
            for word in pair {
                felts.push(wire_felt(&word).expect("canonical action word"));
            }
        }
        self.dump_wire_if_configured(&felts);
        felts
    }

    /// 结算 wire 落盘仪表（env 门控）：`TEXAS_SETTLE_WIRE_DUMP` 指向 JSONL
    /// 路径时，每次构建 102 词 wire 追加一行 `{hand_id, binding, words}`。
    /// 用途：fold 攒批管线的真实手语料采集（prove-batch.sh base input）。
    /// 生产勿设。
    fn dump_wire_if_configured(&self, words: &[Felt]) {
        let Ok(path) = std::env::var("TEXAS_SETTLE_WIRE_DUMP") else {
            return;
        };
        let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path)
        else {
            return;
        };
        let hex32 = |b: &[u8]| format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
        let line = serde_json::json!({
            "hand_id": self.hand_id,
            "binding": hex32(&self.hand_binding),
            "words": words
                .iter()
                .map(|w| {
                    let be = w.to_bytes_be();
                    hex32(&be)
                })
                .collect::<Vec<_>>(),
        });
        {
            use std::io::Write as _;
            let _ = writeln!(f, "{line}");
        }
    }

    /// prove-hand flat 输入（hex 形态）：Span ABI `[len, elements…]` 摊平
    /// （与 combined / fold_batch / settlement_batch 同约定）——`[102] ++
    /// settle wire 102 词`，共 103 hex。HTTP prover 体与导出 JSON 同源。
    pub fn flat_inputs_hex(&self) -> Vec<String> {
        let wire = self.inputs_felts();
        let mut hexes: Vec<String> = Vec::with_capacity(1 + wire.len());
        hexes.push(format!("0x{:x}", Felt::from(wire.len() as u64)));
        hexes.extend(wire.iter().map(|f| format!("0x{f:x}")));
        hexes
    }

    /// prove-hand `--inputs` JSON（hex felt 数组，Span ABI 摊平形态）。
    pub fn inputs_json(&self) -> String {
        serde_json::to_string(&self.flat_inputs_hex()).expect("inputs json")
    }

    /// 本地推导赢家认领承诺（与合约公式一致：
    /// `cm = poseidon([commitment, hand_binding, amount_lo, amount_hi])`）。
    pub fn derive_claim_cms(&self) -> Vec<[u8; 32]> {
        let binding = wire_felt(&self.hand_binding).expect("canonical binding");
        (0..MAX_PARTICIPANTS)
            .map(|i| {
                if self.signs[i] == 1 && self.magnitudes[i] != 0 {
                    let commitment =
                        wire_felt(&self.commitments[i]).expect("canonical commitment");
                    starknet_crypto::poseidon_hash_many(&[
                        commitment,
                        binding,
                        Felt::from(self.magnitudes[i]),
                        Felt::ZERO,
                    ])
                    .to_bytes_be()
                } else {
                    [0u8; 32]
                }
            })
            .collect()
    }

    /// 期望公开段（felt 形态）：`[MAGIC, hand_id, digest, n, binding,
    /// cm_0..cm_8, total_winnings, action_log_digest]`（16 felt，9 人桌）——
    /// v2 合约入口的段长（SETTLEMENT_SEGMENT_LEN=16）与 combined 信封
    /// （前插 chain_acc 后 17 词）的基底。v2 合约托管金额 =
    /// total_winnings（电路内累加），尾词对注册的动作日志承诺
    /// 逐 felt 比对（#18 Phase B）。
    pub fn public_segment_felts(&self) -> Vec<Felt> {
        let mut segment = vec![
            prove_magic(),
            Felt::from(self.hand_id),
            wire_felt(&self.registered_digest).expect("canonical digest"),
            Felt::from(self.n_participants),
            wire_felt(&self.hand_binding).expect("canonical binding"),
        ];
        let mut total_winnings: u64 = 0;
        for (index, cm) in self.derive_claim_cms().iter().enumerate() {
            segment.push(wire_felt(cm).expect("canonical cm"));
            if self.signs[index] == 1 && self.magnitudes[index] != 0 {
                total_winnings = total_winnings.saturating_add(self.magnitudes[index]);
            }
        }
        segment.push(Felt::from(total_winnings));
        segment.push(
            wire_felt(&self.action_log_digest).expect("canonical action log digest"),
        );
        segment
    }

    /// 期望公开段（hex 形态，供公开段比对）。
    pub fn expected_public_segment(&self) -> Vec<String> {
        self.public_segment_felts()
            .iter()
            .map(|f| format!("0x{f:x}"))
            .collect()
    }

    /// fact-registry 锚：`fact = poseidon([circuit_program_hash ++ 公开段])`。
    /// 电路 program_hash 部署时钉入合约常量，prover 侧经
    /// `register_settlement_fact` 登记，`..._v2` 结算入口校验。
    /// 生产由真实电路证明的 prover 登记；dev 本地模式
    /// （`shadow::ProverMode::Local`）由 operator 直登
    /// （`dual_settle::local_register_settlement_fact`）。
    pub fn settlement_fact(&self, circuit_program_hash: [u8; 32]) -> Result<[u8; 32], String> {
        let ph = wire_felt(&circuit_program_hash)?;
        let mut fields = vec![ph];
        fields.extend(self.public_segment_felts());
        Ok(starknet_crypto::poseidon_hash_many(&fields).to_bytes_be())
    }
}

/// v2 单手电路（settlement_private.cairo）的 settle wire 词数（Span ABI，
/// 2026-09-30 重构 + 9 人桌迁移：`fn main(words: Span<felt252>)`，flat
/// 输入 = `[102] ++ wire`）。在发往该电路的调用点显式对长度：把「远端
/// 解析深处失配」提前为「近处可读错误」，不静默。
const V2_CIRCUIT_INPUT_WORDS: usize = 102;

/// 导出到 workload 目录（best-effort，绝不阻塞结算）：
/// `settlement-private-{hand_id}-{binding:x}.inputs.json`——Span ABI 摊平
/// 形态（`[102] ++ wire`），v2 prove-settlement 管线与 combined 语句同源
/// 可复用。
pub fn export_settlement_private_inputs(
    req: &SettlementPrivateRequest,
    dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let words = req.inputs_felts().len();
    if words != V2_CIRCUIT_INPUT_WORDS {
        tracing::warn!(
            "[settlement-private] inputs are {words} words but the v2 single-hand circuit \
             settle wire is {V2_CIRCUIT_INPUT_WORDS} — the exported file cannot be consumed \
             by the v2 prove pipeline"
        );
    }
    let path = dir.join(format!(
        "settlement-private-{}-{:x}.inputs.json",
        req.hand_id,
        wire_felt(&req.hand_binding).ok()?
    ));
    let result = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&path, req.inputs_json()));
    match result {
        Ok(()) => {
            tracing::info!("[settlement-private] circuit inputs exported: {}", path.display());
            Some(path)
        }
        Err(e) => {
            tracing::warn!("[settlement-private] inputs export failed (non-fatal): {e}");
            None
        }
    }
}

/// 从链上结算明文一步构建请求（ commitments 由 vault async 读取）。
pub async fn prepare_request(
    hand_id: u32,
    hand_binding: Felt,
    players: &[Felt],
    deltas_wei: &[i128],
    action_log_digest: Felt,
    action_entries: &[[Felt; 2]],
) -> Result<SettlementPrivateRequest, String> {
    let commitments = fetch_payout_commitments(players, deltas_wei).await?;
    build_request(
        hand_id,
        hand_binding,
        players,
        deltas_wei,
        &commitments,
        action_log_digest,
        action_entries,
    )
}

/// prover 服务返回的 attestation：digest 与 cms 已对照本地推导校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPrivateAttestation {
    pub program_hash: String,
}

/// `STARKNET_PROVER_URL` 客户端——指向 `proving-tool/scripts/prover_service.py`
/// （或任何实现了相同协议的服务）：POST
/// `{"circuit":"settlement_private","hand_id":..,"inputs":[hex..]}`，
/// 响应 `{"ok":true,"output":[hex..],"program_hash":"0x.."}`。
/// 公开段在本地重算校验：digest 必须等于请求的 registered_digest，
/// cms 必须等于本地推导——prover 无法用别的语句蒙混。
pub struct HttpSettlementProver {
    pub url: Option<String>,
}

impl HttpSettlementProver {
    pub fn new(url: Option<String>) -> Self {
        Self { url }
    }

    pub fn configured(&self) -> bool {
        self.url.as_deref().is_some_and(|u| !u.trim().is_empty())
    }

    pub async fn prove_settlement_private(
        &self,
        req: &SettlementPrivateRequest,
    ) -> Result<SettlementPrivateAttestation, String> {
        // 显式前置闸：v2 单手电路的 settle wire 固定 102 词（Span ABI，
        // [`V2_CIRCUIT_INPUT_WORDS`]）。失配只会在远端电路解析深处失败——
        // 在这里以可读错误拒绝，不静默。
        let words = req.inputs_felts().len();
        if words != V2_CIRCUIT_INPUT_WORDS {
            return Err(format!(
                "v2 single-hand circuit expects a {V2_CIRCUIT_INPUT_WORDS}-word settle wire \
                 (9-seat Span ABI), request has {words}"
            ));
        }
        let Some(url) = self.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
            return Err("settlement prover URL not configured".into());
        };
        let body = serde_json::json!({
            "circuit": "settlement_private",
            "hand_id": req.hand_id,
            "inputs": req.flat_inputs_hex(),
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(super::dual_settle::PROVER_ATTEST_TIMEOUT.as_secs() + 15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("prover unreachable: {e}"))?;
        let status = resp.status();
        let payload: serde_json::Value = resp.json().await.map_err(|e| format!("prover response: {e}"))?;
        if !status.is_success() || payload.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!(
                "prover rejected ({status}): {}",
                payload.get("error").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }
        let output = payload
            .get("output")
            .and_then(|v| v.as_array())
            .ok_or("prover response missing output")?;
        let segment = output
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        let magic = format!("0x{:x}", prove_magic());
        let start = segment
            .iter()
            .position(|w| *w == magic)
            .ok_or("prover public segment missing MAGIC")?;
        let want_len = 5 + MAX_PARTICIPANTS + 2; // MAGIC..binding + cms + total + action log
        if segment.len() < start + want_len {
            return Err("prover public segment too short".into());
        }
        let got = &segment[start..start + want_len];
        let expected = req.expected_public_segment();
        if got.len() < expected.len() || got[..expected.len()] != expected[..] {
            return Err(format!(
                "prover public segment mismatch: got {got:?}, expected {}",
                expected.join(",")
            ));
        }
        Ok(SettlementPrivateAttestation {
            program_hash: payload
                .get("program_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }
}

/// combined 信封的 P 层任务（hand-verify-native `RecurseTask` 的 texas 侧
/// wire 形态：跨 workspace 走 CLI 子进程缝，不链接其类型）。
#[derive(Debug, Clone)]
pub struct CombinedTask {
    pub hand_binding: Felt,
    pub payload: Vec<Felt>,
}

impl CombinedTask {
    /// 从动作签名材料构造 P 任务（生产产源：`recursion_prover::
    /// action_sig_materials` 的输出，与 snip36 递归信封同源）。payload 组装
    /// 借 hand-verify-native 库依赖（texas 已直连，见 recursion_prover::
    /// prove_batch_blocking 同用法）；宿主直验在 prove_combined_layer 内
    /// fail-closed。
    pub fn from_materials(
        table_id: u32,
        hand_id: u32,
        hand_binding: Felt,
        materials: &[super::recursion_prover::ActionSigMaterial],
    ) -> Result<Vec<CombinedTask>, String> {
        let statements: Vec<hand_verify_native::recurse::ActionSigStatement> = materials
            .iter()
            .map(|m| hand_verify_native::recurse::ActionSigStatement {
                pk_x_hex: m.pk_x_hex.clone(),
                pk_y_hex: m.pk_y_hex.clone(),
                r_x_hex: m.r_x_hex.clone(),
                r_y_hex: m.r_y_hex.clone(),
                s_hex: m.s_hex.clone(),
                table_id,
                hand_id,
                seq: m.seq,
                action: m.action.clone(),
                amount: m.amount,
            })
            .collect();
        let payload = hand_verify_native::recurse::build_action_batch_payload(
            hand_binding,
            table_id,
            hand_id,
            &statements,
        )?;
        Ok(vec![CombinedTask { hand_binding, payload }])
    }
}

/// combined 信封证明产出（hand-verify-native `combined --input` 的 stdout
/// 契约解析结果）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedProofOutput {
    /// 折叠链新累计承诺（= public_output[0]）。
    pub cairo_acc: Felt,
    /// 17 词公开输出 `[chain_acc] ++ v2 公开段(16)`——combined 合约入口的
    /// segment 参数原样。
    pub public_output: [Felt; 17],
    /// 出证 Cairo 程序哈希（prove-hand 报告值）。
    pub program_hash: Felt,
    pub steps: u64,
    pub total_ms: u64,
    pub out_dir: String,
}

impl CombinedProofOutput {
    /// combined fact-registry 锚：`fact = poseidon([combined_program_hash ‖
    /// 整段 17 词])`——与合约 `fact_for_segment(combined_program_hash,
    /// segment)`（poker_dual_settlement.cairo:302）及 v2 版
    /// [`SettlementPrivateRequest::settlement_fact`] 同式（段长 17、首词
    /// chain_acc）。
    pub fn settlement_fact(&self, combined_program_hash: Felt) -> [u8; 32] {
        let mut fields = Vec::with_capacity(1 + 17);
        fields.push(combined_program_hash);
        fields.extend(self.public_output);
        starknet_crypto::poseidon_hash_many(&fields).to_bytes_be()
    }
}

/// hand-verify-native 可执行发现：显式路径 > 仓根 target（根 workspace
/// 成员构建位）> poker_contracts 内嵌 workspace 遗留位。仓根从 cwd 与
/// 当前可执行目录向上找（目录含 `poker_contracts/` 子目录即仓根）。
/// 找不到返回 None（调用方报错回退，不阻塞结算）。
pub fn discover_combined_native_bin(explicit: &str) -> Option<std::path::PathBuf> {
    const BIN: &str = "hand-verify-native";
    let trimmed = explicit.trim();
    if !trimmed.is_empty() {
        let p = std::path::PathBuf::from(trimmed);
        return p.is_file().then_some(p);
    }
    let mut roots: Vec<std::path::PathBuf> = vec![];
    if let Ok(cwd) = std::env::current_dir() {
        roots.extend(cwd.ancestors().map(|a| a.to_path_buf()));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            roots.extend(dir.ancestors().map(|a| a.to_path_buf()));
        }
    }
    for root in roots {
        if !root.join("poker_contracts").is_dir() {
            continue;
        }
        for cand in [
            root.join("target/release").join(BIN),
            root.join("poker_contracts/hand-verify-native/target/release").join(BIN),
        ] {
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

/// combined 证明子进程超时（Cairo 编译 + 运行 + 证明 + check-only 复验，
/// 实测量级 30-60 s；留 10× 余量——超时即回退，绝不卡死结算）。
const COMBINED_PROVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

impl HttpSettlementProver {
    /// combined 信封出证：spawn hand-verify-native CLI（`combined --input`），
    /// 输入 JSON 写临时文件、解析 stdout 单行 JSON（跨 workspace 子进程缝，
    /// wire 契约见 hand-verify-native src/main.rs `combined_cmd` 文档）。
    ///
    /// settle 语句由 [`SettlementPrivateRequest`]（本地重算 digest 的同一
    /// 真源）序列化；任务由调用方给（生产产源
    /// [`CombinedTask::from_materials`]）。证明内部的 acc/segment 双 parity
    /// 门由 prove_combined_layer 强制（CLI 侧），此处只解析结果。
    pub async fn prove_combined(
        &self,
        tasks: &[CombinedTask],
        settle: &SettlementPrivateRequest,
        prev_acc: Felt,
        out_dir: &std::path::Path,
        native_bin: &str,
    ) -> Result<CombinedProofOutput, String> {
        let bin = discover_combined_native_bin(native_bin).ok_or_else(|| {
            format!(
                "hand-verify-native binary not found (set STARKNET_COMBINED_NATIVE_BIN or \
                 build: cargo build --release -p hand-verify-native)"
            )
        })?;
        std::fs::create_dir_all(out_dir).map_err(|e| format!("combined out_dir: {e}"))?;

        // 输入 JSON（felt 一律 hex；形状 = CLI combined_cmd 文档）。
        let felt_hex = |f: &Felt| format!("0x{f:x}");
        let mut players = Vec::with_capacity(MAX_PARTICIPANTS);
        for p in &settle.players {
            players.push(felt_hex(&wire_felt(p).map_err(|e| format!("players: {e}"))?));
        }
        let mut commitments = Vec::with_capacity(MAX_PARTICIPANTS);
        for c in &settle.commitments {
            commitments.push(felt_hex(&wire_felt(c).map_err(|e| format!("commitments: {e}"))?));
        }
        let mut action_entries: Vec<[String; 2]> = Vec::with_capacity(settle.action_entries.len() / 2);
        for pair in settle.action_entries.chunks(2) {
            action_entries.push([
                felt_hex(&wire_felt(&pair[0]).map_err(|e| format!("action entry: {e}"))?),
                felt_hex(&wire_felt(&pair[1]).map_err(|e| format!("action entry: {e}"))?),
            ]);
        }
        let tasks_json: Vec<serde_json::Value> = tasks
            .iter()
            .map(|t| {
                serde_json::json!({
                    "hand_binding": felt_hex(&t.hand_binding),
                    "payload": t.payload.iter().map(felt_hex).collect::<Vec<_>>(),
                })
            })
            .collect();
        let input = serde_json::json!({
            "prev_acc": felt_hex(&prev_acc),
            "out_dir": out_dir.display().to_string(),
            "params_path": serde_json::Value::Null,
            "settle": {
                "hand_id": u64::from(settle.hand_id),
                "registered_digest": felt_hex(&wire_felt(&settle.registered_digest)
                    .map_err(|e| format!("registered_digest: {e}"))?),
                "n_expected": u64::from(settle.n_participants),
                "hand_binding": felt_hex(&wire_felt(&settle.hand_binding)
                    .map_err(|e| format!("hand_binding: {e}"))?),
                "players": players,
                "signs": settle.signs.map(u64::from),
                "magnitudes": settle.magnitudes,
                "commitments": commitments,
                "action_log_digest": felt_hex(&wire_felt(&settle.action_log_digest)
                    .map_err(|e| format!("action_log_digest: {e}"))?),
                "action_entries": action_entries,
            },
            "tasks": tasks_json,
        });
        let input_path = out_dir.join("combined-cli-input.json");
        std::fs::write(&input_path, serde_json::to_string(&input).map_err(|e| e.to_string())?)
            .map_err(|e| format!("write combined input: {e}"))?;

        // spawn（跨 workspace 子进程缝：不链接 combined 证明器本体）。
        let run = tokio::process::Command::new(&bin)
            .arg("combined")
            .arg("--input")
            .arg(&input_path)
            .output();
        let output = tokio::time::timeout(COMBINED_PROVE_TIMEOUT, run)
            .await
            .map_err(|_| "combined prove timed out".to_string())?
            .map_err(|e| format!("spawn hand-verify-native: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() {
            let err = serde_json::from_str::<serde_json::Value>(&stdout)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
                .unwrap_or_else(|| {
                    format!(
                        "exit {:?}: {}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr).trim()
                    )
                });
            return Err(format!("combined prove failed: {err}"));
        }
        let parsed: serde_json::Value =
            serde_json::from_str(&stdout).map_err(|e| format!("combined stdout JSON: {e}"))?;
        if parsed.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!(
                "combined prove rejected: {}",
                parsed.get("error").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }
        let parse_felt = |v: &serde_json::Value, ctx: &str| -> Result<Felt, String> {
            let s = v.as_str().ok_or_else(|| format!("{ctx}: expected hex string"))?;
            Felt::from_hex(s.trim_start_matches("0x")).map_err(|e| format!("{ctx}: {e:?}"))
        };
        let public: Vec<Felt> = parsed
            .get("public_output")
            .and_then(|v| v.as_array())
            .ok_or("combined stdout missing public_output")?
            .iter()
            .enumerate()
            .map(|(i, w)| parse_felt(w, &format!("public_output[{i}]")))
            .collect::<Result<_, _>>()?;
        let public_output: [Felt; 17] = public
            .try_into()
            .map_err(|v: Vec<Felt>| format!("public_output len {} != 17", v.len()))?;
        if public_output[1] != prove_magic() {
            return Err("combined public_output[1] != MAGIC (wire drift)".into());
        }
        let cairo_acc = parse_felt(
            parsed.get("cairo_acc").ok_or("combined stdout missing cairo_acc")?,
            "cairo_acc",
        )?;
        if cairo_acc != public_output[0] {
            return Err("combined cairo_acc != public_output[0]".into());
        }
        Ok(CombinedProofOutput {
            cairo_acc,
            public_output,
            program_hash: parse_felt(
                parsed.get("program_hash").ok_or("combined stdout missing program_hash")?,
                "program_hash",
            )?,
            steps: parsed.get("steps").and_then(|v| v.as_u64()).unwrap_or(0),
            total_ms: parsed.get("total_ms").and_then(|v| v.as_u64()).unwrap_or(0),
            out_dir: parsed
                .get("out_dir")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_felt(seed: u8) -> Felt {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        Felt::from_bytes_be(&bytes)
    }

    fn sample_felt_bytes(seed: u8) -> [u8; 32] {
        sample_felt(seed).to_bytes_be()
    }

    fn sample_entries() -> Vec<[Felt; 2]> {
        vec![[sample_felt(0xB1), Felt::ZERO], [sample_felt(0xB2), sample_felt(0xB3)]]
    }

    fn sample_request() -> SettlementPrivateRequest {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let deltas = [3_000_i128, -2_000, -1_000, 0, 0, 0, 0, 0, 0]; // chips 口径做单测（9 槽）
        let mut commitments = [[0u8; 32]; MAX_PARTICIPANTS];
        commitments[0] = sample_felt_bytes(0x21);
        build_request(
            42,
            sample_felt(0xAA),
            &players,
            &deltas,
            &commitments,
            sample_felt(0xA7),
            &sample_entries(),
        )
        .expect("request")
    }

    #[test]
    fn inputs_match_cairo_signature_order() {
        let req = sample_request();
        let felts = req.inputs_felts();
        // 41 标量 + 1 计数 + 30×2 词条槽 = 102（9 席 settle wire，与
        // settlement_stmt.cairo / settlement_private.cairo Span wire 逐槽一致；
        // 发往 v2 电路的调用点有显式长度闸）。
        assert_eq!(felts.len(), 42 + 60);
        assert_eq!(felts[0], Felt::from(42u32), "hand_id first");
        assert_eq!(felts[1], Felt::from_bytes_be(&req.registered_digest));
        assert_eq!(felts[2], Felt::from(3u32), "n_participants");
        assert_eq!(felts[3], Felt::from_bytes_be(&req.hand_binding));
        assert_eq!(felts[4], sample_felt(1), "p0");
        // signs 组在 players 组（9 个）之后
        assert_eq!(felts[13], Felt::from(1u64), "s0");
        assert_eq!(felts[14], Felt::from(0u64), "s1（负数 → 0）");
        // mags 组
        assert_eq!(felts[22], Felt::from(3_000u64), "m0");
        // commitments 组
        assert_eq!(felts[31], sample_felt(0x21), "c0");
        // 第 41 入参 = 动作日志哈希（#18 Phase B）
        assert_eq!(felts[40], sample_felt(0xA7), "action log digest last");
        // 词条区：count=2 + 槽 0 = [日志, 0]（非 auto）+ 槽 1 = [日志, 合法性]。
        assert_eq!(felts[41], Felt::from(2u64), "action count");
        assert_eq!(felts[42], sample_felt(0xB1), "entry0 log");
        assert_eq!(felts[43], Felt::ZERO, "entry0 legality (non-auto)");
        assert_eq!(felts[44], sample_felt(0xB2), "entry1 log");
        assert_eq!(felts[45], sample_felt(0xB3), "entry1 legality");
        assert_eq!(felts[46], Felt::ZERO, "padding slot starts");
        assert_eq!(felts[41 + 60], Felt::ZERO, "last padding slot");
    }

    #[test]
    fn digest_is_stable_and_binds_players_and_deltas() {
        let req = sample_request();
        let again = sample_request();
        assert_eq!(req.registered_digest, again.registered_digest);
        // 改动任一输入必须改变 digest（digest 绑定整份语句）
        let mut tampered_players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        tampered_players[0] = sample_felt(9);
        let tampered = build_request(
            42,
            sample_felt(0xAA),
            &tampered_players,
            &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0, 0],
            &req.commitments,
            sample_felt(0xA7),
            &sample_entries(),
        )
        .expect("tampered request still buildable");
        assert_ne!(req.registered_digest, tampered.registered_digest);
        // 动作日志哈希（吸收链尾词）改动必须改变 digest（#18 Phase B 绑定）。
        let other_log = build_request(
            42,
            sample_felt(0xAA),
            &[sample_felt(1), sample_felt(2), sample_felt(3)],
            &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0, 0],
            &req.commitments,
            sample_felt(0xA8),
            &sample_entries(),
        )
        .expect("other log request buildable");
        assert_ne!(req.registered_digest, other_log.registered_digest);
    }

    #[test]
    fn zero_sum_violation_rejected() {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let err = build_request(42, sample_felt(0xAA), &players, &[3_001, -2_000, -1_000, 0, 0, 0, 0, 0, 0], &[[0u8; 32]; MAX_PARTICIPANTS], sample_felt(0xA7), &sample_entries())
            .err()
            .expect("non-zero-sum must be rejected");
        assert!(err.contains("zero-sum"));
    }

    #[test]
    fn winner_without_commitment_rejected() {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let err = build_request(42, sample_felt(0xAA), &players, &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0, 0], &[[0u8; 32]; MAX_PARTICIPANTS], sample_felt(0xA7), &sample_entries())
            .err()
            .expect("winner without commitment must be rejected");
        assert!(err.contains("payout commitment"));
    }

    #[test]
    fn expected_segment_shape() {
        let req = sample_request();
        let segment = req.expected_public_segment();
        assert_eq!(segment.len(), 7 + MAX_PARTICIPANTS);
        assert!(segment[0].starts_with("0x5350324d5f4f4b"), "MAGIC='SP2M_OK'");
        assert_eq!(segment[1], "0x2a", "hand_id=42");
        assert_eq!(segment[3], "0x3", "n_participants");
        // 非赢家 cm 全零（cm×9：槽 5..14，赢家 0 → 6..14 全零）
        for cm in &segment[6..14] {
            assert_eq!(cm, "0x0");
        }
        // 赢家 cm 与合约公式一致
        let binding = sample_felt(0xAA);
        let commitment = sample_felt(0x21);
        let expected_cm = starknet_crypto::poseidon_hash_many(&[
            commitment,
            binding,
            Felt::from(3_000u64),
            Felt::ZERO,
        ]);
        assert_eq!(segment[5], format!("0x{expected_cm:x}"));
        // total_winnings = Σ 赢家 |delta|（chips 口径样例 = 3000）
        assert_eq!(segment[14], format!("0x{:x}", Felt::from(3_000u64)));
        // #18 Phase B：尾词 = 动作日志哈希
        assert_eq!(segment[15], format!("0x{:x}", sample_felt(0xA7)));
    }

    #[test]
    fn settlement_fact_binds_program_hash_and_segment() {
        let req = sample_request();
        let fact_a = req.settlement_fact(sample_felt_bytes(1)).expect("fact");
        let fact_b = req.settlement_fact(sample_felt_bytes(1)).expect("fact");
        let fact_c = req.settlement_fact(sample_felt_bytes(2)).expect("fact");
        assert_eq!(fact_a, fact_b, "同语句同 program hash → 同 fact");
        assert_ne!(fact_a, fact_c, "program hash 不同 → fact 不同");
        let mut tampered = sample_request();
        tampered.registered_digest[31] ^= 1;
        assert_ne!(
            fact_a,
            tampered.settlement_fact(sample_felt_bytes(1)).expect("fact"),
            "语句任何字段变化 → fact 不同"
        );
    }

    #[test]
    fn inputs_json_is_hex_array() {
        let req = sample_request();
        let parsed: Vec<String> = serde_json::from_str(&req.inputs_json()).expect("json");
        // Span ABI 摊平：[102] ++ settle wire 102 词。
        assert_eq!(parsed.len(), 1 + 42 + 60);
        assert_eq!(parsed[0], "0x66", "Span 长度前缀 = 102");
        assert!(parsed.iter().all(|h| h.starts_with("0x")));
        assert_eq!(parsed[1], "0x2a", "flat[1] = wire[0] = hand_id");
        assert_eq!(
            parsed[2],
            format!("0x{:x}", Felt::from_bytes_be(&req.registered_digest)),
            "flat[2] = wire[1] = registered_digest"
        );
    }

    /// combined fact 参考测试：`fact = poseidon([combined_program_hash ‖
    /// 整段 17 词])` 必须与合约 `fact_for_segment`（poker_dual_settlement.
    /// cairo:302，PoseidonTrait 逐词 update）同式——用
    /// starknet_crypto::poseidon_hash_many 独立重算钉死，并断言链首词
    /// chain_acc 进 fact（改 acc 必改 fact）。
    #[test]
    fn combined_settlement_fact_matches_contract_formula() {
        let mut public = [Felt::ZERO; 17];
        public[0] = sample_felt(0x11); // chain_acc
        public[1] = prove_magic(); // MAGIC 'SP2M_OK'
        for w in public.iter_mut().skip(2) {
            *w = sample_felt(0x40);
        }
        let out = CombinedProofOutput {
            cairo_acc: public[0],
            public_output: public,
            program_hash: sample_felt(0x77),
            steps: 0,
            total_ms: 0,
            out_dir: String::new(),
        };
        let ph = sample_felt(0x5A);
        let fact = Felt::from_bytes_be(&out.settlement_fact(ph));
        // 独立重算（同 v2 版 settlement_fact 的对拍写法）。
        let mut fields = vec![ph];
        fields.extend(public);
        assert_eq!(
            fact,
            starknet_crypto::poseidon_hash_many(&fields),
            "combined fact 必须与 poseidon_hash_many([ph ‖ segment17]) 逐词同式"
        );
        // 确定性与绑定：同 ph 同 fact；换 ph / 改 chain_acc 首词 → fact 变。
        assert_eq!(
            fact.to_bytes_be(),
            out.settlement_fact(ph),
            "同语句同 program hash → 同 fact"
        );
        assert_ne!(fact.to_bytes_be(), out.settlement_fact(sample_felt(0x5B)));
        let mut tampered = out.clone();
        tampered.public_output[0] += Felt::ONE;
        assert_ne!(
            fact.to_bytes_be(),
            tampered.settlement_fact(ph),
            "chain_acc 是 fact 预映像首词（改 acc 必改 fact）"
        );
    }

    /// CLI stdout 契约解析的负例面（不 spawn 子进程，只钉 wire 形状断言）：
    /// 17 词 + MAGIC 锚 + cairo_acc == public_output[0]。
    #[test]
    fn combined_output_shape_invariants() {
        let req = sample_request();
        // 请求侧不产出 combined 输出；这里仅钉住 v2 段（16 词）与 combined
        // 段（17 词）的前缀关系：combined[1..17] == v2 segment。
        let v2 = req.public_segment_felts();
        assert_eq!(v2.len(), 16);
        let mut combined = [Felt::ZERO; 17];
        combined[0] = Felt::from(0xACCu64);
        combined[1..17].copy_from_slice(&v2);
        assert_eq!(combined[1], prove_magic());
        assert_eq!(combined[16], Felt::from_bytes_be(&req.action_log_digest));
    }
}


#[cfg(test)]
mod selector_probe {
    #[test]
    fn print_action_selectors() {
        let names = ["transfer", "approve", "balance_of", "allowance", "mint",
            "withdraw_to", "token", "chip_to_note", "shieldable_balance", "vault", "pool",
            "set_unshield_helper", "unshield_helper", "set_authorized_helper"];
        for n in names {
            println!("SEL {} = {:x}", n, starknet::core::utils::starknet_keccak(n.as_bytes()));
        }
    }
}
