//! Hand-batch（Dual-layer Attested Proof Verification，双层证明结算）+ G 层
//! 链上结算（`PokerDualSettlement`）。
//!
//! 术语说明：Hand-batch 是本项目内部命名，指"两层证明的结算验证"——
//! **P 层**（Player 侧：每座位 hand-bound Schnorr 认可，链上 ρ 折叠）
//! + **G 层**（Game 侧：canonical STARK 聚合摘要注册）。对外表述
//! 建议使用标准描述："ρ-folded Schnorr ownership endorsement batch
//! + host-verified STARK attestation"。
//!
//! 完整设计文档：`{docs/design/DUAL_PROOF_PROTOCOL.md,
//! docs/SOUNDNESS.md}`（v2.8；含 hand_batch.cairo 的 Cairo 侧规范）。
//! 概要：
//! - **P 层**：每座位一条 hand-bound secp256k1 Schnorr 认可（ownership
//!   endorsement），全部残差方程在链上以 ρ 折叠成单点校验
//!   `L = Σ ρⁱ·Lᵢ == O`（`dual/hand_batch.cairo`；secp256k1 点经 OS 级
//!   secp mul syscall / corelib 验证，非 EC_OP builtin——后者仅限
//!   STARK 曲线）；
//! - **G 层**：Phase 1 = host 验证的 canonical STARK（orchestrator 的
//!   verified outer aggregate），其摘要经 `register_hand` 注册
//!   （`g_attestation`），公开输入承诺统一进 `hand_binding`。
//!
//! 绑定链（防跨手/跨层拼装）：
//! 1. `hand_binding` = Poseidon(table_id, hand_id, players, deck 承诺,
//!    reveal 承诺, state roots, settlement_digest)——注册后单次使用；
//! 2. Hand-batch 批次的 transcript 域与 ρ 都从 `hand_binding` 字节派生
//!   （链上 `bytes_to_felt(hand_id_bytes) == hand_binding` 强校验），
//!   且 ownership 挑战前置该域（§9-L2）：他手铸造的认可在本手折叠必
//!   非零；
//! 3. `settlement_digest` 在链上按 (hand_id, players, deltas) 重算并与
//!   注册值精确比对——证明无法为别的支付方案背书。
//!
//! 本运行时的现实边界（如实记录）：
//! - 游戏协议本体（poker_l1 镜像）运行在 BLS12-381 上，其洗牌/reveal
//!   语句是 BLS 点。链上 EC 支持分三档：EC_OP builtin 仅限 STARK 曲线
//!   （原生，最便宜）；secp256k1/r1 经 OS 级 mul syscall（中档）；BLS12-381
//!   无原生支持（需 Garaga 纯 Cairo 模拟，最贵）——所以 BLS 点的
//!   reveal/fold 残差暂不能进本手批次（载荷格式已支持）。
//!   迁移目标见 docs/design/DUAL_PROOF_PROTOCOL.md v2.9（Plan D）：协议本体迁 STARK
//!   曲线（EC_OP 原生，是全残差批次唯一可负担的路线）；secp256k1 保留
//!   为 EVM ecrecover 互操作备选。当前批次仍承载每座位的 hand-bound
//!   所有权认可（secp256k1）。
//! - 2026-09-06：客户端认可提交通道（ENDORSEMENT_SUBMIT/registry）已删除——
//!   ownership 认可改由**动作签名**承担（游戏 SK，`zgame.action-sig.v2`
//!   域含 hand_id，开局即随动作铸造）；批次/折叠机器保留待重接。

use poker_protocol_core::{Curve, CurvePoint, CurveScalar, StarkCurve};
use starknet::accounts::Account;
use starknet::core::types::{Call, Felt};
use starknet::core::utils::starknet_keccak;

use poker_texas_air::hand_binding::{HandBindingInput, compute_hand_binding};
use poker_texas_air::starknet_settlement::AggregateDigestFelts;

use super::config::SettleMode;
use super::submit::{HandSettlement, i128_to_felt};
use super::vm_session::VmTable;

pub type Sc = <StarkCurve as Curve>::Scalar;
pub type Pt = <StarkCurve as Curve>::Point;

/// 取（首次则生成并托管）钱包的 secp256k1 认可密钥对。
///
/// hand_batch 的域分离标签与认可工件（P2.1 后服务器不持有任何认可
/// 私钥；`mint_endorsement`/`Endorsement` 仅存于测试与向量生成，生产
/// 铸造在客户端 client-wasm `endorsement_mint`，公式逐字节一致）。

/// hand_batch.cairo 的域分离标签（逐字节对齐，勿改）。

/// 一条 hand-bound 所有权认可：pk = sk·G，s = w + c·sk，
/// c = H(domain ‖ G ‖ pk ‖ R)，R = w·G。
#[derive(Debug, Clone)]
pub struct Endorsement {
    pub pk: Pt,
    pub r: Pt,
    pub s: Sc,
}

/// 铸造 hand-bound 认可。
///
/// 生产用途限定：仅供**服务器自己托管的测试玩家（dev_bot）**在进程内铸造——
/// 真实客户端的认可私钥保持在浏览器（client-wasm `endorsement_mint`），
/// 服务器不持有、也无法调用此函数代铸。
pub fn mint_endorsement(sk: &Sc, pk: &Pt, hand_binding: &[u8; 32]) -> Endorsement {
    let mut rng = rand::rngs::OsRng;
    let g = StarkCurve::base_g();
    loop {
        let w = <Sc as CurveScalar>::random(&mut rng);
        if w == <Sc as CurveScalar>::zero() {
            continue;
        }
        let r = g * w;
        if r.is_identity() {
            continue;
        }
        // gas 压缩版挑战：felt 直通 Poseidon（core 规范实现，与 Cairo/wasm
        // 复刻同式；取代 keccak 域 + 32B 压缩编码的字节流形态）。
        let c = poker_protocol_core::stark_curve::handbatch_endorsement_challenge(
            hand_binding,
            &g,
            pk,
            &r,
        );
        return Endorsement {
            pk: *pk,
            r,
            s: w + c * *sk,
        };
    }
}

/// 仿射 (x, y) 各 32 字节大端（payload 字布局）。STARK 曲线坐标即
/// felt252，字直通 Cairo 合约，无 u256↔felt 换算。
pub fn point_xy(p: &Pt) -> ([u8; 32], [u8; 32]) {
    // audit M2：恒等点不再 panic（panic 会杀死 game_loop task 冻结牌桌），
    // 改为全零坐标——下游 Cairo EC 验证会自然拒绝该批认可（交易 revert，
    // 走既有有界重试/放弃路径），服务端日志可观测。
    match p.to_affine_parts() {
        Some((x, y)) => (x.to_bytes_be(), y.to_bytes_be()),
        None => {
            tracing::error!(
                "point_xy: identity point encoded as zero words (will be rejected downstream)"
            );
            ([0u8; 32], [0u8; 32])
        }
    }
}

fn scalar_be(s: &Sc) -> [u8; 32] {
    let v = <Sc as CurveScalar>::as_bytes(s);
    v.as_slice().try_into().expect("32-byte scalar")
}

/// Hand-batch 一次结算的全部工件。
pub struct DualSettlement {
    pub hand_binding: Felt,
    /// G（外部聚合）+ 状态根的 Poseidon 承诺——已逐字嵌入
    /// register_calldata（合约 register_hand 第 3 参）；字段本体仅测试
    /// 对拍断言读（生产走 calldata），保留为对拍锚。
    #[allow(dead_code)]
    pub g_attestation: Felt,
    pub hand_id: u32,
    /// 本手动作日志哈希（#18 Phase B）——v2 电路第 37 入参 / 公开段尾词。
    pub action_log_digest: Felt,
    /// 本手动作日志词条对（每条 2 felt：[日志词, 合法性词]，切片 2）。
    pub action_entries: Vec<[Felt; 2]>,
    /// hand_batch 载荷（u256 字，大端 32 字节表示）。
    pub batch_words: Vec<[u8; 32]>,
    /// Linear（默认）路径 calldata：`register_hand`（含 3 个零的期望
    /// 桶计数尾部）+ `verify_and_settle_dapv`（p_batch 全文上链）。
    /// 永远构建——也是 proved 模式回退的目标。
    pub register_calldata: Vec<Felt>,
    pub settle_calldata: Vec<Felt>,
    /// Proved 路径工件（总是构建，成本仅一次 Poseidon + 两个 Vec；
    /// 是否使用由 `STARKNET_SETTLE_MODE` 在提交时决定）。
    pub proved: ProvedSettlement,
}

/// Proved 模式的上链工件：p_batch 不进 calldata，settle 只携带承诺。
#[derive(Debug, Clone)]
pub struct ProvedSettlement {
    /// `poseidon(hand_binding, poseidon(p_batch words))`——注册与结算
    /// 两侧都必须精确等于该值，把 attested batch 绑定到注册的那一个。
    pub p_batch_commitment: Felt,
    /// p_batch 词数（与承诺一起注册/比对）。
    pub p_batch_len: usize,
    /// `register_hand_proved` calldata：
    /// [hand_binding, settlement_digest, g_attestation, action_log_digest,
    ///  commitment, batch_len, exp_reveal, exp_leave, exp_recon]（期望计数
    /// 暂为零 = 链上不约束，由 prover 线下校验）。
    pub register_calldata: Vec<Felt>,
    /// `verify_and_settle_dapv_proved` calldata：
    /// [hand_binding, 32, hand_id_bytes…, hand_id, action_log, n, players…, n,
    /// deltas…, commitment, batch_len]——无 p_batch。proved 路径预留
    ///（当前 prover 存根必失败回退 linear，提交期才填充；生产未读）。
    #[allow(dead_code)]
    pub settle_calldata: Vec<Felt>,
}

/// 递给外部 prover 的 workload（也是 JSON 导出文件的 schema）。
///
/// 远端模式（`HttpBatchProver`）下字段只写不读（存根必然报错 → 回退
/// linear）；本地模式（`LocalBatchProver`，`shadow::ProverMode::Local`）
/// 会读取全部字段做进程内校验并出具 attestation。
#[derive(Debug, Clone)]
pub struct ProverWorkload {
    pub hand_binding: Felt,
    /// wire/export schema 字段（workload JSON 消费方使用；attestation
    /// 本身只绑定 hand_binding + 批次词，本地 prover 不读）。
    #[allow(dead_code)]
    pub hand_id: u32,
    pub batch_words: Vec<[u8; 32]>,
    pub p_batch_commitment: Felt,
}

/// 外部 prover 对 workload 的 attestation。
#[derive(Debug, Clone)]
pub struct ProverAttestation {
    /// prover 实际验证过的承诺——必须与 workload 的承诺逐字节相等
    /// 才接受（否则视为 prover 故障，回退 linear）。
    pub p_batch_commitment: Felt,
}

/// `p_batch_commitment = poseidon(hand_binding, poseidon(p_batch words))`。
///
/// 每个载荷词是 STARK 曲线坐标/标量（< 域模），32 字节大端可直接作
/// felt 进 Poseidon；任何超域词直接报错（这类批次本就无法以 felt 形态
/// 上链，线性路径同样会拒）。
pub fn compute_p_batch_commitment(
    hand_binding: Felt,
    batch_words: &[[u8; 32]],
) -> Result<Felt, String> {
    let mut inner: Vec<Felt> = Vec::with_capacity(batch_words.len());
    for w in batch_words {
        // types-core from_bytes_be 无失败路径（≥ P 静默归约），沿用原
        // Result 语义：非 canonical 载荷词 fail-loud。
        let felt = Felt::from_bytes_be(w);
        if felt.to_bytes_be() != *w {
            return Err("dapv: batch word not in felt252 range".to_string());
        }
        inner.push(felt);
    }
    Ok(starknet_crypto::poseidon_hash_many(&[
        hand_binding,
        starknet_crypto::poseidon_hash_many(&inner),
    ]))
}

/// 外部 batch-prover 客户端 seam：服务器**绝不**进程内跑 prover——只把
/// workload 提交给 `STARKNET_PROVER_URL` 指向的服务并接收 attestation。
/// 在独立 prover 工具（STARK fact-registry / SNIP-36 verifier 落地前的
/// 临时形态）存在之前，唯一实现 [`HttpBatchProver`] 是必然报错的存根：
/// proved 模式因此总是回退 linear（保持暗跑可观测：workload JSON 仍导出）。
pub trait BatchProver: Send + Sync {
    /// 返回 prover 对该 workload 的 attestation；**任何**错误都由调用
    /// 方视为"回退 linear"。
    fn request_attestation<'a>(
        &'a self,
        workload: &'a ProverWorkload,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
    >;
}

/// prover attestation 等待上限：超时即回退 linear（结算绝不因 prover
/// 阻塞超过 30s）。
pub const PROVER_ATTEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `STARKNET_PROVER_URL` 的 HTTP prover 客户端——**存根**。
///
/// 真实客户端（提交 workload → 轮询/等待 → 拿回 attestation）在独立
/// prover CLI/服务存在后实现；当前无条件报错，使 proved 模式确定性地
/// 回退 linear。没有真实端点被请求。
pub struct HttpBatchProver {
    pub url: Option<String>,
}

impl HttpBatchProver {
    pub fn new(url: Option<String>) -> Self {
        Self { url }
    }
}

impl BatchProver for HttpBatchProver {
    fn request_attestation<'a>(
        &'a self,
        _workload: &'a ProverWorkload,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
    > {
        let url = self.url.clone();
        Box::pin(async move {
            Err(format!(
                "batch prover client not implemented (STARKNET_PROVER_URL={url:?}) — \
                 proved mode stays dark until the standalone prover tool exists"
            ))
        })
    }
}

/// dev 本地 batch prover（`shadow::ProverMode::Local`）：进程内出具
/// attestation，无需外部 prover 服务。校验两道门，任一失败即回退 linear：
/// 1. 批次可解析且 host ρ-fold 折叠到单位点（与 Cairo 端
///    `verify_hand_batch_stark` 同构——本地做的是真验证，不是放行）；
/// 2. `p_batch_commitment` 从 workload 自身批次词重算一致。
///
/// 仅限 dev：生产的 proved 结算必须由外部 prover 出具真实 STARK 证明
/// （`HttpBatchProver`）。
pub struct LocalBatchProver;

impl BatchProver for LocalBatchProver {
    fn request_attestation<'a>(
        &'a self,
        workload: &'a ProverWorkload,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let hb = workload.hand_binding.to_bytes_be();
            let equations = parse_batch_terms(&hb, &workload.batch_words)
                .ok_or_else(|| "local prover: batch payload unparsable".to_string())?;
            if !host_fold_check(&hb, &equations) {
                return Err("local prover: host rho-fold check failed".into());
            }
            let recomputed =
                compute_p_batch_commitment(workload.hand_binding, &workload.batch_words)?;
            if recomputed != workload.p_batch_commitment {
                return Err(format!(
                    "local prover: commitment mismatch (recomputed {recomputed:#x} != workload {:#x})",
                    workload.p_batch_commitment
                ));
            }
            Ok(ProverAttestation {
                p_batch_commitment: recomputed,
            })
        })
    }
}

/// proved 模式下把 workload 导出到 `<dir>/hand-{hand_id}-{binding:#x}.json`
/// （best-effort：目录创建/写入失败只告警，绝不阻塞结算）。这是未来
/// 独立 prover CLI 消费的文件，也让 proved 模式在暗跑期可观测/可 dry-run。
pub fn export_prover_workload(
    dual: &DualSettlement,
    dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let path = dir.join(format!(
        "hand-{}-{:#x}.json",
        dual.hand_id, dual.hand_binding
    ));
    let doc = serde_json::json!({
        "hand_binding": format!("{:#x}", dual.hand_binding),
        "hand_id": dual.hand_id,
        "batch_words": dual.batch_words.iter()
            .map(|w| hex::encode(w))
            .collect::<Vec<_>>(),
        "p_batch_commitment": format!("{:#x}", dual.proved.p_batch_commitment),
        "p_batch_len": dual.proved.p_batch_len,
    });
    let result = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap_or_default()));
    match result {
        Ok(()) => {
            tracing::info!(
                "[dapv-proved] workload exported: {} ({} words, commitment {:#x})",
                path.display(),
                dual.proved.p_batch_len,
                dual.proved.p_batch_commitment
            );
            Some(path)
        }
        Err(e) => {
            tracing::warn!("[dapv-proved] workload export failed (non-fatal): {e}");
            None
        }
    }
}

/// proved 模式的提交决策：尝试 prover attestation，**任何**错误/超时/
/// 承诺不匹配都回退 [`SettleMode::Linear`]。结算绝不因 prover 阻塞。
pub async fn resolve_settle_mode_with_prover(
    prover: &dyn BatchProver,
    workload: &ProverWorkload,
) -> SettleMode {
    match tokio::time::timeout(PROVER_ATTEST_TIMEOUT, prover.request_attestation(workload)).await {
        Ok(Ok(att)) if att.p_batch_commitment == workload.p_batch_commitment => SettleMode::Proved,
        Ok(Ok(att)) => {
            tracing::warn!(
                "[dapv-proved] prover attestation commitment mismatch (att {:#x} != workload {:#x}) — falling back to linear",
                att.p_batch_commitment,
                workload.p_batch_commitment
            );
            SettleMode::Linear
        }
        Ok(Err(e)) => {
            tracing::warn!("[dapv-proved] prover attestation failed, falling back to linear: {e}");
            SettleMode::Linear
        }
        Err(_) => {
            tracing::warn!(
                "[dapv-proved] prover attestation timed out after {:?}, falling back to linear",
                PROVER_ATTEST_TIMEOUT
            );
            SettleMode::Linear
        }
    }
}

/// reveal 承诺的域分隔标签：keccak256("zgame.dapv.reveal_commit.v2")。
fn handbatch_reveal_commit_label() -> Felt {
    // starknet_keccak 返回的 Felt 与本仓统一载体（types-core）同型，
    // keccak 输出 < 2^250 < P，直接使用。
    starknet_keccak("zgame.dapv.reveal_commit.v2".as_bytes())
}

/// 任意字节串 → 31 字节大端块逐 felt（每块 < 2^248 < 域模，无截断风险）。
fn bytes_as_felts(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[32 - chunk.len()..].copy_from_slice(chunk);
            // 31 字节 < 2^248 < P，canonical 恒成立。
            Felt::from_bytes_be(&buf)
        })
        .collect()
}

/// 32 字节 → felt（清高 5 位保证 < 域模；仅用于承诺类字段，非安全性输入）。
fn bytes_to_field(b: &[u8; 32]) -> Felt {
    let mut out = *b;
    out[0] &= 0x07;
    // 高 3 位清零 ⇒ < 2^253 的最高位被砍到 < 2^251 + …< P，canonical 恒成立。
    Felt::from_bytes_be(&out)
}

/// 构造 Hand-batch 结算：hand_binding + g_attestation + 认可批次 + calldata。
///
/// `endorsement_keys` 与 `settlement.players_remapped` 同序（每参与者一条
/// (sk, pk)），在内部用 hand 域铸造认可。提交前在宿主侧做与链上完全
/// 一致的 ρ 折叠 parity 检查（L == O），本地不过直接报错，不上链浪费 gas。
/// 内部构建（接受认可生产回调）：客户端路径传成品认可；服务器铸造
/// 路径传 mint 闭包。hand_binding 派生需要先于认可铸造（挑战域）。
/// Hand-batch 结算第一阶段产物（P2.1）：hand_binding 及其 32B 大端字节。
/// 认可铸造以此为挑战域，客户端 mint 前必须拿到它。
#[derive(Debug, Clone)]
pub struct HandBatchBinding {
    pub hand_binding: Felt,
    pub hand_id_bytes: [u8; 32],
}

/// 提前派生 hand_binding（不依赖任何认可——绑定链只含 deck 承诺、
/// reveal 承诺、状态根、结算摘要）。`build_dual_settlement_with` 内部
/// 复用同一确定性计算，两处结果逐字节一致。
pub fn prepare_handbatch_binding(
    mirror: &VmTable,
    settlement: &HandSettlement,
) -> Result<HandBatchBinding, String> {
    let pre_table = mirror.pre_settlement.as_ref().unwrap_or(&mirror.table);
    let deck_commit = poker_texas_air::deck_commitment::deck_commitment(pre_table);
    let reveal_commitment = {
        let deck_bytes = borsh::to_vec(&pre_table.deck_state.encrypted)
            .map_err(|e| format!("dapv: deck encode: {e}"))?;
        let mut input = vec![handbatch_reveal_commit_label()];
        input.push(Felt::from(deck_bytes.len() as u64));
        input.extend(bytes_as_felts(&deck_bytes));
        let digest_bytes = settlement.aggregate_digest.to_vec();
        input.push(Felt::from(digest_bytes.len() as u64));
        input.extend(bytes_as_felts(&digest_bytes));
        starknet_crypto::poseidon_hash_many(&input)
    };
    let hand_binding = compute_hand_binding(&HandBindingInput {
        table_id: mirror.table_seed,
        hand_id: u64::from(settlement.hand_id),
        players: settlement.players_remapped.clone(),
        deck_commitments: vec![poker_texas_air::state_root::u64_to_field(deck_commit)],
        reveal_commitment,
        state_root_pre: bytes_to_field(&settlement.pre_state_root),
        state_root_post: bytes_to_field(&settlement.post_state_root),
        settlement_digest: settlement.settlement_digest,
    })
    .map_err(|e| format!("dapv: hand_binding: {e}"))?;
    Ok(HandBatchBinding {
        hand_id_bytes: hand_binding.to_bytes_be(),
        hand_binding,
    })
}

pub fn build_dual_settlement_with(
    mirror: &VmTable,
    settlement: &HandSettlement,
    produce: &dyn Fn(&[u8; 32], &[Felt]) -> Result<Vec<Endorsement>, String>,
) -> Result<DualSettlement, String> {
    let _pre_table = mirror.pre_settlement.as_ref().unwrap_or(&mirror.table);

    // ---- 1. hand_binding（复用 prepare_handbatch_binding 的确定性派生）----
    let binding = prepare_handbatch_binding(mirror, settlement)?;
    let hand_id_bytes = binding.hand_id_bytes;
    let hand_binding = binding.hand_binding;
    let endorsements = produce(&hand_id_bytes, &settlement.players_remapped)?;
    let batch_words = assemble_batch(&endorsements, &[]);

    // ---- 3. 宿主侧 ρ 折叠 parity（Horner，与 Cairo fold_and_check 同构）----
    let equations = parse_batch_terms(&hand_id_bytes, &batch_words)
        .ok_or("dapv: batch reparse failed (internal)")?;
    if !host_fold_check(&hand_id_bytes, &equations) {
        return Err(
            "dapv: host fold parity failed (L != O) — batch would be rejected on-chain".into(),
        );
    }

    // ---- 4. g_attestation：G（外部聚合）+ 状态根的 Poseidon 承诺 ----
    let agg = AggregateDigestFelts::split(&settlement.aggregate_digest)
        .map_err(|e| format!("dapv: aggregate split: {e}"))?;
    let pre = AggregateDigestFelts::split(&settlement.pre_state_root)
        .map_err(|e| format!("dapv: pre root split: {e}"))?;
    let post = AggregateDigestFelts::split(&settlement.post_state_root)
        .map_err(|e| format!("dapv: post root split: {e}"))?;
    let g_attestation = starknet_crypto::poseidon_hash_many(&[
        hand_binding,
        settlement.settlement_digest,
        agg.hi,
        agg.lo,
        pre.hi,
        pre.lo,
        post.hi,
        post.lo,
    ]);

    // ---- 5. calldata（linear + proved 两套都构建；提交时按模式选用）----
    let hb_felt = hand_binding;
    // register_hand(hand_binding, settlement_digest, g_attestation,
    // exp_reveal, exp_leave, exp_recon)：期望桶计数暂全零（= 链上不约束；
    // 与合约侧"零 = 无约束"的兼容语义一致）。
    // register_hand(hand_binding, settlement_digest, g_attestation,
    // action_log_digest, exp_reveal, exp_leave, exp_recon)：期望桶计数暂
    // 全零（= 链上不约束）；动作日志哈希为 #18 Phase B 的注册承诺。
    let register_calldata = vec![
        hb_felt,
        settlement.settlement_digest,
        g_attestation,
        settlement.action_log_digest,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];

    let mut settle_calldata = Vec::with_capacity(6 + 32 + 4 * settlement.players_remapped.len());
    settle_calldata.push(hb_felt);
    // hand_id_bytes: Span<u8> = [len, items...]
    settle_calldata.push(Felt::from(32u64));
    for b in hand_id_bytes {
        settle_calldata.push(Felt::from(u64::from(b)));
    }
    settle_calldata.push(Felt::from(u64::from(settlement.hand_id)));
    // #18 Phase B：verify_and_settle_dapv_stark[_private] 的动作日志哈希
    // 标量（hand_id 之后，与合约签名一致）。
    settle_calldata.push(settlement.action_log_digest);
    // players: Span<ContractAddress>
    settle_calldata.push(Felt::from(settlement.players_remapped.len() as u64));
    for p in &settlement.players_remapped {
        settle_calldata.push(*p);
    }
    // deltas: Span<i128>（负数取模补，与合约 from_felt_signed_i128 对齐）。
    // 单位与 legacy 路径一致：vault 以 wei 记账，这里放大为 wei，
    // 与 register 的 settlement_digest（同样按 wei 计算）保持一致。
    // 2026-09-04 修复：曾局部定义 1e14 与全局 config::WEI_PER_CHIP(1e15) 差
    // 10 倍（买入 1e15 记账 / 结算 1e14 挪账），统一引用全局常量。
    const DAPV_WEI_PER_CHIP: i128 = super::config::WEI_PER_CHIP as i128;
    settle_calldata.push(Felt::from(settlement.deltas.len() as u64));
    for d in &settlement.deltas {
        let wei = d
            .checked_mul(DAPV_WEI_PER_CHIP)
            .ok_or("delta wei overflow")?;
        settle_calldata.push(i128_to_felt(wei));
    }
    // p_batch: Span<felt252> —— 每字单 felt（STARK 曲线基域 == felt252，
    // 点坐标/标量词天然在域内；越界词在此报错不上链）。提交入口为
    // verify_and_settle_dapv_stark——旧 `verify_and_settle_dapv` 收
    // Span<u256> 并走 secp 变体 verify_hand_batch，与 STARK 背书不匹配。
    settle_calldata.push(Felt::from(batch_words.len() as u64));
    for w in &batch_words {
        // 与 compute_p_batch_commitment 同门槛：非 canonical 词拒绝上链。
        let felt = Felt::from_bytes_be(w);
        if felt.to_bytes_be() != *w {
            return Err("dapv: batch word not in felt252 range".to_string());
        }
        settle_calldata.push(felt);
    }

    // ---- 6. proved 工件：p_batch 承诺 + 无 p_batch 的 register/settle ----
    let p_batch_commitment = compute_p_batch_commitment(hand_binding, &batch_words)?;
    let p_batch_len_felt = Felt::from(batch_words.len() as u64);
    let proved_register_calldata = vec![
        hb_felt,
        settlement.settlement_digest,
        g_attestation,
        settlement.action_log_digest,
        p_batch_commitment,
        p_batch_len_felt,
        // 期望桶计数（reveal/leave/recon）：链上不校验 proved 载荷（词都
        // 不上链），注册值供外部 prover 线下比对——暂全零（无约束）。
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    // settle calldata 不在此构建：P2-M4 的 proved_private 入口需要
    // settlement_private 公开段（含赢家 payout commitment 的 claim cm），
    // 在 submit_dual_settlement 里由 prepare_request 的结果填充。
    let proved = ProvedSettlement {
        p_batch_commitment,
        p_batch_len: batch_words.len(),
        register_calldata: proved_register_calldata,
        settle_calldata: Vec::new(),
    };

    Ok(DualSettlement {
        hand_binding,
        g_attestation,
        hand_id: settlement.hand_id,
        action_log_digest: settlement.action_log_digest,
        action_entries: settlement.action_entries.clone(),
        batch_words,
        register_calldata,
        settle_calldata,
        proved,
    })
}

/// ρ 折叠宿主 parity（Horner 版，A 优化）：与 Cairo 端
/// hand_batch_stark.cairo::fold_and_check 同构。
///
/// 结构：方程内点 `eq_i = s_i·G − c_i·pk_i − R_i`（负项用**点取反**表达，
/// −c·pk ≡ c·(−pk)，规避 felt 域取反 ≠ −c mod n 的陷阱），随后
/// Horner 折叠 `L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)`。
/// host 用归约后的 c/ρ（Z_n 标量），Cairo 用原始 poseidon felt 作标量
/// ——EC 标量乘对 m 与 m mod n 同结果（群阶），两侧同点。
pub fn host_fold_check(hand_id_bytes: &[u8; 32], equations: &[HandBatchEquation]) -> bool {
    if equations.is_empty() {
        return false;
    }
    let g = StarkCurve::base_g();

    // 展开全部方程内点 + ρ 词（ownership 1 点/方程，reveal 2 点/方程）。
    let mut eq_points: Vec<Pt> = Vec::new();
    let mut all_words = Vec::new();
    for e in equations {
        // BG 的两条标量校验是精确等式（不是概率性折叠）：失败必须立即
        // 拒绝（与 Cairo verify 直接 return false 同构）。
        if let HandBatchEquation::Shuffle {
            input,
            output,
            pk,
            proof,
        } = e
        {
            let eqs = bg_shuffle_fold_equations(input, output, pk, proof);
            if !eqs.scalar_check_1 || !eqs.scalar_check_2 {
                return false;
            }
        }
        let (pts, words) = e.points_and_words(hand_id_bytes, &g);
        eq_points.extend(pts);
        all_words.push(words);
    }
    let rho = poker_protocol_core::stark_curve::handbatch_rho(hand_id_bytes, &all_words);

    // Horner：L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)
    let mut acc = eq_points[eq_points.len() - 1];
    for eq in eq_points[..eq_points.len() - 1].iter().rev() {
        acc = acc * rho + *eq;
    }
    acc.is_identity()
}

/// [`host_fold_check`] 的语义别名（测试/诊断用）。
#[cfg(test)]
pub fn host_fold_is_identity(hand_id_bytes: &[u8; 32], equations: &[HandBatchEquation]) -> bool {
    host_fold_check(hand_id_bytes, equations)
}

/// 一条参与 Hand-batch 折叠的方程（host 表示）。
#[derive(Debug, Clone)]
pub enum HandBatchEquation {
    /// s·G − c·pk − R = O（c = handbatch_endorsement_challenge）
    Ownership { s: Sc, pk: Pt, r: Pt },
    /// reveal 两联方程（c = handbatch_reveal_challenge）：
    ///   eq1: s·G − t1 − c·pk = O
    ///   eq2: s·c1 − t2 − c·token = O
    Reveal {
        s: Sc,
        pk: Pt,
        c1: Pt,
        c2: Pt,
        token: Pt,
        t1: Pt,
        t2: Pt,
        nonce: Sc,
    },
    /// leave/remask 批量 DLEQ（c = handbatch_leave_challenge）：
    ///   eq0:  s·G − cpk − c·pk = O
    ///   eq_i: s·in_c1ᵢ − aᵢ − c·d2ᵢ = O（d2ᵢ = in_c2ᵢ − out_c2ᵢ）
    Leave {
        s: Sc,
        pk: Pt,
        cpk: Pt,
        nonce: Sc,
        cards: Vec<LeaveCardPts>,
    },
    /// reconstruct CP-DLEQ 两联方程（c = handbatch_reconstruct_challenge）：
    ///   eq1: s·G1 − A − c·P1 = O
    ///   eq2: s·G2 − B − c·P2 = O
    /// wire 词序（13 词/条）：[g1 2, g2 2, p1 2, p2 2, A 2, B 2, s]。
    Reconstruct {
        s: Sc,
        g1: Pt,
        g2: Pt,
        p1: Pt,
        p2: Pt,
        a: Pt,
        b: Pt,
    },
    /// Bayer–Groth V2 洗牌（kind=5）：经 [`bg_shuffle_fold_equations`] 分解为
    /// 6 条线性方程（E1a, E1b, E3, E4a, E4b, E-batched——E2/E5/E6 已按
    /// E2/E5/E6 分开验证）+ 2 条标量校验。每条方程一个 ρ 词组
    /// （s=c=0——语句已由 BG transcript 自身整体绑定，ρ 只需记录"按序折
    /// 叠"），与 Cairo 端 bg_stark.cairo::bg_equation_words 同构。wire 词序
    /// （11n+31 词/条）：[n, input 4n, output 4n, pk 2, 承诺 22, 响应 3n+6]。
    Shuffle {
        input: Vec<poker_protocol_core::StarkElGamalCiphertext>,
        output: Vec<poker_protocol_core::StarkElGamalCiphertext>,
        pk: Pt,
        proof: Box<BayerGrothShuffleProof<StarkCurve>>,
    },
}

/// leave 每卡公开点。
#[derive(Debug, Clone)]
pub struct LeaveCardPts {
    pub in_c1: Pt,
    pub in_c2: Pt,
    pub out_c1: Pt,
    pub out_c2: Pt,
    pub a: Pt,
}

impl HandBatchEquation {
    /// 展开为（方程内点，ρ 词 (kind, s, c)）。
    fn points_and_words(
        &self,
        hand_binding: &[u8; 32],
        g: &Pt,
    ) -> (
        Vec<Pt>,
        poker_protocol_core::stark_curve::HandBatchEquationWords,
    ) {
        use poker_protocol_core::stark_curve::HandBatchEquationWords;
        match self {
            HandBatchEquation::Ownership { s, pk, r } => {
                let c = poker_protocol_core::stark_curve::handbatch_endorsement_challenge(
                    hand_binding,
                    g,
                    pk,
                    r,
                );
                let eq = *g * *s + (-*pk) * c + (-*r);
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (
                    vec![eq],
                    HandBatchEquationWords {
                        kind: 1,
                        s: s_w,
                        c: c_w,
                    },
                )
            }
            HandBatchEquation::Reveal {
                s,
                pk,
                c1,
                c2,
                token,
                t1,
                t2,
                nonce,
            } => {
                let c = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
                    hand_binding,
                    pk,
                    c1,
                    c2,
                    token,
                    t1,
                    t2,
                    nonce,
                );
                let eq1 = *g * *s + (-*pk) * c + (-*t1);
                let eq2 = *c1 * *s + (-*token) * c + (-*t2);
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (
                    vec![eq1, eq2],
                    HandBatchEquationWords {
                        kind: 2,
                        s: s_w,
                        c: c_w,
                    },
                )
            }
            HandBatchEquation::Leave {
                s,
                pk,
                cpk,
                nonce,
                cards,
            } => {
                let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards
                    .iter()
                    .map(|c| poker_protocol_core::stark_curve::HandLeaveCardWords {
                        in_c1: c.in_c1,
                        in_c2: c.in_c2,
                        out_c1: c.out_c1,
                        out_c2: c.out_c2,
                        a: c.a,
                    })
                    .collect();
                let c = poker_protocol_core::stark_curve::handbatch_leave_challenge(
                    hand_binding,
                    pk,
                    cpk,
                    nonce,
                    &card_words,
                );
                let mut pts = vec![*g * *s + (-*cpk) + (-*pk) * c];
                for card in cards {
                    let d2 = card.in_c2 - card.out_c2;
                    pts.push(card.in_c1 * *s + (-card.a) + (-d2) * c);
                }
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (
                    pts,
                    HandBatchEquationWords {
                        kind: 3,
                        s: s_w,
                        c: c_w,
                    },
                )
            }
            HandBatchEquation::Reconstruct {
                s,
                g1,
                g2,
                p1,
                p2,
                a,
                b,
            } => {
                let c = poker_protocol_core::stark_curve::handbatch_reconstruct_challenge(
                    hand_binding,
                    g1,
                    g2,
                    p1,
                    p2,
                    a,
                    b,
                );
                let eq1 = *g1 * *s + (-*a) + (-*p1) * c;
                let eq2 = *g2 * *s + (-*b) + (-*p2) * c;
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (
                    vec![eq1, eq2],
                    HandBatchEquationWords {
                        kind: 4,
                        s: s_w,
                        c: c_w,
                    },
                )
            }
            HandBatchEquation::Shuffle {
                input,
                output,
                pk,
                proof,
            } => {
                let eqs = bg_shuffle_fold_equations(input, output, pk, proof);
                let zero_w = [0u8; 32];
                // 每条 BG 方程一个残差点 + 一个 kind=5 ρ 词组（与 Cairo
                // hand_batch_stark 的 shuffle 桶折叠粒度一致）。
                let pts = eqs.equations.iter().map(|eq| linear_residual(eq)).collect();
                (
                    pts,
                    HandBatchEquationWords {
                        kind: 5,
                        s: zero_w,
                        c: zero_w,
                    },
                )
            }
        }
    }
}

/// 组装 hand_batch 载荷（P 层批次）。规范头（5 词）：
/// `[n_own, n_shuffle, n_reveal, n_leave, n_recon]`；随后按序：
/// - own：`(pk_x, pk_y, r_x, r_y, s) × n_own`（5 词/条）
/// - shuffle：BG 桶槽位（见 parse_batch_terms，暂拒）
/// - reveal：`(pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s) × n_reveal`
///   （14 词/条）
/// - leave：每条 `[n, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n,
///   out_c2 2n, a 2n]`
/// - recon：`(g1 2, g2 2, p1 2, p2 2, A 2, B 2, s) × n_recon`（13 词/条）
fn assemble_batch(endorsements: &[Endorsement], recon: &[HandBatchEquation]) -> Vec<[u8; 32]> {
    let recon_terms: Vec<&HandBatchEquation> = recon
        .iter()
        .filter(|e| matches!(e, HandBatchEquation::Reconstruct { .. }))
        .collect();
    // 规范头（5 词）：[n_own, n_shuffle, n_reveal, n_leave, n_recon]
    let mut batch_words: Vec<[u8; 32]> =
        Vec::with_capacity(5 + 5 * endorsements.len() + 13 * recon_terms.len());
    batch_words.push(u256_word(endorsements.len() as u64));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(recon_terms.len() as u64));
    for e in endorsements {
        let (pk_x, pk_y) = point_xy(&e.pk);
        let (r_x, r_y) = point_xy(&e.r);
        batch_words.push(pk_x);
        batch_words.push(pk_y);
        batch_words.push(r_x);
        batch_words.push(r_y);
        batch_words.push(scalar_be(&e.s));
    }
    for term in recon_terms {
        if let HandBatchEquation::Reconstruct {
            s,
            g1,
            g2,
            p1,
            p2,
            a,
            b,
        } = term
        {
            for p in [g1, g2, p1, p2, a, b] {
                let (x, y) = point_xy(p);
                batch_words.push(x);
                batch_words.push(y);
            }
            batch_words.push(scalar_be(s));
        }
    }
    batch_words
}

/// P2.1 客户端认可路径：用玩家客户端铸造并提交的成品认可构建结算，
/// 服务器全程不接触认可私钥。数量必须与参与者一致。
/// 解析 hand_batch 载荷为折叠项（与 Cairo 端 ownership_terms 同构；
/// 当前批次只含 ownership）。跨手重放检测与篡改检测的测试入口。
pub fn parse_batch_terms(
    _hand_binding: &[u8; 32],
    batch_words: &[[u8; 32]],
) -> Option<Vec<HandBatchEquation>> {
    // 规范头（5 词，Hand-batch v2.8 方程序序）：[n_own, n_shuffle, n_reveal, n_leave, n_recon]
    if batch_words.len() < 5 {
        return None;
    }
    let n_own = word_low_u64(&batch_words[0])? as usize;
    let n_shuffle = word_low_u64(&batch_words[1])? as usize;
    let n_reveal = word_low_u64(&batch_words[2])? as usize;
    let n_leave = word_low_u64(&batch_words[3])? as usize;
    let n_recon = word_low_u64(&batch_words[4])? as usize;
    if batch_words.len() < 5 + 5 * n_own + 14 * n_reveal + 13 * n_recon {
        return None;
    }
    let mut equations = Vec::with_capacity(n_own + n_reveal + n_leave + n_recon);
    for i in 0..n_own {
        let base = 5 + 5 * i;
        let pk = point_from_words(&batch_words[base], &batch_words[base + 1])?;
        let r = point_from_words(&batch_words[base + 2], &batch_words[base + 3])?;
        let s = scalar_from_word(&batch_words[base + 4])?;
        equations.push(HandBatchEquation::Ownership { s, pk, r });
    }
    // shuffle 桶（kind=5）：每条 [n, input 4n, output 4n, pk 2, 承诺 22,
    // 响应 3n+6] = 11n+31 词。重建 BayerGrothShuffleProof 后交
    // bg_shuffle_fold_equations 分解（挑战由 transcript 重放重算）。
    let mut cursor = 5 + 5 * n_own;
    for _ in 0..n_shuffle {
        if batch_words.len() < cursor + 1 {
            return None;
        }
        let n = word_low_u64(&batch_words[cursor])? as usize;
        if n == 0 {
            return None;
        }
        let bucket_len = 11 * n + 31;
        if batch_words.len() < cursor + bucket_len {
            return None;
        }
        let w = &batch_words[cursor..cursor + bucket_len];
        let mut o = 1usize;
        let ct_n = |o: &mut usize| -> Option<poker_protocol_core::StarkElGamalCiphertext> {
            let c1 = point_from_words(&w[*o], &w[*o + 1])?;
            let c2 = point_from_words(&w[*o + 2], &w[*o + 3])?;
            *o += 4;
            Some(poker_protocol_core::StarkElGamalCiphertext { c1, c2 })
        };
        let mut input = Vec::with_capacity(n);
        for _ in 0..n {
            input.push(ct_n(&mut o)?);
        }
        let mut output = Vec::with_capacity(n);
        for _ in 0..n {
            output.push(ct_n(&mut o)?);
        }
        let pk = point_from_words(&w[o], &w[o + 1])?;
        o += 2;
        let pt_n = |o: &mut usize| -> Option<Pt> {
            let p = point_from_words(&w[*o], &w[*o + 1])?;
            *o += 2;
            Some(p)
        };
        let sc_n = |o: &mut usize| -> Option<Sc> {
            let s = scalar_from_word(&w[*o])?;
            *o += 1;
            Some(s)
        };
        let c_permutation = pt_n(&mut o)?;
        let c_permuted_powers = pt_n(&mut o)?;
        let c_alpha = pt_n(&mut o)?;
        let c_beta = pt_n(&mut o)?;
        let ciphertext_0 = ct_n(&mut o)?;
        let ciphertext_1 = ct_n(&mut o)?;
        let c_d = pt_n(&mut o)?;
        let c_delta = pt_n(&mut o)?;
        let c_capital_delta = pt_n(&mut o)?;
        let mut alpha_response = Vec::with_capacity(n);
        for _ in 0..n {
            alpha_response.push(sc_n(&mut o)?);
        }
        let commitment_response = sc_n(&mut o)?;
        let beta = sc_n(&mut o)?;
        let beta_blinding_response = sc_n(&mut o)?;
        let rerandomization_response = sc_n(&mut o)?;
        let mut a_response = Vec::with_capacity(n);
        for _ in 0..n {
            a_response.push(sc_n(&mut o)?);
        }
        let mut b_response = Vec::with_capacity(n);
        for _ in 0..n {
            b_response.push(sc_n(&mut o)?);
        }
        let r_response = sc_n(&mut o)?;
        let s_response = sc_n(&mut o)?;
        debug_assert_eq!(o, bucket_len);
        equations.push(HandBatchEquation::Shuffle {
            input,
            output,
            pk,
            proof: Box::new(BayerGrothShuffleProof {
                c_permutation,
                c_permuted_powers,
                multi_exponentiation: MultiExponentiationArgument {
                    c_alpha,
                    c_beta,
                    ciphertext_0,
                    ciphertext_1,
                    alpha_response,
                    commitment_response,
                    beta,
                    beta_blinding_response,
                    rerandomization_response,
                },
                product: ProductArgument {
                    c_d,
                    c_delta,
                    c_capital_delta,
                    a_response,
                    b_response,
                    r_response,
                    s_response,
                },
            }),
        });
        cursor += bucket_len;
    }
    // reveal 词布局（与 secp 变体同构）：
    // [pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s] = 14 词/条。
    for _ in 0..n_reveal {
        let pk = point_from_words(&batch_words[cursor], &batch_words[cursor + 1])?;
        let c1 = point_from_words(&batch_words[cursor + 2], &batch_words[cursor + 3])?;
        let c2 = point_from_words(&batch_words[cursor + 4], &batch_words[cursor + 5])?;
        let token = point_from_words(&batch_words[cursor + 6], &batch_words[cursor + 7])?;
        let t1 = point_from_words(&batch_words[cursor + 8], &batch_words[cursor + 9])?;
        let t2 = point_from_words(&batch_words[cursor + 10], &batch_words[cursor + 11])?;
        let nonce = scalar_from_word(&batch_words[cursor + 12])?;
        let s = scalar_from_word(&batch_words[cursor + 13])?;
        equations.push(HandBatchEquation::Reveal {
            s,
            pk,
            c1,
            c2,
            token,
            t1,
            t2,
            nonce,
        });
        cursor += 14;
    }
    for _ in 0..n_leave {
        // [n, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]
        let n_cards = word_low_u64(&batch_words[cursor])? as usize;
        if batch_words.len() < cursor + 7 + 10 * n_cards {
            return None;
        }
        let pk = point_from_words(&batch_words[cursor + 1], &batch_words[cursor + 2])?;
        let cpk = point_from_words(&batch_words[cursor + 3], &batch_words[cursor + 4])?;
        let nonce = scalar_from_word(&batch_words[cursor + 5])?;
        let s = scalar_from_word(&batch_words[cursor + 6])?;
        let base = cursor + 7;
        let mut cards = Vec::with_capacity(n_cards);
        for i in 0..n_cards {
            let o = base + 2 * i;
            let in_c1 = point_from_words(&batch_words[o], &batch_words[o + 1])?;
            let in_c2 = point_from_words(
                &batch_words[base + 2 * n_cards + 2 * i],
                &batch_words[base + 2 * n_cards + 2 * i + 1],
            )?;
            let out_c1 = point_from_words(
                &batch_words[base + 4 * n_cards + 2 * i],
                &batch_words[base + 4 * n_cards + 2 * i + 1],
            )?;
            let out_c2 = point_from_words(
                &batch_words[base + 6 * n_cards + 2 * i],
                &batch_words[base + 6 * n_cards + 2 * i + 1],
            )?;
            let a = point_from_words(
                &batch_words[base + 8 * n_cards + 2 * i],
                &batch_words[base + 8 * n_cards + 2 * i + 1],
            )?;
            cards.push(LeaveCardPts {
                in_c1,
                in_c2,
                out_c1,
                out_c2,
                a,
            });
        }
        equations.push(HandBatchEquation::Leave {
            s,
            pk,
            cpk,
            nonce,
            cards,
        });
        cursor += 7 + 10 * n_cards;
    }
    // recon 词布局：[g1 2, g2 2, p1 2, p2 2, A 2, B 2, s] = 13 词/条。
    for _ in 0..n_recon {
        let g1 = point_from_words(&batch_words[cursor], &batch_words[cursor + 1])?;
        let g2 = point_from_words(&batch_words[cursor + 2], &batch_words[cursor + 3])?;
        let p1 = point_from_words(&batch_words[cursor + 4], &batch_words[cursor + 5])?;
        let p2 = point_from_words(&batch_words[cursor + 6], &batch_words[cursor + 7])?;
        let a = point_from_words(&batch_words[cursor + 8], &batch_words[cursor + 9])?;
        let b = point_from_words(&batch_words[cursor + 10], &batch_words[cursor + 11])?;
        let s = scalar_from_word(&batch_words[cursor + 12])?;
        equations.push(HandBatchEquation::Reconstruct {
            s,
            g1,
            g2,
            p1,
            p2,
            a,
            b,
        });
        cursor += 13;
    }
    Some(equations)
}

fn word_low_u64(w: &[u8; 32]) -> Option<u64> {
    if w[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&w[24..]);
    Some(u64::from_be_bytes(tail))
}

fn point_from_words(x: &[u8; 32], y: &[u8; 32]) -> Option<Pt> {
    // types-core Felt 与 Pt（StarkPoint）内部域一致；BETA 来自
    // starknet-curve 0.6（同 types-core 0.2 类型实例）。
    use starknet_curve::curve_params::BETA;
    let px = Felt::from_bytes_be(x);
    let py = Felt::from_bytes_be(y);
    // 恶意载荷可能给出不在曲线上的 (x, y)：折叠数学只在真曲线上成立，
    // 解析时必须验证曲线方程 y² = x³ + x + β（STARK 曲线，a=1）。
    if py * py != px * px * px + px + BETA {
        return None;
    }
    Some(Pt::from_affine_parts(px, py))
}

fn scalar_from_word(w: &[u8; 32]) -> Option<Sc> {
    <Sc as CurveScalar>::from_canonical_bytes(w)
}

fn u256_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// 提交 Hand-batch 结算。按 `STARKNET_SETTLE_MODE` 分流：
///
/// - `Linear`（默认）：`register_hand` + `verify_and_settle_dapv`
///   （p_batch 全文上链）——与引入 settle-mode 之前的行为一致。
/// - `Proved`：先导出 workload JSON（prover CLI 的输入，best-effort），
///   再尝试外部 prover attestation（当前为必然报错的存根）；**任何**
///   错误/超时自动回退 linear 路径（复用同一份 batch_words/calldata，
///   结算绝不因 prover 阻塞）。attestation 成功且承诺匹配时才走
///   `register_hand_proved` + `verify_and_settle_dapv_proved`。
///
/// 返回 (register_tx, settle_tx)。
/// Part A Phase 1：检查所有赢家是否已在 vault 注册 payout commitment。
/// 任一未注册 → 私有结算入口缺前置，回退 legacy（不卡结算）。
async fn winners_registered(players_remapped: &[Felt], deltas: &[i128]) -> bool {
    let Some(chain) = super::chain() else {
        return false;
    };
    let Some(vault_addr) = super::chain::parse_felt(&chain.config.vault_address) else {
        return false;
    };
    let selector = starknet_keccak(b"payout_commitment");
    for (i, p) in players_remapped.iter().enumerate() {
        // 只有赢家（delta > 0）需要 payout commitment——输家走公开扣款。
        let Some(d) = deltas.get(i) else { return false };
        if *d <= 0 {
            continue;
        }
        match chain.call_contract(vault_addr, selector, vec![*p]).await {
            Ok(felts) => {
                let registered = felts.first().map(|f| *f != Felt::ZERO).unwrap_or(false);
                if !registered {
                    tracing::info!(
                        "[starknet-settle] winner {p:#x} has no payout commitment — legacy settle"
                    );
                    return false;
                }
            }
            Err(e) => {
                tracing::warn!("[starknet-settle] payout_commitment query failed: {e}");
                return false;
            }
        }
    }
    true
}

/// DAPV proved 路径的 settle 入口选择（`STARKNET_DAPV_SETTLE_ENTRY`）：
///
/// - `v2`（默认）：`verify_and_settle_dapv_stark_private_v2`——零明文结算，
///   calldata `[hand_binding, hand_id, segment(16)]`（9 人桌公开段：MAGIC +
///   4 头词 + cm×9 + total + ald），fact-registry 单证明锚
///   （settlement_private 电路，2026-09-30 Span ABI 迁移后支持 9 席——
///   digest 固定 9 槽全吸收，非满桌语料与链上按实际人数折叠的注册值
///   不一致，会 DIGEST_MISMATCH fail-closed；n<9 的手走 combined），**可随时
///   回退的稳定入口**；
/// - `proved_private`：`verify_and_settle_dapv_proved_private`——hand_verify +
///   stark verify 双 fact 认证，calldata 尾部追加 `[p_batch_commitment,
///   p_batch_len]`（P2-M4，dual v4）；
/// - `snip36`：`verify_and_settle_dapv_stark_private_v3`——SNIP-36
///   proof_facts 优先 + fact-registry 降级双门，calldata 与 v2 同形
///   （**合约侧随 cairo ≥2.12 迁移上链后生效**，见
///   docs/design/SNIP36_INTEGRATION.md §4；选中未上链的入口会 revert）；
/// - `combined`：`verify_and_settle_dapv_combined_private`——P 层 + settlement
///   合并信封（combined.cairo 一次出证），calldata `[hand_binding, hand_id,
///   segment(17)]`（v2 16 词段前置 chain_acc，**必须来自 prove_combined 的公开
///   输出**，不可本地拼装——chain_acc 是证明内折叠值），单 fact 门
///   `fact = poseidon([combined_program_hash ‖ 段17])`（合约
///   `fact_for_segment` 同式）。
///
/// 各入口共用 register_hand_proved 注册（bindings/action_logs 同写）；差异在
/// fact 消费方式与 calldata 形状。
pub fn settle_entry_calldata(
    entry: &str,
    hand_binding: Felt,
    hand_id: u32,
    segment: &[Felt],
    p_batch_commitment: Felt,
    p_batch_len: usize,
) -> (&'static str, Vec<Felt>) {
    let mut calldata = Vec::with_capacity(2 + segment.len() + 2);
    calldata.push(hand_binding);
    calldata.push(Felt::from(u64::from(hand_id)));
    for f in segment {
        calldata.push(*f);
    }
    match entry {
        "proved_private" => {
            calldata.push(p_batch_commitment);
            calldata.push(Felt::from(p_batch_len as u64));
            ("verify_and_settle_dapv_proved_private", calldata)
        }
        "snip36" => ("verify_and_settle_dapv_stark_private_v3", calldata),
        // combined：segment 为 17 词公开输出（[chain_acc] ++ v2 段 16 词），
        // 由 prove_combined 结果传入（长度由合约 COMBINED_SEGMENT_LEN 再门）。
        "combined" => ("verify_and_settle_dapv_combined_private", calldata),
        // "v2" 与任何未知值：默认稳定入口（回退保证）
        _ => ("verify_and_settle_dapv_stark_private_v2", calldata),
    }
}

/// SNIP-36 两笔交易管线（服务内自动接线，`try_snip36_submit`）：
/// 1. create_proof 交易（调 `emit_settlement_proof_message`，零价字段、
///    不广播）→ 自托管 prover `starknet_proveTransaction` 虚拟执行出证；
/// 2. 同 calldata 的 v3 结算交易 + proof(uint32)/proof_facts 字段原始广播
///    （starknet-rs 账户抽象无此字段，走 [`super::snip36::ProvedInvokeV3`]
///    手拼 + 自算含 proof_facts 的交易哈希 + operator 密钥签名）。
///
/// 前置：`STARKNET_SNIP36_PROVER_URL` 指向内网 prover；合约侧 v6 门
/// （facts[2] = 虚拟 OS 哈希钉扎）已部署。任何失败都返回 Err。
async fn try_snip36_submit(
    chain: &super::StarknetChain,
    calldata: Vec<Felt>,
) -> Result<String, String> {
    use super::snip36::{BoundsVariant, ProvedInvokeV3, Snip36ProverClient};
    use starknet::core::types::{BlockId, BlockTag};
    use starknet::providers::Provider;
    use starknet::signers::SigningKey;

    let config = &chain.config;
    let prover_url = config
        .snip36_prover_url
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "snip36: STARKNET_SNIP36_PROVER_URL not configured".to_string())?
        .to_string();
    let sender = super::chain::parse_felt(&config.operator_address)
        .ok_or_else(|| "snip36: invalid operator address".to_string())?;
    let secret = super::chain::parse_felt(&config.operator_private_key)
        .ok_or_else(|| "snip36: invalid operator private key".to_string())?;
    let signing = SigningKey::from_secret_scalar(secret);
    let provider = chain.provider();
    let chain_id = provider
        .chain_id()
        .await
        .map_err(|e| format!("snip36: chain_id: {e}"))?;
    let nonce = provider
        .get_nonce(BlockId::Tag(BlockTag::Latest), sender)
        .await
        .map_err(|e| format!("snip36: nonce: {e}"))?;
    // 零价字段是 prover 输入校验的硬要求（证明客户端侧完成、不收费）；
    // l2_gas.max_amount = OS 执行 gas 上限（非 0）。
    let build = |proof_base64: Option<String>, proof_facts: Vec<Felt>| ProvedInvokeV3 {
        sender_address: sender,
        calldata: calldata.clone(),
        nonce,
        tip: 0,
        l1_gas: (0, 0),
        l1_data_gas: (0, 0),
        l2_gas: (config.snip36_l2_gas, 0),
        bounds_variant: BoundsVariant::AllResources,
        proof_base64,
        proof_facts,
    };

    // 1. create_proof 交易：签名覆盖其哈希，供虚拟执行中的 __validate__ 验证。
    let create_tx = build(None, vec![]);
    let sig = signing
        .sign(&create_tx.transaction_hash(chain_id))
        .map_err(|e| format!("snip36: sign create_proof tx: {e:?}"))?;
    let create_invoke = create_tx.to_broadcast_json([sig.r, sig.s]);

    // 2. 证明（对照已 finalization 的最新参考区块虚拟执行）。
    let output = Snip36ProverClient::new(prover_url)
        .prove_transaction(serde_json::json!("latest"), &create_invoke)
        .await?;
    tracing::info!(
        "[snip36] prover returned proof ({} felts, {} l2→l1 messages)",
        output.proof_facts.len(),
        output.l2_to_l1_messages.len()
    );

    // 3. proved v3 结算交易：同一 nonce（create_proof 未广播、不消耗 nonce）。
    let proved = ProvedInvokeV3::from_prove_output(build(None, vec![]), output);
    let sig = signing
        .sign(&proved.transaction_hash(chain_id))
        .map_err(|e| format!("snip36: sign proved tx: {e:?}"))?;
    let invoke = proved.to_broadcast_json([sig.r, sig.s]);

    // 4. 原始广播 add_invoke_transaction（扩展字段不经 starknet-rs 类型）。
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "add_invoke_transaction",
        "params": [invoke],
    });
    let resp = reqwest::Client::new()
        .post(&config.rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("snip36: submit: {e}"))?;
    let reply: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("snip36: submit body: {e}"))?;
    if let Some(err) = reply.get("error") {
        return Err(format!("snip36: submit rejected: {err}"));
    }
    reply["result"]["transaction_hash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "snip36: missing result.transaction_hash".to_string())
}

/// dev 本地 prover 的 settlement fact 登记：读 dual `circuit_program_hash`
/// 视图 → `fact = poseidon([program_hash ++ 公开段])` → operator 调
/// `register_settlement_fact`（owner/prover 白名单）。仅
/// `shadow::ProverMode::Local` 调用——生产的 fact 必须由跑过真实电路
/// 证明的 prover 登记，本地直登只用于 devnet e2e 闭环（v2 入口的
/// fact-registry 锚）。
async fn local_register_settlement_fact(
    req: &super::settlement_prover::SettlementPrivateRequest,
) -> Result<String, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let dual_addr = super::chain::parse_felt(&chain.config.dual_settlement_address)
        .ok_or("invalid dual settlement contract address")?;
    let program_hash = *chain
        .call_contract(
            dual_addr,
            super::chain::selector("circuit_program_hash"),
            vec![],
        )
        .await?
        .first()
        .ok_or("empty circuit_program_hash return")?;
    let fact = Felt::from_bytes_be(&req.settlement_fact(program_hash.to_bytes_be())?);
    register_settlement_fact_tx(&chain, dual_addr, fact).await
}

/// combined 腿的 fact 登记：程序哈希取 config
/// （`STARKNET_COMBINED_PROGRAM_HASH`）> 链上 `combined_program_hash` 视图；
/// 与证明公开的 program_hash 不一致（Cairo 源漂移）→ Err（fail-closed，
/// 不登记错 fact）。combined 的证明由 operator 自己 spawn 的子进程出具，
/// 所以 operator 直登 fact 与 v2 的 dev-local 语义一致（生产 remote v2 才
/// 依赖外部 prover 登记）。
async fn local_register_combined_settlement_fact(
    output: &super::settlement_prover::CombinedProofOutput,
) -> Result<String, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let dual_addr = super::chain::parse_felt(&chain.config.dual_settlement_address)
        .ok_or("invalid dual settlement contract address")?;
    let program_hash = match chain.config.combined_program_hash_felt() {
        Some(ph) => ph,
        None => *chain
            .call_contract(
                dual_addr,
                super::chain::selector("combined_program_hash"),
                vec![],
            )
            .await?
            .first()
            .ok_or("empty combined_program_hash return")?,
    };
    if program_hash == Felt::ZERO {
        return Err("combined program hash not set (owner set_combined_program_hash)".into());
    }
    if output.program_hash != program_hash {
        return Err(format!(
            "combined proof program hash {:#x} != pinned {:#x} (cairo source drift)",
            output.program_hash, program_hash
        ));
    }
    let fact = Felt::from_bytes_be(&output.settlement_fact(program_hash));
    register_settlement_fact_tx(&chain, dual_addr, fact).await
}

/// `register_settlement_fact` 的 operator 直登核心（v2 dev-local 与
/// combined 腿共用）。
async fn register_settlement_fact_tx(
    chain: &super::StarknetChain,
    dual_addr: Felt,
    fact: Felt,
) -> Result<String, String> {
    let operator = chain
        .operator()
        .await
        .ok_or("operator account unavailable")?;
    let result = operator
        .execute_v3(vec![Call {
            to: dual_addr,
            selector: super::chain::selector("register_settlement_fact"),
            calldata: vec![fact],
        }])
        .send()
        .await
        .map_err(|e| format!("register_settlement_fact invoke: {e}"))?;
    Ok(format!("{:#x}", result.transaction_hash))
}

/// combined 证明腿：读 acc 链状态 → spawn hand-verify-native CLI 出证。
/// P 任务产源接缝：调用方传入（hooks 从 `action_sig_materials` 构造，见
/// [`super::settlement_prover::CombinedTask::from_materials`]）；空任务 =
/// 无已签名动作，诚实跳过（不出无 P 语句的退化证明）。任一步失败返回
/// Err（调用方回退 linear，结算不阻塞）。
async fn prove_combined_segment(
    chain: &super::StarknetChain,
    req: &super::settlement_prover::SettlementPrivateRequest,
    dual: &DualSettlement,
    tasks: &[super::settlement_prover::CombinedTask],
) -> Result<super::settlement_prover::CombinedProofOutput, String> {
    if tasks.is_empty() {
        return Err(
            "no P tasks (no signed actions / payload build failed) — combined proof skipped".into(),
        );
    }
    let prover = super::settlement_prover::HttpSettlementProver::new(None);
    let out_dir = std::path::Path::new(&chain.config.prover_work_dir)
        .join(format!("hand-{}-combined", dual.hand_id));
    let prev_acc = read_combined_acc()?;
    prover
        .prove_combined(
            tasks,
            req,
            prev_acc,
            &out_dir,
            &chain.config.combined_native_bin,
        )
        .await
}

/// combined acc 链状态文件（env `STARKNET_COMBINED_ACC_STATE`，默认
/// `data/combined_acc.txt`，相对 cwd）。文件不存在 = GENESIS（Felt::ZERO）；
/// 内容为单行 hex。链状态是 operator 侧不变量（合约只 emit chain_acc、
/// 不校验连续性）——读失败 fail-closed（combined 腿放弃回退），写失败
/// 告警（下一手需人工对账恢复，见 [`write_combined_acc`]）。
fn combined_acc_state_path() -> std::path::PathBuf {
    std::env::var("STARKNET_COMBINED_ACC_STATE")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("data/combined_acc.txt"))
}

fn read_combined_acc() -> Result<Felt, String> {
    read_combined_acc_at(&combined_acc_state_path())
}

fn read_combined_acc_at(path: &std::path::Path) -> Result<Felt, String> {
    if !path.exists() {
        return Ok(Felt::ZERO); // GENESIS（hand-verify-native GENESIS_ACC 同值）
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let t = raw.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() {
        return Err(format!(
            "combined acc state {} is empty (corrupt)",
            path.display()
        ));
    }
    Felt::from_hex(t).map_err(|e| {
        format!(
            "combined acc state {} not a felt hex ({e:?}) — manual reconciliation required",
            path.display()
        )
    })
}

/// 原子写（临时文件 + rename，同目录同文件系统）：并发读者只会看到旧值或
/// 新值，不会看到半行。
fn write_combined_acc(acc: Felt) -> Result<(), String> {
    write_combined_acc_at(&combined_acc_state_path(), acc)
}

fn write_combined_acc_at(path: &std::path::Path, acc: Felt) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("0x{acc:x}\n"))
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), path.display()))
}

pub async fn submit_dual_settlement(
    dual: &DualSettlement,
    dual_address: &str,
    players_remapped: &[Felt],
    deltas: &[i128],
    departed: &[String],
    combined_tasks: &[super::settlement_prover::CombinedTask],
) -> Result<(String, String), String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let contract =
        super::chain::parse_felt(dual_address).ok_or("invalid dual settlement contract address")?;
    let operator = chain
        .operator()
        .await
        .ok_or("operator account unavailable")?;
    // txmgr 发送面（rollup-components 条目 2）：register/settle 两笔的
    // nonce 租约/回执轮询/幂等重放分类归交易管理层。每次提交独立
    // TxManager（基线 nonce 链上现查）；operator 账户保留给非结算发送
    // （snip36 原始管线 / 事后 win-relock）。
    let txmgr_send = std::sync::Arc::new(starknet_txmgr::provider::ProviderSend::new(
        operator.clone(),
    ));
    let account_felt = operator.address();

    // 模式决策（proved → 尝试 prover → 失败回退 linear）。
    // entry=snip36：证明源 = create_proof 交易的虚拟 SNOS 证明（自托管
    // prover），不依赖 settlement_private 电路 prover/batch attestation——
    // 只要隐私公开段就绪（全体赢家 payout commitment 齐备）即具备提交条件。
    // entry=combined：证明源 = operator spawn 的 hand-verify-native 合并
    // 信封（combined.cairo，一次 Cairo 执行覆盖 P 层 + settlement）——
    // 17 词公开段只能来自证明输出，证明失败/无 P 任务即回退 linear。
    let snip36_engaged = chain.config.dapv_settle_entry() == "snip36";
    let combined_engaged = chain.config.dapv_settle_entry() == "combined";
    let mode = if chain.config.settle_mode == SettleMode::Proved
        || snip36_engaged
        || combined_engaged
    {
        export_prover_workload(dual, std::path::Path::new(&chain.config.prover_work_dir));
        // prover 走向开关（shadow::prover_mode）：dev 本地模式在进程内
        // 校验并出具 attestation（fact 由 operator 直登），生产 remote
        // 模式走 STARKNET_PROVER_URL 外部服务。
        let local_prover = super::vm_session::prover_mode() == super::vm_session::ProverMode::Local;
        // P2-M2：settlement-private 电路 inputs 导出 + prover attestation。
        // best-effort：任何失败只告警，绝不阻塞结算（与 batch prover 同语义）。
        // P2-M4/M3：请求成功时构建公开段（16 felt，9 人桌），按
        // STARKNET_DAPV_SETTLE_ENTRY 选择 settle 入口（v2 默认 / proved_private）。
        // entry=combined：v2 段不直接上链——只作为 prove_combined 的 settle
        // 语句真源，上链段 = 证明公开输出（[chain_acc] ++ v2 段）。
        let mut proved_settle: Option<(&'static str, Vec<Felt>)> = None;
        let mut combined_output: Option<super::settlement_prover::CombinedProofOutput> = None;
        {
            // 本地模式无外部电路 prover：url 置空（configured=false），
            // 下面以 local_prover 为总门进段构建 + fact 直登。
            let settlement_prover =
                super::settlement_prover::HttpSettlementProver::new(if local_prover {
                    None
                } else {
                    chain.config.prover_url.clone()
                });
            if local_prover || settlement_prover.configured() || snip36_engaged || combined_engaged
            {
                match super::settlement_prover::prepare_request(
                    dual.hand_id,
                    dual.hand_binding,
                    players_remapped,
                    deltas,
                    dual.action_log_digest,
                    &dual.action_entries,
                )
                .await
                {
                    Ok(req) => {
                        super::settlement_prover::export_settlement_private_inputs(
                            &req,
                            std::path::Path::new(&chain.config.prover_work_dir),
                        );
                        if combined_engaged {
                            // combined 腿：证明先行——17 词段只能来自证明公开
                            // 输出（chain_acc 是证明内折叠值，本地拼不出）。
                            match prove_combined_segment(chain, &req, dual, combined_tasks).await {
                                Ok(out) => {
                                    let segment = out.public_output.to_vec();
                                    let (selector, calldata) = settle_entry_calldata(
                                        "combined",
                                        dual.hand_binding,
                                        dual.hand_id,
                                        &segment,
                                        dual.proved.p_batch_commitment,
                                        dual.proved.p_batch_len,
                                    );
                                    tracing::info!(
                                        "[dapv] settle entry = {selector} (combined segment {} felts, chain_acc {:#x}, steps {})",
                                        segment.len(),
                                        out.cairo_acc,
                                        out.steps
                                    );
                                    // fact 登记（operator 即 prover：证明由
                                    // operator spawn 的子进程出具，直登与 v2
                                    // dev-local 同语义）。失败即放弃 combined 腿
                                    // ——settle 的 fact 断言必拒，发出去必 revert。
                                    match local_register_combined_settlement_fact(&out).await {
                                        Ok(tx) => {
                                            tracing::info!(
                                                "[combined] settlement fact registered tx={tx}"
                                            );
                                            proved_settle = Some((selector, calldata));
                                            combined_output = Some(out);
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                "[combined] fact registration failed: {e} — combined leg aborted, falling back"
                                            );
                                        }
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    "[combined] envelope proof failed: {e} — falling back (v2/linear)"
                                ),
                            }
                        } else {
                            let segment = req.public_segment_felts();
                            let (selector, calldata) = settle_entry_calldata(
                                chain.config.dapv_settle_entry(),
                                dual.hand_binding,
                                dual.hand_id,
                                &segment,
                                dual.proved.p_batch_commitment,
                                dual.proved.p_batch_len,
                            );
                            tracing::info!(
                                "[dapv] settle entry = {selector} (segment {} felts)",
                                segment.len()
                            );
                            proved_settle = Some((selector, calldata));
                        }
                        if local_prover && !combined_engaged {
                            match local_register_settlement_fact(&req).await {
                                Ok(tx) => tracing::info!(
                                    "[settlement-private] dev local attestation (no STARK proof) — fact registered tx={tx}"
                                ),
                                Err(e) => tracing::warn!(
                                    "[settlement-private] local fact registration failed (non-fatal): {e}"
                                ),
                            }
                        } else if settlement_prover.configured() && !combined_engaged {
                            match settlement_prover.prove_settlement_private(&req).await {
                                Ok(att) => tracing::info!(
                                    "[settlement-private] attested (program {})",
                                    att.program_hash
                                ),
                                Err(e) => tracing::warn!(
                                    "[settlement-private] prover attestation failed (non-fatal): {e}"
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[settlement-private] request build failed (non-fatal): {e}")
                    }
                }
            }
        }
        let workload = ProverWorkload {
            hand_binding: dual.hand_binding,
            hand_id: dual.hand_id,
            batch_words: dual.batch_words.clone(),
            p_batch_commitment: dual.proved.p_batch_commitment,
        };
        let mut resolved = if local_prover {
            tracing::info!("[dapv-proved] local prover mode — batch attestation in-process");
            resolve_settle_mode_with_prover(&LocalBatchProver, &workload).await
        } else {
            let prover = HttpBatchProver::new(chain.config.prover_url.clone());
            resolve_settle_mode_with_prover(&prover, &workload).await
        };
        // Proved 结算依赖公开段——构建失败（赢家 payout commitment 缺失等）
        // 则降级 linear，绝不发不完整 calldata。v2/proved_private 均同此门。
        match proved_settle {
            Some((selector, _)) if resolved == SettleMode::Proved => tracing::info!(
                "[dapv-proved] table settling via {selector} (commitment {:#x}, {} words)",
                dual.proved.p_batch_commitment,
                dual.proved.p_batch_len
            ),
            Some(_) => {}
            None => {
                if resolved == SettleMode::Proved {
                    tracing::warn!(
                        "[dapv-proved] settlement segment unavailable — falling back to linear"
                    );
                    resolved = SettleMode::Linear;
                }
            }
        }
        // entry=snip36：公开段就绪即视为 Proved（协议内 SNOS 证明承载证明）；
        // batch attestation 保持观测性输出，不作门槛。
        // entry=combined：证明 + fact 登记落地（proved_settle 挂上）才视为
        // Proved——combined 证明本身就是 fact 的凭证，不再依赖 batch
        // attestation（P-batch 走线性兜底路径）。
        if (snip36_engaged || combined_engaged) && proved_settle.is_some() {
            resolved = SettleMode::Proved;
        }
        (resolved, proved_settle, combined_output)
    } else {
        (SettleMode::Linear, None, None)
    };
    let (mode, proved_settle, combined_output) = mode;

    // Part A Phase 1：STARKNET_SETTLE_PRIVATE=true 时走隐私结算入口
    // （赢家派奖进认领托管而非公开 chip 余额；输家仍公开扣款）。
    // 前置条件：所有赢家已在 vault 注册 payout commitment——未齐则自动
    // 回退 legacy 入口（下一手再试），绝不因缺注册而卡死结算。
    let settle_private = std::env::var("STARKNET_SETTLE_PRIVATE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let use_private = settle_private && winners_registered(players_remapped, deltas).await;

    let mut snip36_fallback_linear = false;
    let (mut register_selector, mut register_calldata, mut settle_selector, mut settle_calldata) =
        match mode {
            SettleMode::Proved => {
                let (selector, calldata) = proved_settle.clone().unwrap_or_else(|| {
                    // 上面的 segment 门保证 Proved 时必有 calldata；
                    // 兜底空集（链上会拒绝），不静默改道。
                    ("verify_and_settle_dapv_stark_private_v2", Vec::new())
                });
                (
                    "register_hand_proved",
                    dual.proved.register_calldata.clone(),
                    selector,
                    calldata,
                )
            }
            SettleMode::Linear => (
                "register_hand",
                dual.register_calldata.clone(),
                if use_private {
                    "verify_and_settle_dapv_stark_private"
                } else {
                    "verify_and_settle_dapv_stark"
                },
                dual.settle_calldata.clone(),
            ),
        };

    // ===== SNIP-36 在线腿（§5 #4 服务内自动接线）=====
    //
    // entry=snip36 且 Proved：先走协议内证明提交（create_proof 交易 → 自托管
    // prover → 携带 proof/proof_facts 的 v3 原始广播）；任何失败（prover 未
    // 部署/拒绝、服务忙、链上拒收）都回退 v2 fact-registry 腿——同一份
    // calldata，绝不卡结算。回退的前提是 fact 已由证明运营侧登记。
    if mode == SettleMode::Proved
        && chain.config.dapv_settle_entry() == "snip36"
        && proved_settle.is_some()
    {
        // 0) 注册先行（txmgr 发送面）：create_proof / v3 的公开段断言读
        //    已注册 digest——register 独立成笔（公开），已注册则幂等吞掉
        //    （重放分类归 txmgr replay.rs）。回执包含 = 注册落地（旧 45s
        //    view 轮询已由回执判据取代）。
        {
            let mgr = super::submit::build_txmgr(txmgr_send.clone());
            let call = starknet_txmgr::Call {
                to: contract,
                selector: starknet_keccak(b"register_hand"),
                calldata: dual.register_calldata.clone(),
            };
            match mgr
                .submit_ordered(account_felt, "register_hand", vec![call])
                .await
            {
                Ok(starknet_txmgr::SendOutcome::Receipted(r)) => {
                    tracing::info!("[snip36] register_hand tx={:#x}", r.tx_hash)
                }
                Ok(starknet_txmgr::SendOutcome::IdempotentReplay(
                    starknet_txmgr::ReplayVerdict::RegisterReplay,
                )) => tracing::info!("[snip36] register_hand already done"),
                Ok(starknet_txmgr::SendOutcome::IdempotentReplay(_)) => {
                    // settle 相文案（Hand already settled）：文案原样上抛，
                    // 由调用方（hooks 的幂等重放分支）按已结算收尾。
                    return Err("[snip36] register_hand failed: Hand already settled".into());
                }
                Err(e) => return Err(format!("[snip36] register_hand failed: {e}")),
            }
        }
        // 1-2) 两笔 SNIP-36 提交：create_proof（不广播）→ 自托管 prover
        //      虚拟执行出证（实测 ≈2 分钟）→ v3 结算携 proof/proof_facts。
        //      证明期间 create/v3 共用同一 nonce 且不可加速——并发 operator
        //      提交会让 proved 交易被拒，此时回退公开线性腿，结算恒可落地。
        match try_snip36_submit(chain, settle_calldata.clone()).await {
            Ok(hash) => {
                tracing::info!("[snip36] in-protocol proved settle submitted tx={hash}");
                // 赢额重锁不进 v3 交易：单笔 best-effort 跟进（离桌释放与
                // 续钟由调用方收尾：flush_leave_releases + refresh）。
                if let Some(vault) = super::chain::parse_felt(&chain.config.vault_address) {
                    let treasury = chain.config.treasury_address.to_lowercase();
                    let mut calls = Vec::new();
                    for (p, d) in players_remapped.iter().zip(deltas.iter()) {
                        if *d <= 0 {
                            continue;
                        }
                        let wallet = super::lock::wallet_of_felt(p);
                        if wallet == treasury {
                            continue;
                        }
                        if let Some(wei) = (*d as i128)
                            .checked_mul(super::config::WEI_PER_CHIP as i128)
                            .and_then(|w| u128::try_from(w).ok())
                        {
                            let (lo, hi) = super::lock::wei_to_u256_felts(wei);
                            calls.push(Call {
                                to: vault,
                                selector: starknet_keccak(b"lock"),
                                calldata: vec![*p, lo, hi],
                            });
                        }
                    }
                    if !calls.is_empty() {
                        let n_calls = calls.len();
                        match operator.execute_v3(calls).send().await {
                            Ok(r) => tracing::info!(
                                "[snip36] post-settle win-relock tx={:#x} ({} calls)",
                                r.transaction_hash,
                                n_calls
                            ),
                            Err(e) => tracing::warn!(
                                "[snip36] post-settle win-relock failed (non-fatal): {e}"
                            ),
                        }
                    }
                }
                return Ok((hash.clone(), hash));
            }
            Err(e) => {
                tracing::warn!(
                    "[snip36] in-protocol submit failed ({e}) — falling back to public linear leg"
                );
                // 主网 fact-registry 未登记事实：v2 私密腿的 fact 断言必拒。
                // 回退必须走公开线性 bundle（register 已落，bundle 内
                // "already registered" 重试会吸收），结算恒可落地。
                snip36_fallback_linear = true;
            }
        }
    }

    // ===== 线性模式原子编排（2026-09-07 设计裁定，零合约改动）=====
    //
    // operator = vault owner = settlement prover：单笔 __execute__ 多调用
    // 按序执行、共享状态、整体回滚。把 register → settle → 赢额回锁 →
    // 续钟 → 离桌释放串进同一笔交易：
    // - 注册对结算可见（省掉两步提交的落地轮询）；
    // - 赢额回锁与结算原子落地（消除"结算落地→回锁落地"的异步逃单窗口）；
    // - 离桌玩家的 force_unlock 随最后一手结算同笔释放。
    // SNIP-36 在线腿失败（prover 拒绝/超时/链上拒收）时的公开线性兜底：
    // register 用线性 register_hand（已注册则 bundle 内重试吸收），settle
    // 用公开 verify_and_settle_dapv_stark——恒可落地，与 entry=v2 等价。
    if snip36_fallback_linear {
        register_selector = "register_hand";
        register_calldata = dual.register_calldata.clone();
        settle_selector = "verify_and_settle_dapv_stark";
        settle_calldata = dual.settle_calldata.clone();
    }

    // 任一子调用 revert 则整笔 revert——回锁/续钟只对确有 session/余额
    // 的玩家追加，避免无关断言拖垮结算。
    if mode == SettleMode::Linear || snip36_fallback_linear {
        let vault = super::chain::parse_felt(&chain.config.vault_address)
            .ok_or("invalid vault address in config")?;
        let treasury = chain.config.treasury_address.to_lowercase();
        // （Call 类型换 txmgr 载体——同一 Felt 实例，calldata 构建不动。）
        let register_call = starknet_txmgr::Call {
            to: contract,
            selector: starknet_keccak(register_selector.as_bytes()),
            calldata: register_calldata,
        };
        let settle_call = starknet_txmgr::Call {
            to: contract,
            selector: starknet_keccak(settle_selector.as_bytes()),
            calldata: settle_calldata,
        };
        let mut calls = vec![settle_call];
        let mut notes: Vec<&'static str> = Vec::new();
        // 赢额回锁（treasury/rake 不锁——无 session，锁了只会造出假时钟）。
        for (p, d) in players_remapped.iter().zip(deltas.iter()) {
            if *d <= 0 {
                continue;
            }
            let wallet = super::lock::wallet_of_felt(p);
            if wallet == treasury {
                continue;
            }
            let Some(wei) = (*d as i128)
                .checked_mul(super::config::WEI_PER_CHIP as i128)
                .and_then(|w| u128::try_from(w).ok())
            else {
                continue;
            };
            let (lo, hi) = super::lock::wei_to_u256_felts(wei);
            calls.push(starknet_txmgr::Call {
                to: vault,
                selector: starknet_keccak(b"lock"),
                calldata: vec![*p, lo, hi],
            });
            notes.push("win-relock");
        }
        // 续钟不进 bundle：vault_session_active 检查与链上执行之间存在
        // 竞态，"No active session" 断言会让整笔原子结算回滚（2026-09-08
        // hand 1788812613 线上：结算丢失）。结算成功后由 hooks 用
        // invoke_vault（带重试、失败仅告警）逐个续钟。
        // 离桌释放（force_unlock 无断言，空锁调用只是写零）。
        for w in departed {
            if let Some(f) = super::chain::parse_felt(w) {
                calls.push(starknet_txmgr::Call {
                    to: vault,
                    selector: starknet_keccak(b"force_unlock"),
                    calldata: vec![f],
                });
                notes.push("leave-release");
            }
        }
        // 注册先行：同笔内顺序执行，settle 看得到注册写入。
        let mut attempts = vec![{
            let mut c = vec![register_call.clone()];
            c.extend(calls.iter().cloned());
            c
        }];
        // 过渡兼容：老两步流程可能已把 register 落地而 settle 未成——
        // 整笔因 "already registered" revert 时，去掉 register 重发。
        attempts.push(calls.clone());
        let mut last_err = String::new();
        // nonce 竞态退避重试：相邻两手（或结算与离桌释放）并发提交时，
        // 后一笔按旧 nonce 构建会被内存池拒（不上链不花 gas）——2026-09-07
        // 线上：hand 1788803579 结算因此永久丢失，随 bundle 的离桌释放
        // 一并滞留。txmgr 内层按同 nonce 加价重发；竞态仍未消解时外层
        // 重建（新基线 nonce）退避重试，等对方交易落地即可成功。
        const MAX_NONCE_RETRIES: u32 = 5;
        const NONCE_RETRY_BACKOFF_SECS: u64 = 4;
        'bundle: for (i, bundle) in attempts.iter().enumerate() {
            let mut nonce_try = 1u32;
            loop {
                // 每次尝试独立 TxManager：基线 nonce 链上现查（重放决议
                // 不消耗 nonce，不留空洞；nonce 竞态后取新基线重发）。
                let mgr = super::submit::build_txmgr(txmgr_send.clone());
                let tag = if i == 0 {
                    "settle-bundle"
                } else {
                    "settle-bundle-no-register"
                };
                match mgr.submit_ordered(account_felt, tag, bundle.clone()).await {
                    Ok(starknet_txmgr::SendOutcome::Receipted(r)) => {
                        let hash = format!("{:#x}", r.tx_hash);
                        tracing::info!(
                            "[dapv] atomic settle bundle (register+settle+{} extras: {}) tx={hash}",
                            notes.len(),
                            notes
                                .iter()
                                .fold(
                                    std::collections::HashMap::<&'static str, usize>::new(),
                                    |mut m, n| {
                                        *m.entry(n).or_default() += 1;
                                        m
                                    }
                                )
                                .iter()
                                .map(|(k, v)| format!("{k}x{v}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                        return Ok((hash.clone(), hash));
                    }
                    // 已结算（Hand already settled）：幂等成功收尾。
                    Ok(starknet_txmgr::SendOutcome::IdempotentReplay(
                        starknet_txmgr::ReplayVerdict::SettleReplay,
                    )) => {
                        return Ok(("already-settled".to_string(), "already-settled".to_string()));
                    }
                    // bundle 内 register 是首个调用，整笔估计失败于注册相
                    //（already registered）——去掉 register 重发（下一组）。
                    Ok(starknet_txmgr::SendOutcome::IdempotentReplay(
                        starknet_txmgr::ReplayVerdict::RegisterReplay,
                    )) => {
                        last_err = "already registered".to_string();
                        continue 'bundle;
                    }
                    // txmgr 不产生该组合（NotReplay 不以幂等语义返回）。
                    Ok(starknet_txmgr::SendOutcome::IdempotentReplay(
                        starknet_txmgr::ReplayVerdict::NotReplay,
                    )) => {
                        return Err("atomic settle bundle failed: not-replay invariant".to_string());
                    }
                    Err(starknet_txmgr::TxError::Broadcast { last, .. }) => {
                        if super::lock::is_nonce_race(&last) && nonce_try < MAX_NONCE_RETRIES {
                            tracing::warn!(
                                "[dapv] settle bundle nonce race (variant {i}, try {nonce_try}/{MAX_NONCE_RETRIES}) — backing off {NONCE_RETRY_BACKOFF_SECS}s"
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(
                                NONCE_RETRY_BACKOFF_SECS,
                            ))
                            .await;
                            nonce_try += 1;
                            continue; // 同一 bundle 新基线重发
                        }
                        return Err(format!("atomic settle bundle failed: {last}"));
                    }
                    Err(e) => return Err(format!("atomic settle bundle failed: {e}")),
                }
            }
        }
        // 第二组也报注册相重放：结算早已完整落地——按幂等成功处理
        //（txmgr replay 分类替代旧文案匹配）。
        if starknet_txmgr::classify_execution_error(&last_err)
            != starknet_txmgr::ReplayVerdict::NotReplay
        {
            return Ok(("already-settled".to_string(), "already-settled".to_string()));
        }
        return Err(format!("atomic settle bundle failed: {last_err}"));
    }

    // ===== Proved 模式：两步提交（txmgr 发送面；rollup-components 条目 2）=====
    // register 腿回执包含 = 注册落地（旧 hand_binding view 的 45s 轮询已由
    // 回执判据取代）；重放文案由 txmgr replay.rs 分类（SettleReplay → 幂等
    // 成功 "already-settled"——旧实现上抛错误文案、由 hooks 的
    // is_already_settled_error 分支收尾，两路径等价）。
    let (register_hash, settle_hash) = super::submit::drive_two_leg_settlement(
        txmgr_send,
        account_felt,
        starknet_txmgr::Call {
            to: contract,
            selector: starknet_keccak(register_selector.as_bytes()),
            calldata: register_calldata,
        },
        starknet_txmgr::Call {
            to: contract,
            selector: starknet_keccak(settle_selector.as_bytes()),
            calldata: settle_calldata,
        },
        register_selector,
        settle_selector,
    )
    .await?;

    // combined 腿：settle 拿到**成功回执**后推进 acc 链状态（原子写）。
    // 信任边界（如实声明）：txmgr 回执 = 交易已入块——比旧 `.send()` 接受
    // 即推进更强；若节点丢弃后重放仍落空（理论不可达），恢复手段 = 从
    // DualProofSettledCombined 事件重放对账。并发两手同时结算时 acc 状态
    // 文件存在同类竞态——生产应单 operator 串行结算（现状即如此）。
    if let Some(out) = combined_output {
        match write_combined_acc(out.cairo_acc) {
            Ok(()) => tracing::info!(
                "[combined] acc chain advanced to {:#x} (state file)",
                out.cairo_acc
            ),
            Err(e) => tracing::warn!(
                "[combined] acc state persist failed (next hand folds from stale acc): {e}"
            ),
        }
    }

    Ok((register_hash, settle_hash))
}

// ============================================================
// Plan D P2：BG 洗牌可折叠方程（felt 直通 Poseidon transcript 纪元）
//
// 给定一条在 PoseidonFeltTranscript 上证明的诚实
// BayerGrothShuffleProof<StarkCurve>，把 verify() 的全部点校验分解为
// 纯线性方程（每条 = Σ scalar_i · point_i = O，负系数表达减项）+ 两条
// 纯标量校验。Cairo 端只需：重放 transcript 取挑战 → 从公开词重建
// 方程组 → ρ 折叠单点校验。
// ============================================================

/// BG 承诺密钥（与 poker-protocol-bg/src/proof.rs::CommitmentKey 同派生：
/// h = hash_to_curve("poker/bg12/v2/H")，CK_i =
/// hash_to_curve("poker/bg12/v2/G/{n}/{i}")）——公开词，Cairo 端作为
/// 常量钉死（见 /tmp/bgvectors/ck_n52.txt）。
pub struct BgCommitmentKey {
    pub h: Pt,
    pub generators: Vec<Pt>,
}

impl BgCommitmentKey {
    pub fn derive(n: usize) -> BgCommitmentKey {
        let h = <StarkCurve as Curve>::hash_to_curve(b"poker/bg12/v2/H");
        let generators = (0..n)
            .map(|i| {
                <StarkCurve as Curve>::hash_to_curve(format!("poker/bg12/v2/G/{n}/{i}").as_bytes())
            })
            .collect();
        BgCommitmentKey { h, generators }
    }
}

/// 一条线性点方程：Σ (scalar_i · point_i) = O（负 scalar 表减项）。
pub type LinearTerms = Vec<(Sc, Pt)>;

/// 方程残差（lhs 求和；诚实证明 = 恒等点 O）。
pub fn linear_residual(terms: &LinearTerms) -> Pt {
    terms
        .iter()
        .map(|(s, p)| *p * *s)
        .fold(<Pt as CurvePoint>::identity(), |acc, t| acc + t)
}

/// BG 方程组 + 派生挑战 + 两条标量校验的公开中间量。
/// （挑战中间量 ck/x/y/z/e/q 的字段在验证主路径不读——它们已折进
/// equations 的系数；但 Cairo 金向量导出（tests 的 transcript replay）
/// 逐个读取，保留为导出 schema。）
#[allow(dead_code)]
pub struct BgShuffleEquations {
    pub ck: BgCommitmentKey,
    /// transcript 派生挑战：x（powers）、y、z、e（mexp）、q（product）。
    pub powers_challenge: Sc,
    pub product_y: Sc,
    pub product_z: Sc,
    pub mexp_challenge: Sc,
    pub product_challenge: Sc,
    /// E1（2 条）+ E2 + E3 + E4（2 条）+ E5 + E6，共 8 条线性方程
    ///（顺序：E1a, E1b, E2, E3, E4a, E4b, E5, E6）。
    pub equations: Vec<LinearTerms>,
    /// 标量校验 1：b_response[0] == a_response[0]。
    pub scalar_check_1: bool,
    /// 标量校验 2：b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)。
    pub scalar_check_2: bool,
}

use poker_protocol::zk_shuffle::bayer_groth::{
    BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
};

/// BG 验证 transcript 上的非零挑战（与 proof.rs::challenge_nonzero 同
/// 重采样语义；poseidon 输出为零的概率 ≈ 2^-251，循环仅为语义对齐）。
fn challenge_nonzero_stark(
    transcript: &mut poker_protocol_core::PoseidonFeltTranscript,
    label: &[u8],
) -> Sc {
    use poker_protocol_core::CryptoTranscript as _;
    let mut challenge = transcript.challenge::<StarkCurve>(label).scalar;
    let mut counter = 0u32;
    while challenge == <Sc as CurveScalar>::zero() {
        transcript.append_message(b"bg12_zero_challenge_retry", &counter.to_le_bytes());
        challenge = transcript.challenge::<StarkCurve>(label).scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

/// 从公开词重放 BG 验证 transcript（与 poker-protocol-bg/src/proof.rs
/// verify() 的 append 顺序逐字节一致），返回五个挑战
/// (x=powers, y, z, e=mexp, q=product)。
pub fn bg_replay_challenges(
    input: &[poker_protocol_core::StarkElGamalCiphertext],
    output: &[poker_protocol_core::StarkElGamalCiphertext],
    pk: &Pt,
    proof: &BayerGrothShuffleProof<StarkCurve>,
    transcript: &mut poker_protocol_core::PoseidonFeltTranscript,
) -> (Sc, Sc, Sc, Sc, Sc) {
    use poker_protocol_core::CryptoTranscript as _;
    let mexp = &proof.multi_exponentiation;

    transcript.append_message(b"bg12_protocol", b"poker/bayer-groth-shuffle/v2");
    transcript.append_message(b"bg12_deck_size", &(input.len() as u64).to_le_bytes());
    transcript.append_point::<StarkCurve>(b"bg12_public_key", pk);
    for (label, cts) in [(b"input" as &[u8], input), (b"output" as &[u8], output)] {
        for ct in cts {
            transcript.append_message(b"bg12_ciphertext_label", label);
            transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c1", &ct.c1);
            transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c2", &ct.c2);
        }
    }
    transcript.append_point::<StarkCurve>(b"bg12_c_permutation", &proof.c_permutation);
    let x = challenge_nonzero_stark(transcript, b"bg12_powers_challenge");
    transcript.append_point::<StarkCurve>(b"bg12_c_permuted_powers", &proof.c_permuted_powers);
    let y = challenge_nonzero_stark(transcript, b"bg12_product_y");
    let z = challenge_nonzero_stark(transcript, b"bg12_product_z");

    transcript.append_point::<StarkCurve>(b"bg12_mexp_c_alpha", &mexp.c_alpha);
    transcript.append_point::<StarkCurve>(b"bg12_mexp_c_beta", &mexp.c_beta);
    for (label, ct) in [
        (b"mexp_0", &mexp.ciphertext_0),
        (b"mexp_1", &mexp.ciphertext_1),
    ] {
        transcript.append_message(b"bg12_ciphertext_label", label);
        transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c1", &ct.c1);
        transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c2", &ct.c2);
    }
    let e = challenge_nonzero_stark(transcript, b"bg12_mexp_challenge");

    let product = &proof.product;
    transcript.append_point::<StarkCurve>(b"bg12_product_c_d", &product.c_d);
    transcript.append_point::<StarkCurve>(b"bg12_product_c_delta", &product.c_delta);
    transcript
        .append_point::<StarkCurve>(b"bg12_product_c_capital_delta", &product.c_capital_delta);
    let q = challenge_nonzero_stark(transcript, b"bg12_product_challenge");

    (x, y, z, e, q)
}

/// 把一条（诚实或待检的）BG 证明分解为线性方程组 + 标量校验。
///
/// 方程（均以残差 Σ scalar·point = O 表达，符号从 proof.rs verify()
/// 的 lhs−rhs 逐条推出）：
/// - E1（2 条）：msm(input, x^i) − ciphertext_1 = O（c1 与 c2 各一条）
/// - E2：e·c_permuted_powers + c_alpha − vc(alpha_resp, commit_resp)
/// - E3：c_beta − G·beta − CK_h·beta_blinding_response = O
/// - E4（2 条）：ciphertext_0 + e·ciphertext_1 − (G·τ +
///   msm(output, alpha_response)) = O（c1 侧）；c2 侧再 − G·beta − pk·τ
/// - E5：c_d + q·(y·c_perm + c_ppow) − q·z·S − vc(a_resp, r_resp)，
///   其中 c_minus_z = Σ(−z)·CK_i 因式为均匀标量 −z 乘 S = Σ CK_i
///   （CK 钉死常量，S 由程序内 52 次点加预计算，代数恒等）
/// - E6：c_delta + q·c_capital_delta − vc(recurrence, s_resp)，
///   recurrence_i = q·b_{i+1} − b_i·a_{i+1}（i<n−1），
///   recurrence_{n−1} = 0
///
/// 注意：E2/E5/E6 **不做** λ-批量合并（历史教训，见函数体内注释）：
/// 共享 λ 等价于检验裸和 E2+E5+E6，可被分量相消攻破；独立 λ 在
/// Cairo 成本模型下（fr_mul ≈ 12× EC 点乘）反而净亏。
pub fn bg_shuffle_fold_equations(
    input: &[poker_protocol_core::StarkElGamalCiphertext],
    output: &[poker_protocol_core::StarkElGamalCiphertext],
    pk: &Pt,
    proof: &BayerGrothShuffleProof<StarkCurve>,
) -> BgShuffleEquations {
    let n = input.len();
    let ck = BgCommitmentKey::derive(n);
    let mut tr = poker_protocol_core::PoseidonFeltTranscript::new_bg_fold();
    let (x, y, z, e, q) = bg_replay_challenges(input, output, pk, proof, &mut tr);
    let mexp = &proof.multi_exponentiation;
    let product = &proof.product;
    let g = StarkCurve::base_g();
    let one = <Sc as CurveScalar>::one();

    // 公开幂 x^1..x^n
    let mut powers = Vec::with_capacity(n);
    let mut cur = x;
    for _ in 0..n {
        powers.push(cur);
        cur = cur * x;
    }

    // S = Σ_i CK_i（均匀标量因式化的基；CK 为钉死常量，S 程序内
    // 52 次点加预计算，Rust/Cairo 一致）。
    let s_sum = ck
        .generators
        .iter()
        .fold(<Pt as CurvePoint>::identity(), |acc, p| acc + *p);

    let mut equations: Vec<LinearTerms> = Vec::with_capacity(8);

    // E1：Σ x^{i+1}·input_i − ciphertext_1 = O（c1 / c2）
    for side in [0usize, 1] {
        let mut terms: LinearTerms = input
            .iter()
            .zip(powers.iter())
            .map(|(ct, p)| {
                let pt = if side == 0 { ct.c1 } else { ct.c2 };
                (*p, pt)
            })
            .collect();
        terms.push((
            -one,
            if side == 0 {
                mexp.ciphertext_1.c1
            } else {
                mexp.ciphertext_1.c2
            },
        ));
        equations.push(terms);
    }

    // E3：c_beta − G·beta − CK_h·beta_blinding_response = O
    equations.push(vec![
        (one, mexp.c_beta),
        (-mexp.beta, g),
        (-mexp.beta_blinding_response, ck.h),
    ]);

    // E4：ct0 + e·ct1 − (G·τ + Σ alpha_resp_i·output_i) = O
    //     ct0.c2 + e·ct1.c2 − (G·beta + pk·τ + Σ alpha_resp_i·output_i.c2) = O
    {
        let mut terms = vec![
            (one, mexp.ciphertext_0.c1),
            (e, mexp.ciphertext_1.c1),
            (-mexp.rerandomization_response, g),
        ];
        for (resp, ct) in mexp.alpha_response.iter().zip(output.iter()) {
            terms.push((-resp, ct.c1));
        }
        equations.push(terms);

        let mut terms = vec![
            (one, mexp.ciphertext_0.c2),
            (e, mexp.ciphertext_1.c2),
            (-mexp.beta, g),
            (-mexp.rerandomization_response, *pk),
        ];
        for (resp, ct) in mexp.alpha_response.iter().zip(output.iter()) {
            terms.push((-resp, ct.c2));
        }
        equations.push(terms);
    }

    // E2/E5/E6 **分开**验证（不做 λ-批量合并）。两个原因，写在这里
    // 防止将来重蹈：
    // 1. Soundness：共享单一 λ 的合并等价于检验 E2+E5+E6 = O——
    //    α_response/a_response 等都是证明者自由选取的公开词，E2/E5
    //    对它们线性，取 E2 残差 = P、E5 残差 = −P 即可精确相消；
    //    小指数批量验证需**独立**随机指数（λ₂,λ₅,λ₆）才成立。
    // 2. 成本：Cairo VM 里 mod-n 标量乘（fr_mul，u256 无 mul-mod
    //    builtin）每元素数千 step，而 EC 点乘走 EC_OP builtin
    //    ≈ 162 step——独立 λ 每元素 3 次 fr_mul，省下的 EC 点乘
    //    远 cover 不住（实测 λ 合并 +17% step-gas）。
    // E2：e·c_permuted_powers + c_alpha − vc(alpha_resp, commit_resp)
    equations.push({
        let mut terms: LinearTerms = mexp
            .alpha_response
            .iter()
            .zip(ck.generators.iter())
            .map(|(a, ck_i)| (-*a, *ck_i))
            .collect();
        terms.push((e, proof.c_permuted_powers));
        terms.push((one, mexp.c_alpha));
        terms.push((-mexp.commitment_response, ck.h));
        terms
    });
    // E5：c_d + q·(y·c_perm + c_ppow) − q·z·S − vc(a_resp, r_resp)。
    // 均匀标量因式化：c_minus_z = Σ(−z)·CK_i = −z·S（S = Σ CK_i，
    // 52 次点加预计算，代数恒等）。
    equations.push({
        let mut terms: LinearTerms = product
            .a_response
            .iter()
            .zip(ck.generators.iter())
            .map(|(a, ck_i)| (-*a, *ck_i))
            .collect();
        terms.push((one, product.c_d));
        terms.push((q * y, proof.c_permutation));
        terms.push((q, proof.c_permuted_powers));
        terms.push((-(q * z), s_sum));
        terms.push((-product.r_response, ck.h));
        terms
    });
    // E6：c_delta + q·c_capital_delta − vc(recurrence, s_resp)
    equations.push({
        // recurrence_i = q·b_{i+1} − b_i·a_{i+1}（i < n−1），否则 0
        let mut recurrence = vec![<Sc as CurveScalar>::zero(); n];
        for i in 0..n.saturating_sub(1) {
            recurrence[i] =
                q * product.b_response[i + 1] - product.b_response[i] * product.a_response[i + 1];
        }
        let mut terms: LinearTerms = recurrence
            .iter()
            .zip(ck.generators.iter())
            .map(|(r, ck_i)| (-*r, *ck_i))
            .collect();
        terms.push((one, product.c_delta));
        terms.push((q, product.c_capital_delta));
        terms.push((-product.s_response, ck.h));
        terms
    });

    // 标量校验 2：b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)
    let expected_product = powers
        .iter()
        .enumerate()
        .map(|(i, &xp)| y * <Sc as CurveScalar>::from_u64(i as u64 + 1) + xp - z)
        .fold(one, |acc, v| acc * v);

    BgShuffleEquations {
        ck,
        powers_challenge: x,
        product_y: y,
        product_z: z,
        mexp_challenge: e,
        product_challenge: q,
        equations,
        scalar_check_1: product.b_response[0] == product.a_response[0],
        scalar_check_2: product.b_response[n - 1] == q * expected_product,
    }
}

/// 线性方程组的 ρ 折叠宿主 parity（与 host_fold_check 同 Horner 结构；
/// BG 方程 kind=5 词绑定）。诚实方程组残差逐条为恒等，折叠亦必为恒等。
#[cfg(test)]
pub fn host_fold_check_linear(hand_binding: &[u8; 32], equations: &[LinearTerms]) -> bool {
    if equations.is_empty() {
        return false;
    }
    let residuals: Vec<Pt> = equations.iter().map(linear_residual).collect();
    let words: Vec<poker_protocol_core::stark_curve::HandBatchEquationWords> = equations
        .iter()
        .map(
            |_| poker_protocol_core::stark_curve::HandBatchEquationWords {
                kind: 5,
                s: [0u8; 32],
                c: [0u8; 32],
            },
        )
        .collect();
    let rho = poker_protocol_core::stark_curve::handbatch_rho(hand_binding, &words);
    let mut acc = residuals[residuals.len() - 1];
    for eq in residuals[..residuals.len() - 1].iter().rev() {
        acc = acc * rho + *eq;
    }
    acc.is_identity()
}
#[cfg(test)]
mod stark_endorsement_tests {
    use super::*;

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    fn mint_batch(hand_id_bytes: [u8; 32], count: usize) -> Vec<[u8; 32]> {
        let mut words = vec![
            u256_word(count as u64),
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(0),
        ];
        for _ in 0..count {
            let sk = random_scalar();
            let pk = StarkCurve::base_g() * sk;
            let endorsement = mint_endorsement(&sk, &pk, &hand_id_bytes);
            let (pk_x, pk_y) = point_xy(&endorsement.pk);
            let (r_x, r_y) = point_xy(&endorsement.r);
            words.push(pk_x);
            words.push(pk_y);
            words.push(r_x);
            words.push(r_y);
            words.push(scalar_be(&endorsement.s));
        }
        words
    }

    #[test]
    fn stark_endorsement_batch_folds_to_identity() {
        let hand_id = [0x42u8; 32];
        let words = mint_batch(hand_id, 3);
        let equations = parse_batch_terms(&hand_id, &words).expect("well-formed batch parses");
        assert_eq!(equations.len(), 3, "3 ownership equations");
        assert!(
            host_fold_check(&hand_id, &equations),
            "honest batch must fold to the identity point (Horner)"
        );
    }

    #[test]
    fn tampered_scalar_breaks_fold() {
        let hand_id = [0x43u8; 32];
        let mut words = mint_batch(hand_id, 2);
        // 篡改最后一个认可标量：s += 1
        let last = words.len() - 1;
        let mut s = words[last];
        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        for i in (0..32).rev() {
            let (sum, carry) = (s[i] as u16 + one[i] as u16, s[i] as u16 + one[i] as u16);
            let _ = sum;
            let _ = carry;
            break;
        }
        // 直接逐字节加一（小端进位简化：仅最低字节 +1，溢出忽略——测试用）
        s[31] = s[31].wrapping_add(1);
        words[last] = s;
        let terms = parse_batch_terms(&hand_id, &words).expect("shape still parses");
        assert!(
            !host_fold_check(&hand_id, &terms),
            "a tampered endorsement scalar must not fold to identity"
        );
    }

    #[test]
    fn cross_hand_replay_is_rejected() {
        // hand A 域铸造的认可批次，放进 hand B 的解析域：挑战 c 因域分离
        // 而不同，折叠必非恒等（§9-L2 hand-bound 语义）。
        let hand_a = [0xAAu8; 32];
        let hand_b = [0xBBu8; 32];
        let words = mint_batch(hand_a, 2);
        let terms = parse_batch_terms(&hand_b, &words).expect("shape parses under any domain");
        assert!(
            !host_fold_check(&hand_b, &terms),
            "endorsements minted for hand A must not fold under hand B's domain"
        );
    }

    #[test]
    fn off_curve_payload_point_is_rejected() {
        // 非曲线 (x, y)：y 取一个大概率不满足 y² = x³ + x + β 的值
        let x = starknet_types_core::felt::Felt::from(7u64);
        let bad_y = starknet_types_core::felt::Felt::from(7u64);
        assert!(
            point_from_words(&x.to_bytes_be(), &bad_y.to_bytes_be()).is_none(),
            "off-curve payload coordinates must be rejected at parse time"
        );
        // 曲线上的点必须接受
        let pk = StarkCurve::base_g() * random_scalar();
        let (gx, gy) = point_xy(&pk);
        assert!(
            point_from_words(&gx, &gy).is_some(),
            "on-curve point accepted"
        );
    }

    #[test]
    fn reveal_commitment_label_and_felt_chunks_are_stable() {
        // 域分隔标签确定性
        let l1 = handbatch_reveal_commit_label();
        let l2 = handbatch_reveal_commit_label();
        assert_eq!(l1, l2);
        // 31 字节分块：65 字节 → 3 块（31+31+3），无截断
        let bytes: Vec<u8> = (0..65u8).collect();
        let felts = bytes_as_felts(&bytes);
        assert_eq!(felts.len(), 3);
        // 确定性
        assert_eq!(bytes_as_felts(&bytes), felts);
    }
}

#[cfg(test)]
mod stark_vector_gen {
    use super::*;

    /// 生成 hand_batch_stark.cairo 的测试向量（运行：
    /// cargo +nightly test -p texas print_stark_batch_vector -- --ignored --nocapture）
    #[test]
    #[ignore = "vector generator: prints cairo literal"]
    fn print_stark_batch_vector() {
        print_stark_batch_vector_n(2, "print_stark_batch_vector_n2");
        print_stark_batch_vector_n(4, "print_stark_batch_vector_n4");
    }

    fn print_stark_batch_vector_n(n: usize, label: &str) {
        // 首字节压到 < 0x08：hand_binding 是合法 felt（真实场景恒为
        // Poseidon 输出 < 2^251，天然满足；合成向量显式满足以免
        // host/合约对超域值的归约解释分叉）。
        let mut hand_id = [0x5Bu8; 32];
        hand_id[0] = 0x02;
        let mut words = vec![
            u256_word(n as u64),
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(0),
        ];
        for i in 0..n as u64 {
            let sk = <Sc as CurveScalar>::from_u64(100 + i);
            let pk = StarkCurve::base_g() * sk;
            let e = mint_endorsement(&sk, &pk, &hand_id);
            let (pk_x, pk_y) = point_xy(&e.pk);
            let (r_x, r_y) = point_xy(&e.r);
            words.push(pk_x);
            words.push(pk_y);
            words.push(r_x);
            words.push(r_y);
            words.push(scalar_be(&e.s));
        }
        let terms = parse_batch_terms(&hand_id, &words).expect("parse");
        assert!(host_fold_check(&hand_id, &terms), "vector must fold");
        // hand_binding 的 felt 表示（Cairo 端测试直接引用）
        let binding_felt = bytes_to_field(&hand_id);
        println!("// {label}: hand_binding felt: {binding_felt:#x}");
        println!("// {label}: hand_id (32B):");
        print_cairo_u8_array(&hand_id);
        println!("// {label}: payload ({} felt252 words):", words.len());
        print_cairo_felt_array(&words);
    }

    /// leave-only 最小向量（隔离对照 host/Cairo）。
    #[test]
    #[ignore = "vector generator: leave-only"]
    fn print_leave_only() {
        use poker_protocol::crypto::curve::StarkCurve;
        let mut hand_binding = [0x5Bu8; 32];
        hand_binding[0] = 0x02;
        let g = StarkCurve::base_g();
        let lsk = <Sc as CurveScalar>::from_u64(9001);
        let l_pk = g * lsk;
        let omega = <Sc as CurveScalar>::from_u64(9002);
        let cpk = g * omega;
        let nonce = <Sc as CurveScalar>::from_u64(9003);
        // 1 张剥层卡（确定性）
        let msg = <StarkCurve as Curve>::hash_to_curve(b"leave-only/card-0");
        let r = <Sc as CurveScalar>::from_u64(9004);
        let ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
            &msg, &l_pk, &r,
        );
        let out_ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve> {
            c1: ct.c1,
            c2: ct.c2 - ct.c1 * lsk,
        };
        let a = ct.c1 * omega;
        let cards = vec![super::super::dual_settle::LeaveCardPts {
            in_c1: ct.c1,
            in_c2: ct.c2,
            out_c1: out_ct.c1,
            out_c2: out_ct.c2,
            a,
        }];
        let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards
            .iter()
            .map(|c| poker_protocol_core::stark_curve::HandLeaveCardWords {
                in_c1: c.in_c1,
                in_c2: c.in_c2,
                out_c1: c.out_c1,
                out_c2: c.out_c2,
                a: c.a,
            })
            .collect();
        let c = poker_protocol_core::stark_curve::handbatch_leave_challenge(
            &hand_binding,
            &l_pk,
            &cpk,
            &nonce,
            &card_words,
        );
        let s = omega + c * lsk;
        println!("// leave-only host c = 0x{}", {
            let b = c.as_bytes();
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        });
        let mut words = vec![
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(1),
            u256_word(0),
        ];
        words.push(u256_word(1));
        let (x, y) = point_xy(&l_pk);
        words.push(x);
        words.push(y);
        let (x, y) = point_xy(&cpk);
        words.push(x);
        words.push(y);
        let mut nb = [0u8; 32];
        nb.copy_from_slice(&nonce.as_bytes());
        words.push(nb);
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&s.as_bytes());
        words.push(sb);
        let (x, y) = point_xy(&ct.c1);
        words.push(x);
        words.push(y);
        let (x, y) = point_xy(&ct.c2);
        words.push(x);
        words.push(y);
        let (x, y) = point_xy(&out_ct.c1);
        words.push(x);
        words.push(y);
        let (x, y) = point_xy(&out_ct.c2);
        words.push(x);
        words.push(y);
        let (x, y) = point_xy(&a);
        words.push(x);
        words.push(y);
        let parsed = parse_batch_terms(&hand_binding, &words).expect("parse");
        assert!(
            host_fold_check(&hand_binding, &parsed),
            "leave-only must fold"
        );
        println!("// leave-only payload ({} words):", words.len());
        println!("        array![");
        for w in &words {
            println!("            0x{},", hex::encode(w));
        }
        println!("        ]");
    }

    fn print_cairo_u8_array(bytes: &[u8]) {
        println!("        array![");
        for chunk in bytes.chunks(12) {
            let items: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
            println!("            {},", items.join(", "));
        }
        println!("        ]");
    }

    fn print_cairo_felt_array(words: &[[u8; 32]]) {
        println!("        array![");
        for w in words {
            println!("            0x{},", hex::encode(w));
        }
        println!("        ]");
    }
}

// ============================================================
// Plan D P2 测试：reconstruct 折叠 + BG 线性方程组 + /tmp/bgvectors
// ============================================================
#[cfg(test)]
mod bg_fold_tests {
    use super::*;
    // 测试向量行的 hex 编码统一走 chain::hex_encode（小写、无前缀）。
    use crate::starknet::chain::hex_encode as hex_line;
    use poker_protocol::zk_shuffle::bayer_groth::{
        BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
    };
    use poker_protocol_core::PoseidonFeltTranscript;

    type Ct = poker_protocol_core::StarkElGamalCiphertext;

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    fn test_binding() -> [u8; 32] {
        let mut b = [0x5Bu8; 32];
        b[0] = 0x02; // felt 合法域
        b
    }

    // ---- reconstruct (CP-DLEQ) ----

    /// 诚实 CP-DLEQ reconstruct：P1 = s·G1、P2 = s·G2，
    /// resp = w + c·s（c = handbatch_reconstruct_challenge）。
    fn mint_reconstruct() -> HandBatchEquation {
        let s = random_scalar();
        let g1 = StarkCurve::base_g();
        let g2 = <StarkCurve as Curve>::base_h();
        let p1 = g1 * s;
        let p2 = g2 * s;
        let w = random_scalar();
        let a = g1 * w;
        let b = g2 * w;
        let c = poker_protocol_core::stark_curve::handbatch_reconstruct_challenge(
            &test_binding(),
            &g1,
            &g2,
            &p1,
            &p2,
            &a,
            &b,
        );
        let resp = w + c * s;
        HandBatchEquation::Reconstruct {
            s: resp,
            g1,
            g2,
            p1,
            p2,
            a,
            b,
        }
    }

    #[test]
    fn honest_reconstruct_folds() {
        let hb = test_binding();
        let eqs = [mint_reconstruct()];
        assert!(
            host_fold_check(&hb, &eqs),
            "honest CP-DLEQ must fold to identity"
        );
    }

    #[test]
    fn tampered_reconstruct_fails() {
        let hb = test_binding();
        let eq = mint_reconstruct();
        let tampered = match eq {
            HandBatchEquation::Reconstruct {
                s,
                g1,
                g2,
                p1,
                p2,
                a,
                b,
            } => HandBatchEquation::Reconstruct {
                s: s + <Sc as CurveScalar>::one(),
                g1,
                g2,
                p1,
                p2,
                a,
                b,
            },
            _ => unreachable!(),
        };
        assert!(
            !host_fold_check(&hb, &[tampered]),
            "bumped response scalar must break the fold"
        );
    }

    // ---- BG shuffle over PoseidonFeltTranscript ----

    fn shuffle_instance(n: usize) -> (Vec<Ct>, Vec<Ct>, Pt, Vec<usize>, Vec<Sc>) {
        let sk = random_scalar();
        let pk = StarkCurve::base_g() * sk;
        let input: Vec<Ct> = (0..n)
            .map(|_| {
                let msg = <Pt as CurvePoint>::random(&mut rand::rngs::OsRng);
                Ct::encrypt(&msg, &pk, &random_scalar())
            })
            .collect();
        // 确定性双射（step 与 n 互素）
        let step = 7;
        let permutation: Vec<usize> = (0..n).map(|i| (i * step + 3) % n).collect();
        let rerandomizers: Vec<Sc> = (0..n).map(|_| random_scalar()).collect();
        let output: Vec<Ct> = (0..n)
            .map(|i| input[permutation[i]].re_encrypt(&pk, &rerandomizers[i]))
            .collect();
        (input, output, pk, permutation, rerandomizers)
    }

    #[test]
    fn honest_bg_shuffle_folds() {
        let n = 52;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &pk,
            &mut rand::rngs::OsRng,
            &mut tr,
        )
        .expect("honest BG prove");

        // 参照系：BG verify() 在同一 transcript 类型上通过
        proof
            .verify(
                &input,
                &output,
                &pk,
                &mut PoseidonFeltTranscript::new_bg_fold(),
            )
            .expect("BG verify over PoseidonFeltTranscript");

        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        assert_eq!(eqs.equations.len(), 8, "E1x2 + E2 + E3 + E4x2 + E5 + E6");
        assert!(eqs.scalar_check_1, "b[0] == a[0]");
        assert!(eqs.scalar_check_2, "b[n-1] == q * prod");
        for (i, eq) in eqs.equations.iter().enumerate() {
            assert!(linear_residual(eq).is_identity(), "equation {i} residual");
        }
        assert!(
            host_fold_check_linear(&test_binding(), &eqs.equations),
            "BG equation set must fold to identity"
        );
    }

    #[test]
    fn tampered_bg_shuffle_fails() {
        let n = 16;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &pk,
            &mut rand::rngs::OsRng,
            &mut tr,
        )
        .expect("honest BG prove");

        // 篡改 1：证明词（beta += 1）→ E3/E4c2 破
        let mut bad = proof.clone();
        bad.multi_exponentiation.beta = bad.multi_exponentiation.beta + <Sc as CurveScalar>::one();
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &bad);
        let any_bad = eqs
            .equations
            .iter()
            .any(|e| !linear_residual(e).is_identity())
            || !eqs.scalar_check_1
            || !eqs.scalar_check_2;
        assert!(any_bad, "tampered beta must break the equation set");

        // 篡改 2：交换两条输出密文 → E4 破
        let mut swapped = output.clone();
        swapped.swap(0, 1);
        let eqs = bg_shuffle_fold_equations(&input, &swapped, &pk, &proof);
        assert!(
            eqs.equations
                .iter()
                .any(|e| !linear_residual(e).is_identity()),
            "swapped outputs must break the equation set"
        );
    }

    // ---- /tmp/bgvectors 机器可读向量 ----

    /// /tmp/bgvectors/bg_shuffle.txt 重放一致性：x y z e q 与向量尾部
    /// 逐词一致。
    /// 向量文件缺失时跳过（仅本地/生成环境存在）。
    #[test]
    fn bgvectors_transcript_replay_matches_file() {
        let Ok(text) = std::fs::read_to_string("/tmp/bgvectors/bg_shuffle.txt") else {
            return;
        };
        let mut words: Vec<[u8; 32]> = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut b = [0u8; 32];
            b.copy_from_slice(&hex::decode(l).expect("hex word"));
            words.push(b);
        }
        let n = word_low_u64(&words[1]).expect("n") as usize;
        assert_eq!(n, 52);
        let b = &words[2..]; // after hand_binding + n: input 4n, output 4n, pk 2, comm 22, resp 3n+6, chal 6
        let mut o = 0usize;
        let ct_n = |o: &mut usize| -> Ct {
            let c1 = point_from_words(&b[*o], &b[*o + 1]).expect("c1");
            let c2 = point_from_words(&b[*o + 2], &b[*o + 3]).expect("c2");
            *o += 4;
            Ct { c1, c2 }
        };
        let input: Vec<Ct> = (0..n).map(|_| ct_n(&mut o)).collect();
        let output: Vec<Ct> = (0..n).map(|_| ct_n(&mut o)).collect();
        let pk = point_from_words(&b[o], &b[o + 1]).expect("pk");
        o += 2;
        let pt_n = |o: &mut usize| -> Pt {
            let p = point_from_words(&b[*o], &b[*o + 1]).expect("point");
            *o += 2;
            p
        };
        let sc_n = |o: &mut usize| -> Sc {
            let s = scalar_from_word(&b[*o]).expect("scalar");
            *o += 1;
            s
        };
        let c_permutation = pt_n(&mut o);
        let c_permuted_powers = pt_n(&mut o);
        let c_alpha = pt_n(&mut o);
        let c_beta = pt_n(&mut o);
        let ciphertext_0 = ct_n(&mut o);
        let ciphertext_1 = ct_n(&mut o);
        let c_d = pt_n(&mut o);
        let c_delta = pt_n(&mut o);
        let c_capital_delta = pt_n(&mut o);
        let alpha_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let commitment_response = sc_n(&mut o);
        let beta = sc_n(&mut o);
        let beta_blinding_response = sc_n(&mut o);
        let rerandomization_response = sc_n(&mut o);
        let a_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let b_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let r_response = sc_n(&mut o);
        let s_response = sc_n(&mut o);
        let proof = BayerGrothShuffleProof::<StarkCurve> {
            c_permutation,
            c_permuted_powers,
            multi_exponentiation: MultiExponentiationArgument {
                c_alpha,
                c_beta,
                ciphertext_0,
                ciphertext_1,
                alpha_response,
                commitment_response,
                beta,
                beta_blinding_response,
                rerandomization_response,
            },
            product: ProductArgument {
                c_d,
                c_delta,
                c_capital_delta,
                a_response,
                b_response,
                r_response,
                s_response,
            },
        };
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        let derived = [
            eqs.powers_challenge,
            eqs.product_y,
            eqs.product_z,
            eqs.mexp_challenge,
            eqs.product_challenge,
        ];
        // 末尾 5 词 = x y z e q（历史 λ 向量多 1 词时忽略尾部）
        let tail = &b[o..];
        let cmp_n = tail.len().min(derived.len());
        for i in 0..cmp_n {
            let mut w = [0u8; 32];
            w.copy_from_slice(&derived[i].as_bytes());
            assert_eq!(w, tail[i], "challenge word {i} mismatch");
        }
        // 分解后的方程组在该向量上仍须全零
        assert!(eqs.scalar_check_1 && eqs.scalar_check_2);
        assert!(
            eqs.equations
                .iter()
                .all(|e| linear_residual(e).is_identity()),
            "pinned vector residuals"
        );
    }

    fn point_words(p: &Pt) -> [[u8; 32]; 2] {
        let (x, y) = point_xy(p);
        [x, y]
    }

    fn scalar_word(s: &Sc) -> [u8; 32] {
        let mut b = [0u8; 32];
        b.copy_from_slice(&s.as_bytes());
        b
    }

    /// 生成 Cairo 端复刻所需的全部向量（运行：
    /// cargo +nightly test -p texas bg_vectors -- --nocapture）。
    #[test]
    fn bg_vectors() {
        let dir = std::path::Path::new("/tmp/bgvectors");
        std::fs::create_dir_all(dir).expect("mkdir /tmp/bgvectors");
        let hb = test_binding();

        // ---- 1. CK n=52（h + 52 generators，Cairo 常量钉死）----
        let ck = BgCommitmentKey::derive(52);
        let mut out = String::from(
            "# BG commitment key, n=52, STARK curve affine (x, y) hex words\n\
             # line order: h_x, h_y, G0_x, G0_y, ..., G51_x, G51_y (53 points)\n\
             # derivation: h = hash_to_curve(\"poker/bg12/v2/H\"), Gi = hash_to_curve(\"poker/bg12/v2/G/52/i\")\n",
        );
        for p in std::iter::once(&ck.h).chain(ck.generators.iter()) {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        std::fs::write(dir.join("ck_n52.txt"), out).expect("write ck_n52.txt");

        // ---- 2. CP-DLEQ reconstruct 向量 ----
        // wire 格式（recon 桶，每条 13 词，顺序）：
        //   [g1_x g1_y g2_x g2_y p1_x p1_y p2_x p2_y A_x A_y B_x B_y s]
        // 挑战 c = handbatch_reconstruct_challenge(hand_binding, ...) 链上重算；
        // 方程：s·g1 − A − c·p1 = O；s·g2 − B − c·p2 = O。
        let recon = mint_reconstruct();
        let (r_s, r_g1, r_g2, r_p1, r_p2, r_a, r_b) = match recon {
            HandBatchEquation::Reconstruct {
                s,
                g1,
                g2,
                p1,
                p2,
                a,
                b,
            } => (s, g1, g2, p1, p2, a, b),
            _ => unreachable!(),
        };
        assert!(host_fold_check(
            &hb,
            &[HandBatchEquation::Reconstruct {
                s: r_s,
                g1: r_g1,
                g2: r_g2,
                p1: r_p1,
                p2: r_p2,
                a: r_a,
                b: r_b,
            }]
        ));
        let mut out = String::from(
            "# CP-DLEQ reconstruct vector (foldable epoch, kind=4)\n\
             # word 0: hand_binding (32B BE)\n\
             # words 1..=13 (hex, one per line): g1_x g1_y g2_x g2_y p1_x p1_y p2_x p2_y A_x A_y B_x B_y s\n\
             # equations: s*g1 - A - c*p1 = O ; s*g2 - B - c*p2 = O\n\
             # c = poseidon([\"poker/reconstruct-fold/v1\", hand_binding, g1,g2,p1,p2,A,B]) mod n\n",
        );
        out.push_str(&hex_line(&hb));
        out.push('\n');
        for p in [&r_g1, &r_g2, &r_p1, &r_p2, &r_a, &r_b] {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        out.push_str(&hex_line(&scalar_word(&r_s)));
        out.push('\n');
        std::fs::write(dir.join("cp_recon.txt"), out).expect("write cp_recon.txt");

        // ---- 3. BG shuffle 向量（n=52）----
        // wire 格式（BG 桶，hex felt252 词每行一词，段序）：
        //   hand_binding (1)
        //   n (1)
        //   input  n*4: (c1_x c1_y c2_x c2_y)*n
        //   output n*4: (c1_x c1_y c2_x c2_y)*n
        //   pk (2)
        //   proof commitments (22): c_permutation(2) c_permuted_powers(2)
        //     c_alpha(2) c_beta(2) ct0(4) ct1(4) c_d(2) c_delta(2) c_capital_delta(2)
        //   proof responses (3n+6): alpha_response(n) commitment_response beta
        //     beta_blinding_response rerandomization_response a_response(n)
        //     b_response(n) r_response s_response
        //   derived challenges (5): x y z e q（Cairo 由 transcript 重放重算比对）
        let n = 52;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &pk,
            &mut rand::rngs::OsRng,
            &mut tr,
        )
        .expect("honest BG prove");
        proof
            .verify(
                &input,
                &output,
                &pk,
                &mut PoseidonFeltTranscript::new_bg_fold(),
            )
            .expect("BG verify");
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        assert!(eqs.scalar_check_1 && eqs.scalar_check_2);
        assert!(host_fold_check_linear(&hb, &eqs.equations));

        let mut out = String::from(
            "# BG shuffle vector (foldable epoch), n=52, STARK curve\n\
             # hex felt252 words, one per line; section markers below\n\
             # Cairo recomputes x,y,z,e,q by replaying PoseidonFeltTranscript over:\n\
             #   protocol, deck_size, pk, input cts, output cts, c_permutation,\n\
             #   ->x, c_permuted_powers, ->y, ->z, c_alpha, c_beta, ct0, ct1,\n\
             #   ->e, c_d, c_delta, c_capital_delta, ->q\n",
        );
        out.push_str("# hand_binding\n");
        out.push_str(&hex_line(&hb));
        out.push('\n');
        out.push_str("# n\n");
        out.push_str(&hex_line(&u256_word(n as u64)));
        out.push('\n');
        out.push_str("# input ciphertexts (n*4)\n");
        for ct in &input {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    out.push_str(&hex_line(&w));
                    out.push('\n');
                }
            }
        }
        out.push_str("# output ciphertexts (n*4)\n");
        for ct in &output {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    out.push_str(&hex_line(&w));
                    out.push('\n');
                }
            }
        }
        out.push_str("# pk (2)\n");
        for w in point_words(&pk) {
            out.push_str(&hex_line(&w));
            out.push('\n');
        }
        out.push_str("# proof commitments (22)\n");
        let mexp = &proof.multi_exponentiation;
        let product = &proof.product;
        for p in [
            &proof.c_permutation,
            &proof.c_permuted_powers,
            &mexp.c_alpha,
            &mexp.c_beta,
            &mexp.ciphertext_0.c1,
            &mexp.ciphertext_0.c2,
            &mexp.ciphertext_1.c1,
            &mexp.ciphertext_1.c2,
            &product.c_d,
            &product.c_delta,
            &product.c_capital_delta,
        ] {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        out.push_str("# proof responses (3n+6)\n");
        for s in mexp
            .alpha_response
            .iter()
            .chain(std::iter::once(&mexp.commitment_response))
            .chain(std::iter::once(&mexp.beta))
            .chain(std::iter::once(&mexp.beta_blinding_response))
            .chain(std::iter::once(&mexp.rerandomization_response))
            .chain(product.a_response.iter())
            .chain(product.b_response.iter())
            .chain(std::iter::once(&product.r_response))
            .chain(std::iter::once(&product.s_response))
        {
            out.push_str(&hex_line(&scalar_word(s)));
            out.push('\n');
        }
        out.push_str("# derived challenges x y z e q (transcript replay)\n");
        for s in [
            &eqs.powers_challenge,
            &eqs.product_y,
            &eqs.product_z,
            &eqs.mexp_challenge,
            &eqs.product_challenge,
        ] {
            out.push_str(&hex_line(&scalar_word(s)));
            out.push('\n');
        }
        std::fs::write(dir.join("bg_shuffle.txt"), out).expect("write bg_shuffle.txt");

        // ---- 4. 全桶载荷（own+reveal+leave+recon host 可折叠；shuffle 桶
        //         词序同 bg_shuffle.txt 去掉 hand_binding 行——当前
        //         parse_batch_terms 仍拒 n_shuffle>0，词序为 part-2 目标）----
        let mut words: Vec<[u8; 32]> = vec![
            u256_word(1), // n_own
            u256_word(1), // n_shuffle
            u256_word(1), // n_reveal
            u256_word(1), // n_leave
            u256_word(1), // n_recon
        ];
        // own 桶
        let sk = random_scalar();
        let pk_own = StarkCurve::base_g() * sk;
        let e = mint_endorsement(&sk, &pk_own, &hb);
        for w in point_words(&e.pk).into_iter().chain(point_words(&e.r)) {
            words.push(w);
        }
        words.push(scalar_be(&e.s));
        // shuffle 桶（n + input + output + pk + 22 + 3n+6）
        words.push(u256_word(n as u64));
        for ct in input.iter().chain(output.iter()) {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    words.push(w);
                }
            }
        }
        for w in point_words(&pk) {
            words.push(w);
        }
        for p in [
            &proof.c_permutation,
            &proof.c_permuted_powers,
            &mexp.c_alpha,
            &mexp.c_beta,
            &mexp.ciphertext_0.c1,
            &mexp.ciphertext_0.c2,
            &mexp.ciphertext_1.c1,
            &mexp.ciphertext_1.c2,
            &product.c_d,
            &product.c_delta,
            &product.c_capital_delta,
        ] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        for s in mexp
            .alpha_response
            .iter()
            .chain(std::iter::once(&mexp.commitment_response))
            .chain(std::iter::once(&mexp.beta))
            .chain(std::iter::once(&mexp.beta_blinding_response))
            .chain(std::iter::once(&mexp.rerandomization_response))
            .chain(product.a_response.iter())
            .chain(product.b_response.iter())
            .chain(std::iter::once(&product.r_response))
            .chain(std::iter::once(&product.s_response))
        {
            words.push(scalar_word(s));
        }
        // reveal 桶（14 词）
        let r_sk = random_scalar();
        let r_pk = StarkCurve::base_g() * r_sk;
        let msg = <StarkCurve as Curve>::hash_to_curve(b"bgvectors/reveal/card-0");
        let r_r = random_scalar();
        let ct = Ct::encrypt(&msg, &r_pk, &r_r);
        let token = ct.c1 * r_sk;
        let w_nonce = random_scalar();
        let (t1, t2) = (StarkCurve::base_g() * w_nonce, ct.c1 * w_nonce);
        let c_reveal = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
            &hb, &r_pk, &ct.c1, &ct.c2, &token, &t1, &t2, &w_nonce,
        );
        let s_reveal = w_nonce + c_reveal * r_sk;
        for p in [&r_pk, &ct.c1, &ct.c2, &token, &t1, &t2] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        words.push(scalar_word(&w_nonce));
        words.push(scalar_word(&s_reveal));
        // leave 桶（1 卡）
        let l_sk = random_scalar();
        let l_pk = StarkCurve::base_g() * l_sk;
        let omega = random_scalar();
        let l_cpk = StarkCurve::base_g() * omega;
        let l_nonce = random_scalar();
        let l_msg = <StarkCurve as Curve>::hash_to_curve(b"bgvectors/leave/card-0");
        let l_r = random_scalar();
        let l_ct = Ct::encrypt(&l_msg, &l_pk, &l_r);
        let l_out = Ct {
            c1: l_ct.c1,
            c2: l_ct.c2 - l_ct.c1 * l_sk,
        };
        let l_a = l_ct.c1 * omega;
        let card_words = vec![poker_protocol_core::stark_curve::HandLeaveCardWords {
            in_c1: l_ct.c1,
            in_c2: l_ct.c2,
            out_c1: l_out.c1,
            out_c2: l_out.c2,
            a: l_a,
        }];
        let c_leave = poker_protocol_core::stark_curve::handbatch_leave_challenge(
            &hb,
            &l_pk,
            &l_cpk,
            &l_nonce,
            &card_words,
        );
        let s_leave = omega + c_leave * l_sk;
        words.push(u256_word(1));
        for w in point_words(&l_pk).into_iter().chain(point_words(&l_cpk)) {
            words.push(w);
        }
        words.push(scalar_word(&l_nonce));
        words.push(scalar_word(&s_leave));
        for p in [&l_ct.c1, &l_ct.c2, &l_out.c1, &l_out.c2, &l_a] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        // recon 桶（13 词）
        for p in [&r_g1, &r_g2, &r_p1, &r_p2, &r_a, &r_b] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        words.push(scalar_word(&r_s));

        // host parity：完整 5 桶载荷（含 shuffle）必须解析并折叠——
        // 与 Cairo 端 verify_hand_batch_stark 双跑一致。
        let equations = parse_batch_terms(&hb, &words).expect("5-bucket payload parses");
        assert_eq!(equations.len(), 5);
        assert!(host_fold_check(&hb, &equations), "5-bucket payload folds");

        // 篡改：shuffle 桶里的 beta 词 +1 → 折叠/标量校验必须破。
        // beta 位于 shuffle 桶响应段：1 + 8n + 2 + 22 + n(alpha) + 1。
        let beta_idx = 10 + 1 + 8 * n + 2 + 22 + n + 1;
        let mut bad = words.clone();
        let mut beta_b = bad[beta_idx];
        beta_b[31] = beta_b[31].wrapping_add(1);
        bad[beta_idx] = beta_b;
        let bad_eqs = match parse_batch_terms(&hb, &bad) {
            Some(e) => e,
            None => return, // 解析即拒（beta 非规范）也算正确拒绝
        };
        assert!(
            !host_fold_check(&hb, &bad_eqs),
            "tampered shuffle beta must break the fold"
        );

        let mut out = String::from(
            "# full hand-batch payload, all 5 buckets non-zero (n=52 shuffle)\n\
             # header (5 words): n_own n_shuffle n_reveal n_leave n_recon\n\
             # bucket order: own(5*no) shuffle(n+8n+2+22+3n+6) reveal(14*nr)\n\
             #   leave(7+10n_cards each) recon(13*nrc)\n\
             # shuffle bucket layout: [n, input 4n, output 4n, pk 2,\n\
             #   commitments 22, responses 3n+6]; challenges recomputed by\n\
             #   PoseidonFeltTranscript replay (same order as bg_shuffle.txt\n\
             #   minus hand_binding).\n",
        );
        out.push_str(&hex_line(&hb));
        out.push('\n');
        for w in &words {
            out.push_str(&hex_line(w));
            out.push('\n');
        }
        std::fs::write(dir.join("payload_full.txt"), out).expect("write payload_full.txt");
    }
}

// ============================================================
// Settle-mode（linear 默认 / proved 建而未启）测试
// ============================================================
#[cfg(test)]
mod settle_mode_tests {
    use super::*;
    use poker_l1::contracts::texas_poker::settlement::{
        SETTLEMENT_PLAN_VERSION, SETTLEMENT_SEATS, SettlementPlan, SettlementPotPlan,
        SettlementRunoutSchedule,
    };

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    // ---- 1. 模式解析默认 ----

    #[test]
    fn settle_mode_parsing_defaults_to_linear() {
        assert_eq!(SettleMode::default(), SettleMode::Linear);
        for raw in ["", "linear", "Linear", "LINEAR", "auto", "garbage", "0"] {
            assert_eq!(SettleMode::parse(raw), SettleMode::Linear, "raw={raw:?}");
        }
        for raw in ["proved", "Proved", "PROVED", " proved "] {
            assert_eq!(SettleMode::parse(raw), SettleMode::Proved, "raw={raw:?}");
        }
    }

    // ---- 2. p_batch 承诺 ----

    fn words_fixture() -> Vec<[u8; 32]> {
        // 规范头 + 10 个合成词（无需是曲线点——承诺只是 Poseidon；首字节
        // 压到 0x02 保证 < 域模，其余字节承载差异）。
        let mut w = vec![
            u256_word(2),
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(0),
        ];
        for i in 0u8..10 {
            let mut word = [0u8; 32];
            word[0] = 0x02;
            word[1] = i;
            word[31] = i.wrapping_add(1);
            w.push(word);
        }
        w
    }

    #[test]
    fn p_batch_commitment_is_deterministic_and_binding() {
        let hb = Felt::from(0x5Bu64);
        let words = words_fixture();
        let c1 = compute_p_batch_commitment(hb, &words).expect("commitment");
        let c2 = compute_p_batch_commitment(hb, &words).expect("commitment");
        assert_eq!(c1, c2, "deterministic");
        assert_ne!(c1, Felt::ZERO, "non-trivial");
        // 绑定 hand_binding
        let other_hb = compute_p_batch_commitment(hb + Felt::ONE, &words).expect("commitment");
        assert_ne!(c1, other_hb, "binding must change with hand_binding");
        // 绑定 batch 词
        let mut tampered = words.clone();
        tampered[6][31] ^= 1;
        let c3 = compute_p_batch_commitment(hb, &tampered).expect("commitment");
        assert_ne!(c1, c3, "commitment must change with batch words");
        // 超域词（≥ 域模）必须报错，而不是截断
        let mut bad = vec![u256_word(0); 2];
        bad[1][0] = 0xFF; // 远超 felt 域
        assert!(
            compute_p_batch_commitment(hb, &bad).is_err(),
            "out-of-range word must error"
        );
    }

    // ---- 3. calldata 形态：linear 黄金布局 + proved 无 p_batch ----

    fn synthetic_settlement() -> HandSettlement {
        let mut awards = [0u64; SETTLEMENT_SEATS];
        awards[0] = 200;
        HandSettlement {
            hand_id: 3,
            plan: SettlementPlan {
                version: SETTLEMENT_PLAN_VERSION,
                schedule: SettlementRunoutSchedule::Single,
                gross_pot: 200,
                rake: 0,
                total_awards: 200,
                winner_mask: 0b0001,
                awards,
                pot_count: 0,
                pots: [SettlementPotPlan::inactive(); SETTLEMENT_SEATS],
            },
            register_calldata: vec![],
            settle_calldata: vec![],
            aggregate_digest: [7u8; 32],
            players_remapped: vec![Felt::from(0x1111u64), Felt::from(0x2222u64)],
            deltas: vec![100, -100],
            settlement_digest: Felt::from(123456789u64),
            action_log_digest: Felt::from(0xA11CEu64),
            action_entries: Vec::new(),
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
        }
    }

    fn build_test_dual() -> DualSettlement {
        let mirror = VmTable::new(7, [0xAA; 20], 9, 10, 20, [0xAA; 20]);
        let settlement = synthetic_settlement();
        let binding = prepare_handbatch_binding(&mirror, &settlement).expect("binding");
        let endorsements: Vec<Endorsement> = (0..2)
            .map(|_| {
                let sk = random_scalar();
                let pk = StarkCurve::base_g() * sk;
                mint_endorsement(&sk, &pk, &binding.hand_id_bytes)
            })
            .collect();
        build_dual_settlement_with(&mirror, &settlement, &|_hb, _players| {
            Ok(endorsements.clone())
        })
        .expect("dual build")
    }

    // ---- 错误/缺失语句的 fail-closed 场景 ----
    //
    // 场景：结算聚合时混入错误（坏签名/错绑定）或缺失的 ownership 认可。
    // 回归点：坏批次必须在**构建阶段**被拦（host fold parity），永远到不了
    // register_hand 上链——链上因此不会出现「settle revert → binding 已注册
    // 却永远无法结算」的卡死状态。（认可提交通道已删除；将来 ownership 桶
    // 重接动作签名时，数量闸门在合约 n_own == players.len() 一侧。）

    fn endorsements_for(binding: &HandBatchBinding, n: usize) -> Vec<Endorsement> {
        (0..n)
            .map(|i| {
                let sk = <Sc as CurveScalar>::from_u64(9100 + i as u64);
                let pk = StarkCurve::base_g() * sk;
                mint_endorsement(&sk, &pk, &binding.hand_id_bytes)
            })
            .collect()
    }

    #[test]
    fn tampered_endorsement_fails_closed_before_onchain() {
        let mirror = VmTable::new(7, [0xAA; 20], 9, 10, 20, [0xAA; 20]);
        let settlement = synthetic_settlement();
        let binding = prepare_handbatch_binding(&mirror, &settlement).expect("binding");

        // 诚实控制：同一夹具下两人的成品认可构建成功。
        let honest = endorsements_for(&binding, 2);
        build_dual_settlement_with(&mirror, &settlement, &|_hb, _players| Ok(honest.clone()))
            .expect("honest endorsements must build");

        // 篡改一位玩家的 s（等价于聚合进一份坏语句）：该方程残差
        // s'·G − R − c·pk = G ≠ O，fold 失败，构建必须 Err。
        let mut tampered = honest;
        tampered[1].s = tampered[1].s + <Sc as CurveScalar>::one();
        let err =
            build_dual_settlement_with(&mirror, &settlement, &|_hb, _players| Ok(tampered.clone()))
                .err()
                .expect("tampered endorsement must fail closed");
        assert!(
            err.contains("host fold parity"),
            "expected host fold gate, got: {err}"
        );
    }

    // ---- 5. settle 入口选择（STARKNET_DAPV_SETTLE_ENTRY）----

    #[test]
    fn settle_entry_defaults_to_v2() {
        // v2：calldata = [hand_binding, hand_id, segment(16)]，无承诺尾部。
        let hb = Felt::from(0xBBBBu64);
        let segment: Vec<Felt> = (0..16).map(|i| Felt::from(i as u64)).collect();
        for entry in ["", "v2", "garbage"] {
            let (selector, calldata) =
                settle_entry_calldata(entry, hb, 42, &segment, Felt::from(0xC0BAu64), 37);
            assert_eq!(
                selector, "verify_and_settle_dapv_stark_private_v2",
                "entry={entry}"
            );
            assert_eq!(calldata.len(), 2 + 16);
            assert_eq!(calldata[0], hb);
            assert_eq!(calldata[1], Felt::from(42u64));
            assert_eq!(calldata[2], Felt::ZERO, "segment[0]");
        }
    }

    #[test]
    fn settle_entry_proved_private_appends_commitment() {
        // proved_private：v2 形态 + [p_batch_commitment, p_batch_len] 尾部。
        let hb = Felt::from(0xCCCCu64);
        let segment: Vec<Felt> = (0..16).map(|i| Felt::from(100 + i as u64)).collect();
        let (selector, calldata) = settle_entry_calldata(
            "proved_private",
            hb,
            43,
            &segment,
            Felt::from(0xC0BAu64),
            37,
        );
        assert_eq!(selector, "verify_and_settle_dapv_proved_private");
        assert_eq!(calldata.len(), 2 + 16 + 2);
        assert_eq!(calldata[2], Felt::from(100u64), "segment[0]");
        assert_eq!(calldata[18], Felt::from(0xC0BAu64), "commitment");
        assert_eq!(calldata[19], Felt::from(37u64), "batch len");
        // 公开段前缀与 v2 完全一致（同一 segment 语义）
        let (_, v2) = settle_entry_calldata("v2", hb, 43, &segment, Felt::ZERO, 0);
        assert_eq!(calldata[..18], v2[..], "shared segment prefix");
    }

    #[test]
    fn settle_entry_snip36_uses_v2_shape() {
        // snip36：选择器为 v3 双门入口，calldata 与 v2 同形（无承诺尾部）
        // ——合约侧随 cairo ≥2.12 迁移上链后生效（SNIP36_INTEGRATION §4）。
        let hb = Felt::from(0xDDDDu64);
        let segment: Vec<Felt> = (0..16).map(|i| Felt::from(200 + i as u64)).collect();
        let (selector, calldata) =
            settle_entry_calldata("snip36", hb, 44, &segment, Felt::from(0xC0BAu64), 37);
        assert_eq!(selector, "verify_and_settle_dapv_stark_private_v3");
        assert_eq!(calldata.len(), 2 + 16);
        let (_, v2) = settle_entry_calldata("v2", hb, 44, &segment, Felt::ZERO, 0);
        assert_eq!(calldata, v2, "snip36 shares the v2 calldata shape");
    }

    #[test]
    fn settle_entry_combined_takes_17_word_segment() {
        // combined：选择器为合并信封入口，calldata = [hand_binding, hand_id,
        // segment(17)]——segment 首词 chain_acc（证明公开输出），无承诺尾部。
        // 合约侧逐槽校验 segment[1]=MAGIC / [2]=hand_id / [5]=binding /
        // [3]=digest / [16]=action_log（本测试只钉 calldata 形状）。
        let hb = Felt::from(0xEEEEu64);
        let segment: Vec<Felt> = (0..17).map(|i| Felt::from(300 + i as u64)).collect();
        let (selector, calldata) =
            settle_entry_calldata("combined", hb, 45, &segment, Felt::from(0xC0BAu64), 37);
        assert_eq!(selector, "verify_and_settle_dapv_combined_private");
        assert_eq!(
            calldata.len(),
            2 + 17,
            "17 词段（v2 16 词 + 前置 chain_acc）"
        );
        assert_eq!(calldata[0], hb);
        assert_eq!(calldata[1], Felt::from(45u64));
        assert_eq!(calldata[2], Felt::from(300u64), "segment[0] = chain_acc");
        assert_eq!(
            calldata[18],
            Felt::from(316u64),
            "segment[16] = action_log_digest"
        );
    }

    #[test]
    fn combined_acc_state_roundtrip_atomic() {
        // acc 状态文件：缺省 GENESIS（0）、读回一致、原子写（无 .tmp 残留）、
        // 损坏内容 fail-closed。独立临时目录（_at 变体绕开全局 env）。
        let dir =
            std::env::temp_dir().join(format!("zgame-combined-acc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("acc.txt");
        assert_eq!(read_combined_acc_at(&path).expect("genesis"), Felt::ZERO);
        let acc = starknet_crypto::poseidon_hash_many(&[Felt::from(1u64), Felt::from(2u64)]);
        write_combined_acc_at(&path, acc).expect("write");
        assert_eq!(read_combined_acc_at(&path).expect("read back"), acc);
        assert!(!dir.join("acc.tmp").exists(), "原子写不留临时文件");
        // 覆写（rename 语义）+ 损坏内容拒绝。
        let next = acc + Felt::ONE;
        write_combined_acc_at(&path, next).expect("overwrite");
        assert_eq!(read_combined_acc_at(&path).expect("read back 2"), next);
        std::fs::write(&path, "not-hex!!\n").unwrap();
        assert!(
            read_combined_acc_at(&path).is_err(),
            "损坏状态必须 fail-closed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settle_entry_config_gate() {
        // 配置门：默认/未知值一律归一化为 v2；显式值 trim 后透传。
        let cfg = |v: &str| crate::starknet::config::StarknetConfig {
            dapv_settle_entry: v.to_string(),
            ..crate::starknet::config::StarknetConfig::from_env()
        };
        assert_eq!(cfg("").dapv_settle_entry(), "v2");
        assert_eq!(cfg("v2").dapv_settle_entry(), "v2");
        assert_eq!(
            cfg("garbage").dapv_settle_entry(),
            "v2",
            "unknown → v2 回退"
        );
        assert_eq!(cfg("proved_private").dapv_settle_entry(), "proved_private");
        assert_eq!(
            cfg(" proved_private ").dapv_settle_entry(),
            "proved_private",
            "trim"
        );
        assert_eq!(cfg("snip36").dapv_settle_entry(), "snip36");
        assert_eq!(cfg("combined").dapv_settle_entry(), "combined");
    }

    #[test]
    fn fold_check_cannot_detect_missing_endorsements() {
        let mirror = VmTable::new(7, [0xAA; 20], 9, 10, 20, [0xAA; 20]);
        let settlement = synthetic_settlement();
        let binding = prepare_handbatch_binding(&mirror, &settlement).expect("binding");

        // 文档性断言：fold 校验**检测不到缺席**——剩下的每条方程各自有效，
        // Σ ρⁱ·Lᵢ 仍为 O。缺席的守卫是数量（合约侧 n_own == players.len()），
        // host 侧构建/折叠对此不设防；重接动作签名桶时保持同一不变式。
        let short = endorsements_for(&binding, 1);
        let words = assemble_batch(&short, &[]);
        let parsed =
            parse_batch_terms(&binding.hand_id_bytes, &words).expect("short batch still parses");
        assert!(
            host_fold_check(&binding.hand_id_bytes, &parsed),
            "fold passes on a short batch — absence is count-gated, not fold-gated"
        );
    }

    #[test]
    fn linear_calldata_matches_golden_layout() {
        let dual = build_test_dual();
        let settlement = synthetic_settlement();
        let hb_felt = dual.hand_binding;

        // register：[binding, digest, g_attestation, action_log, 0, 0, 0]
        // （#18 Phase B：动作日志承诺 + 期望桶计数尾全零）。
        assert_eq!(dual.register_calldata.len(), 7);
        assert_eq!(dual.register_calldata[0], hb_felt);
        assert_eq!(dual.register_calldata[1], settlement.settlement_digest);
        assert_eq!(dual.register_calldata[2], dual.g_attestation);
        assert_eq!(dual.register_calldata[3], settlement.action_log_digest);
        for tail in &dual.register_calldata[4..7] {
            assert_eq!(
                *tail,
                Felt::ZERO,
                "expected-count tail must default to zero"
            );
        }

        // settle：binding + [32, bytes…] + hand_id + action_log +
        // [n, players…] + [n, deltas…] + [m, felt×m]（_stark 入口的
        // Span<felt252> 单 felt 打包；曾为 secp 入口的 (low, high) 双
        // felt，已修正）。
        let expect_len = 1
            + 1
            + 32
            + 1
            + 1
            + 1
            + settlement.players_remapped.len()
            + 1
            + settlement.deltas.len()
            + 1
            + dual.batch_words.len();
        assert_eq!(dual.settle_calldata.len(), expect_len);
        assert_eq!(dual.settle_calldata[0], hb_felt);
        assert_eq!(dual.settle_calldata[1], Felt::from(32u64));
        assert_eq!(
            dual.settle_calldata[34],
            Felt::from(u64::from(settlement.hand_id))
        );
        assert_eq!(dual.settle_calldata[35], settlement.action_log_digest);
        assert_eq!(
            dual.settle_calldata[36],
            Felt::from(settlement.players_remapped.len() as u64)
        );
        assert_eq!(
            dual.settle_calldata[36 + 1 + settlement.players_remapped.len()],
            Felt::from(settlement.deltas.len() as u64)
        );
        let words_len_at = 36 + 1 + settlement.players_remapped.len() + 1 + settlement.deltas.len();
        assert_eq!(
            dual.settle_calldata[words_len_at],
            Felt::from(dual.batch_words.len() as u64)
        );
        // 首个 u256 词的 (low, high) 双 felt 形态保持。
        let w0 = dual.batch_words[0];
        assert_eq!(
            dual.settle_calldata[words_len_at + 1],
            Felt::from(u128::from_be_bytes(w0[16..32].try_into().unwrap()))
        );
        assert_eq!(
            dual.settle_calldata[words_len_at + 2],
            Felt::from(u128::from_be_bytes(w0[..16].try_into().unwrap()))
        );
    }

    #[test]
    fn proved_calldata_carries_commitment_and_no_batch() {
        let dual = build_test_dual();
        let settlement = synthetic_settlement();
        let hb_felt = dual.hand_binding;
        let commitment =
            compute_p_batch_commitment(dual.hand_binding, &dual.batch_words).expect("commitment");

        // register_hand_proved：[binding, digest, g_att, action_log,
        // commitment, len, 0,0,0]（#18 Phase B）。
        let pr = &dual.proved.register_calldata;
        assert_eq!(pr.len(), 9);
        assert_eq!(pr[0], hb_felt);
        assert_eq!(pr[1], settlement.settlement_digest);
        assert_eq!(pr[2], dual.g_attestation);
        assert_eq!(pr[3], settlement.action_log_digest, "action log commitment");
        assert_eq!(pr[4], commitment, "registered commitment");
        assert_eq!(pr[5], Felt::from(dual.batch_words.len() as u64));
        assert_eq!(pr[6], Felt::ZERO);
        assert_eq!(pr[7], Felt::ZERO);
        assert_eq!(pr[8], Felt::ZERO);

        // P2-M4：settle calldata 改为 verify_and_settle_dapv_proved_private
        // ——在 submit_dual_settlement 里由 settlement_private 公开段构建
        // （[hand_binding, hand_id, segment(16), commitment, len]），构建期
        // 留空（赢家 payout commitment 需 async 查 vault）。
        assert!(
            dual.proved.settle_calldata.is_empty(),
            "filled at submit time"
        );
        // 承诺与结构字段一致
        assert_eq!(dual.proved.p_batch_commitment, commitment);
        assert_eq!(dual.proved.p_batch_len, dual.batch_words.len());
    }

    // ---- 4. prover 存根与回退 ----

    struct OkProver {
        commitment: Felt,
    }
    impl BatchProver for OkProver {
        fn request_attestation<'a>(
            &'a self,
            _workload: &'a ProverWorkload,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
        > {
            let c = self.commitment;
            Box::pin(async move {
                Ok(ProverAttestation {
                    p_batch_commitment: c,
                })
            })
        }
    }

    fn test_workload() -> ProverWorkload {
        ProverWorkload {
            hand_binding: Felt::from(0x5Bu64),
            hand_id: 1,
            batch_words: words_fixture(),
            p_batch_commitment: Felt::from(0xC0FFEEu64),
        }
    }

    #[tokio::test]
    async fn prover_stub_error_falls_back_to_linear() {
        for url in [None, Some("http://127.0.0.1:9/v1/attest".to_string())] {
            let prover = HttpBatchProver::new(url);
            let err = prover
                .request_attestation(&test_workload())
                .await
                .expect_err("stub must error");
            assert!(err.contains("not implemented"), "stub error text: {err}");
            assert_eq!(
                resolve_settle_mode_with_prover(&prover, &test_workload()).await,
                SettleMode::Linear,
                "any stub error must resolve to linear"
            );
        }
    }

    #[tokio::test]
    async fn prover_attestation_decides_mode() {
        let workload = test_workload();
        // 承诺匹配 → proved。
        let ok = OkProver {
            commitment: workload.p_batch_commitment,
        };
        assert_eq!(
            resolve_settle_mode_with_prover(&ok, &workload).await,
            SettleMode::Proved
        );
        // 承诺不匹配 → linear（prover 故障视同失败）。
        let bad = OkProver {
            commitment: workload.p_batch_commitment + Felt::ONE,
        };
        assert_eq!(
            resolve_settle_mode_with_prover(&bad, &workload).await,
            SettleMode::Linear
        );
    }

    // ---- 4b. 本地 batch prover（dev 模式，shadow::ProverMode::Local）----
    //
    // 本地 prover 做的是真验证（解析 + host ρ-fold + 承诺重算），不是
    // 无条件放行；与远端共用同一决策函数，失败同样回退 linear。

    fn workload_of(dual: &DualSettlement) -> ProverWorkload {
        ProverWorkload {
            hand_binding: dual.hand_binding,
            hand_id: dual.hand_id,
            batch_words: dual.batch_words.clone(),
            p_batch_commitment: dual.proved.p_batch_commitment,
        }
    }

    #[tokio::test]
    async fn local_batch_prover_attests_valid_batch() {
        let dual = build_test_dual();
        let workload = workload_of(&dual);
        let att = LocalBatchProver
            .request_attestation(&workload)
            .await
            .expect("well-formed batch must attest locally");
        assert_eq!(att.p_batch_commitment, workload.p_batch_commitment);
        assert_eq!(
            resolve_settle_mode_with_prover(&LocalBatchProver, &workload).await,
            SettleMode::Proved
        );
    }

    #[tokio::test]
    async fn local_batch_prover_rejects_tampered_batch() {
        let dual = build_test_dual();
        let mut workload = workload_of(&dual);
        // 篡改 ownership 首条认可词（词 5 = pk_x）：fold/解析必破。
        workload.batch_words[5][31] ^= 1;
        let err = LocalBatchProver
            .request_attestation(&workload)
            .await
            .expect_err("tampered batch must be rejected");
        tracing::debug!("local prover rejection: {err}");
        assert_eq!(
            resolve_settle_mode_with_prover(&LocalBatchProver, &workload).await,
            SettleMode::Linear
        );
    }

    #[tokio::test]
    async fn local_batch_prover_rejects_commitment_mismatch() {
        let dual = build_test_dual();
        let mut workload = workload_of(&dual);
        workload.p_batch_commitment = workload.p_batch_commitment + Felt::ONE;
        let err = LocalBatchProver
            .request_attestation(&workload)
            .await
            .expect_err("commitment mismatch must be rejected");
        assert!(err.contains("commitment mismatch"), "error text: {err}");
    }

    // ---- 5. workload JSON 导出 ----

    #[test]
    fn prover_workload_export_writes_consumable_json() {
        let dual = build_test_dual();
        let dir = std::env::temp_dir().join(format!("zgame-prover-test-{}", std::process::id()));
        let path = export_prover_workload(&dual, &dir).expect("export succeeds");

        let text = std::fs::read_to_string(&path).expect("read back");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(
            doc["hand_binding"],
            format!("{:#x}", dual.hand_binding).as_str()
        );
        assert_eq!(doc["hand_id"], serde_json::json!(dual.hand_id));
        assert_eq!(
            doc["p_batch_len"],
            serde_json::json!(dual.batch_words.len())
        );
        assert_eq!(
            doc["p_batch_commitment"],
            format!("{:#x}", dual.proved.p_batch_commitment).as_str()
        );
        let words = doc["batch_words"].as_array().expect("words array");
        assert_eq!(words.len(), dual.batch_words.len());
        assert_eq!(words[0], hex::encode(dual.batch_words[0]).as_str());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ============================================================
// 测试：SNIP-36 服务内自动接线（§5 #4）——双 mock（prover + RPC）端到端：
// create_proof 交易签名上送 → 证明应答 → proved v3 交易携 proof/proof_facts
// 广播 → 回退路径（prover 不可达）报错不 panic。
// ============================================================

#[cfg(test)]
mod snip36_wire_tests {
    use super::*;
    use crate::starknet::StarknetChain;
    use crate::starknet::config::StarknetConfig;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// 起一个一次性 JSON-RPC/HTTP mock：按序应答 `responses`（每连接一条），
    /// 并把收到的请求体推入 `captured` 供断言。
    async fn spawn_mock(
        responses: Vec<serde_json::Value>,
        captured: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut iter = responses.into_iter();
            while let Ok((mut sock, _)) = listener.accept().await {
                let Some(body) = iter.next() else { break };
                let mut buf = vec![0u8; 65536];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).to_string());
                let payload = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.to_string().len(),
                    body
                );
                let _ = sock.write_all(payload.as_bytes()).await;
            }
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn snip36_auto_submit_happy_path() {
        // starknet-rs provider 会轮询 chainId/getNonce；随后 prove + submit。
        let captured: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let rpc_responses = vec![
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":"0x534e5f4d41494e"}), // chainId
            serde_json::json!({"jsonrpc":"2.0","id":2,"result":"0x7"}),              // getNonce
            serde_json::json!({"jsonrpc":"2.0","id":3,
                "result":{"transaction_hash":"0xdeadbeef"}}), // add_invoke
        ];
        let rpc_url = spawn_mock(rpc_responses, captured.clone()).await;
        let prover_url = spawn_mock(
            vec![serde_json::json!({"jsonrpc":"2.0","id":1,"result":{
                "proof":"AQIDBA==",
                "proof_facts":["0x1","0x2","0x3"],
                "l2_to_l1_messages":[["0x1"]]

            }})],
            captured.clone(),
        )
        .await;

        let mut config = StarknetConfig::from_env();
        config.rpc_url = rpc_url;
        config.operator_address = "0x1234".into();
        config.operator_private_key = "0x99".into();
        config.snip36_prover_url = Some(prover_url);
        config.snip36_l2_gas = 0x5f5e100;
        let chain = StarknetChain::new(config);

        let hash = try_snip36_submit(&chain, vec![Felt::ONE, Felt::TWO])
            .await
            .expect("snip36 submit via mocks");
        assert_eq!(hash, "0xdeadbeef");

        let reqs = captured.lock().unwrap();
        // 提交给 prover 的 create_proof 交易：无 proof 字段、零价、nonce=7。
        let prove_req = reqs
            .iter()
            .find(|r| r.contains("starknet_proveTransaction"))
            .unwrap();
        assert!(prove_req.contains("starknet_proveTransaction"));
        // 广播的 proved 交易：含 proof/proof_facts 扩展字段。
        let submit_req = reqs
            .iter()
            .find(|r| r.contains("add_invoke_transaction"))
            .unwrap();
        assert!(submit_req.contains("\"proof\":["));
        assert!(submit_req.contains("\"proof_facts\":[\"0x1\",\"0x2\",\"0x3\"]"));
    }

    #[tokio::test]
    async fn snip36_auto_submit_falls_back_when_prover_missing() {
        // 未配置 prover 端点 → 立即 Err（调用方回退 v2 fact-registry 腿）。
        let captured: Arc<std::sync::Mutex<Vec<String>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let rpc_url = spawn_mock(
            vec![serde_json::json!({"jsonrpc":"2.0","id":1,"result":"0x534e5f4d41494e"})],
            captured.clone(),
        )
        .await;
        let mut config = StarknetConfig::from_env();
        config.rpc_url = rpc_url;
        config.operator_address = "0x1234".into();
        config.operator_private_key = "0x99".into();
        config.snip36_prover_url = None;
        let chain = StarknetChain::new(config);

        let err = try_snip36_submit(&chain, vec![Felt::ONE])
            .await
            .unwrap_err();
        assert!(err.contains("STARKNET_SNIP36_PROVER_URL"), "err: {err}");
    }
}
