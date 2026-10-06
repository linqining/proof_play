//! B6：嵌入式 appchain 运行时——sequencer（WAL + 软确认链）+ ProofPipeline
//! （本地 prover）+ CustodyLedger + VaultProvider 的进程内装配。
//!
//! ## 装配
//!
//! ```text
//! settle/deposit/withdraw 操作
//!   → Sequencer::submit（限流 → 试算 → WAL fsync → 内存态换入）
//!   → emit SOFT_CONFIRM（level=soft：frame_index/state_root/水位）
//!   → ProofPipeline.submit（本地 prover：REAL=STARK 全验证，PLAY=host attestation）
//!   → try_build_batch（批次根）→ mark_proven_through_with_root
//!   → emit SOFT_CONFIRM（level=proven）+ §5.4 finality 证据齐备
//! ```
//!
//! ## 生命周期
//!
//! `init`（main.rs 启动流程调用）：若 WAL 文件存在则先 `Sequencer::replay`
//! 全量恢复（fail-closed 重验链签名与每帧状态根），再挂载追加模式 WAL；
//! 随后装配 pipeline（ProvenCallback 推水位 + record_batch_root）并拉起
//! B7 三条后台管线（存款桥/提现执行/自动对账）。

use std::sync::{Arc, Mutex, OnceLock};

use poker_appchain::fee::{FeePolicy, FeeSplit};
use poker_appchain::keys::{OwnerKey, SequencerKey};
use poker_appchain::metrics::MetricsRegistry;
use poker_appchain::note::AssetClass;
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::{PipelineConfig, ProofPipeline, ProvenCallback};
use poker_appchain::real_policy::RealSettlementPolicy;
use poker_appchain::sequencer::{Sequencer, SequencerConfig};
use poker_appchain::soft_confirm::SignedFrame;
use poker_appchain::vault::CustodyLedger;

use super::bridge::VaultProvider;
use super::prover::TexasAirLocalProver;

/// 软确认 socket.io 事件名（沿 texas 现有 SCREAMING 命名风格）。
/// 载荷 `{frame_index, state_root_hex, watermark, level}`，level ∈
/// {"soft","proven"}。
pub const SOFT_CONFIRM_EVENT: &str = "SOFT_CONFIRM";

/// 软确认事件测试/运维挂钩（设置后每次 emit 同步回调；未设置时仅 socket.io）。
type SoftConfirmListener = Box<dyn Fn(u64, &str, u64, &str) + Send + Sync>;
static SOFT_CONFIRM_LISTENER: OnceLock<SoftConfirmListener> = OnceLock::new();

/// 注册软确认事件监听（测试断言载荷用；进程内单次）。
#[allow(dead_code)] // bin 构建无调用方（场景测试 + 运维挂钩保留）
pub fn set_soft_confirm_listener(l: SoftConfirmListener) {
    let _ = SOFT_CONFIRM_LISTENER.set(l);
}

/// 发出一帧软确认状态（sequencer 每帧后 / 水位推进后调用）。
pub fn emit_soft_confirm(frame_index: u64, state_root: [u8; 32], watermark: u64, level: &str) {
    let root_hex = format!("0x{}", crate::starknet::chain::hex_encode(&state_root));
    if let Some(l) = SOFT_CONFIRM_LISTENER.get() {
        l(frame_index, &root_hex, watermark, level);
    }
    // socket.io 广播（namespace 级）：emit 是异步面——在 tokio 上下文内
    // spawn；同步上下文（spawn_blocking 的出证等待路径）只走监听器。
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if let Some(io) = crate::socket::get_socket_io() {
        if let Some(ns) = io.of("/") {
            let payload = serde_json::json!({
                "frame_index": frame_index,
                "state_root_hex": root_hex,
                "watermark": watermark,
                "level": level,
            });
            handle.spawn(async move {
                if let Err(e) = ns.emit(SOFT_CONFIRM_EVENT, &payload).await {
                    tracing::warn!("[appchain] {SOFT_CONFIRM_EVENT} emit failed: {e:?}");
                }
            });
        }
    }
}

/// appchain 运行时配置（环境变量；devnet 默认 = mock provider + PLAY）。
#[derive(Debug, Clone)]
pub struct AppchainConfig {
    /// 总开关（`TEXAS_APPCHAIN=0` 关闭；默认开）。
    pub enabled: bool,
    /// WAL 目录（`TEXAS_APPCHAIN_WAL_DIR`，默认 /tmp/texas-appchain）。
    pub wal_dir: String,
    /// sequencer 帧签名种子（`TEXAS_APPCHAIN_SEQUENCER_SEED`，64 hex；
    /// 缺省 `<wal_dir>/sequencer-seed` load-or-generate，无公开常量缺省）。
    pub sequencer_seed: [u8; 32],
    /// attestor 签名种子（`TEXAS_APPCHAIN_ATTESTOR_SEED`，64 hex；缺省
    /// `<wal_dir>/attestor-seed` load-or-generate）——`StarkRequired` 模式的
    /// 钉扎公钥即由此派生。
    pub attestor_seed: [u8; 32],
    /// 结算资产类（`TEXAS_APPCHAIN_ASSET`：play（默认，devnet）/ real）。
    pub asset_class: AssetClass,
    /// treasury 份额 bps（`TEXAS_APPCHAIN_TREASURY_BPS`，默认 2000）。
    pub treasury_bps: u16,
    /// provider（`TEXAS_APPCHAIN_PROVIDER`：mock（默认）/ starknet）。
    pub provider: String,
    /// 桥任务轮询周期毫秒（`TEXAS_APPCHAIN_POLL_MS`，默认 2000）。
    pub poll_ms: u64,
    /// 对账周期秒（`TEXAS_APPCHAIN_RECONCILE_SECS`，默认 300）。
    pub reconcile_secs: u64,
    /// 出证等待上限秒（`TEXAS_APPCHAIN_PROVE_TIMEOUT_SECS`，默认 600）。
    pub prove_timeout_secs: u64,
    /// 桌费率 rake bps（`STARKNET_RAKE_BPS` 同源缺省；费率开桌冻结）。
    pub rake_bps: u16,
    /// 桌费率单手封顶（`STARKNET_RAKE_CAP` 同源缺省）。
    pub rake_cap: u64,
}

/// 签名种子装载：显式 env（64 hex）优先；否则 `<wal_dir>/<file_name>`
/// load-or-generate（0600）。旧版本的公开常量缺省（`[0x5E;32]`/`[0xA7;32]`）
/// 意味着未配置部署的帧签名密钥全球公开——任何人可伪造 SOFT_CONFIRM 帧
/// 与 attestation；缺省必须随机生成并落盘，与 WAL 同生命周期。
fn load_or_gen_seed(env_name: &str, wal_dir: &str, file_name: &str) -> [u8; 32] {
    if let Ok(s) = std::env::var(env_name) {
        let s = s.trim().trim_start_matches("0x");
        if let Some(seed) = hex::decode(s).ok().and_then(|v| <[u8; 32]>::try_from(v).ok()) {
            return seed;
        }
        tracing::warn!("[appchain] {env_name} invalid (expect 64 hex) — using persisted seed");
    }
    let path = std::path::Path::new(wal_dir).join(file_name);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes) {
            return seed;
        }
        tracing::warn!("[appchain] {} corrupt (expect 32 bytes) — regenerating", path.display());
    }
    let mut seed = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut seed);
    if let Err(e) = super::keys::write_secret_0600(&path, &seed) {
        tracing::error!(
            "[appchain] cannot persist {file_name} ({e}) — in-memory seed lost on restart"
        );
    } else {
        tracing::warn!(
            "[appchain] generated new {file_name} at {} — soft-confirm/attestation \
             identity is fresh (pre-existing pinned verifiers will not recognize it)",
            path.display()
        );
    }
    seed
}

impl AppchainConfig {
    /// 从环境解析（全部有 dev 缺省，无配置即可启动）。
    #[must_use]
    pub fn from_env() -> Self {
        let wal_dir = std::env::var("TEXAS_APPCHAIN_WAL_DIR")
            .unwrap_or_else(|_| "/tmp/texas-appchain".to_string());
        Self {
            enabled: std::env::var("TEXAS_APPCHAIN").ok().as_deref() != Some("0"),
            sequencer_seed: load_or_gen_seed("TEXAS_APPCHAIN_SEQUENCER_SEED", &wal_dir, "sequencer-seed"),
            attestor_seed: load_or_gen_seed("TEXAS_APPCHAIN_ATTESTOR_SEED", &wal_dir, "attestor-seed"),
            wal_dir,
            asset_class: match std::env::var("TEXAS_APPCHAIN_ASSET")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "real" => AssetClass::Real,
                _ => AssetClass::Play,
            },
            treasury_bps: std::env::var("TEXAS_APPCHAIN_TREASURY_BPS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2_000),
            provider: std::env::var("TEXAS_APPCHAIN_PROVIDER")
                .unwrap_or_else(|_| "mock".to_string())
                .to_ascii_lowercase(),
            poll_ms: std::env::var("TEXAS_APPCHAIN_POLL_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2_000),
            reconcile_secs: std::env::var("TEXAS_APPCHAIN_RECONCILE_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            prove_timeout_secs: std::env::var("TEXAS_APPCHAIN_PROVE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600),
            rake_bps: crate::pokergame::rake::rake_params().rake_bps,
            rake_cap: crate::pokergame::rake::rake_params().rake_cap,
        }
    }
}

/// 桥状态（游标/重试计数/对账缓存）。
#[derive(Default)]
pub struct BridgeState {
    /// 存款桥已处理游标（provider seq；重启后重放由 deposit_id 幂等兜底）。
    pub deposit_cursor: u64,
    /// 已成功打款累计（wei；对账回冲项）。
    pub paid_total: u128,
    /// 打款重试计数。
    pub pay_attempts: std::collections::HashMap<[u8; 32], u32>,
    /// 最近一次对账快照（导出/观测）。
    pub last_report: Option<serde_json::Value>,
}

/// 嵌入式 appchain 运行时（进程单例）。
pub struct AppchainRuntime {
    pub config: AppchainConfig,
    pub metrics: Arc<MetricsRegistry>,
    /// 证明管道（本地 prover；REAL = StarkRequired + 钉扎本进程 attestor）。
    pub pipeline: Arc<ProofPipeline>,
    /// 本进程 attestor 公钥（钉扎值）。
    pub attestor_public: [u8; 32],
    /// 嵌入式 sequencer（WAL 开启；Arc 以便 ProvenCallback 捕获）。
    seq: Arc<Mutex<Sequencer>>,
    /// 托管账（提现 finality 门 + 对账）。
    pub custody: Mutex<CustodyLedger>,
    /// 链上侧 provider。
    pub provider: Arc<dyn VaultProvider>,
    /// 桥状态。
    pub bridge: Mutex<BridgeState>,
}

static RUNTIME: OnceLock<Arc<AppchainRuntime>> = OnceLock::new();

impl AppchainRuntime {
    /// sequencer 独占访问。
    pub fn with_seq<T>(&self, f: impl FnOnce(&mut Sequencer) -> T) -> T {
        let mut seq = self.seq.lock().expect("sequencer lock");
        f(&mut seq)
    }

    /// 提交一笔操作并广播软确认（level=soft）。成功返回已签名帧。
    ///
    /// # Errors
    /// sequencer 拒绝（限流/准入/幂等）→ 对应 [`poker_appchain::error::AppchainError`]。
    pub fn submit_operation(&self, op: Operation) -> Result<SignedFrame, poker_appchain::error::AppchainError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(1);
        let frame = self.with_seq(|seq| seq.submit(op, now_ms))?;
        emit_soft_confirm(
            frame.frame.index,
            frame.frame.state_root,
            self.with_seq(|seq| seq.proven_watermark()),
            "soft",
        );
        Ok(frame)
    }

    /// 批次推进单轮（驱动点：后台循环 + 出证等待内联）。
    /// 有已验证批次时推水位 + `record_batch_root`（§5.4 finality 证据）并
    /// 广播 level=proven 软确认。
    pub fn drive_pipeline_once(&self) -> Option<poker_appchain::pipeline::BatchRoot> {
        match self.pipeline.try_build_batch() {
            Ok(Some(batch)) => {
                self.with_seq(|seq| seq.mark_proven_through_with_root(batch.through_op, batch.root));
                let (root, watermark) = self.with_seq(|seq| (seq.state().root(), seq.proven_watermark()));
                emit_soft_confirm(batch.through_op, root, watermark, "proven");
                Some(batch)
            }
            Ok(None) => None,
            Err(e) => {
                // REAL 钉扎/验证失败等：completion 保留、水位不动（管道语义），
                // 这里只记观测。
                tracing::warn!("[appchain] batch build rejected: {e}");
                None
            }
        }
    }

    /// 等待某 op 被证明覆盖（水位 ≥ op_index），期间驱动批次。
    ///
    /// # Errors
    /// 超时 → 文本错误（结算记录保持软确认态，由后续轮次继续推进）。
    pub fn await_proven(&self, op_index: u64, timeout: std::time::Duration) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            self.drive_pipeline_once();
            if self.with_seq(|seq| seq.proven_watermark()) >= op_index {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "prove wait timeout ({timeout:?}) at op {op_index}; watermark {}",
                    self.with_seq(|seq| seq.proven_watermark())
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// 桌绑定费率策略（开桌冻结；rake 参数与镜像/游戏层同源——配置快照，
    /// 费率关系 `rake.total == plan.rake == policy.rake_of(plan.rake_base())`
    /// （ABI v1.2.2）：FixedRake 与 settlement-core 的 contested-only 计费
    /// 同口径（含 cap），treasury/operator 收款人 = 嵌入式托管密钥。
    #[must_use]
    pub fn fee_policy(&self) -> FeePolicy {
        FeePolicy::FixedRake {
            rate_bps: self.config.rake_bps,
            cap: self.config.rake_cap,
            split: FeeSplit {
                treasury_bps: self.config.treasury_bps,
                treasury: self.treasury_key().public_bytes(),
                operator: self.operator_key().public_bytes(),
            },
        }
    }

    /// treasury appchain 密钥（确定性派生，见 keys 模块信任模型）。
    #[must_use]
    pub fn treasury_key(&self) -> OwnerKey {
        let mut felt = [0u8; 32];
        felt[30] = 0x7E;
        felt[31] = 0x5E;
        super::keys::owner_key_of(&felt)
    }

    /// operator appchain 密钥。
    #[must_use]
    pub fn operator_key(&self) -> OwnerKey {
        super::keys::owner_key_of(&self.config.sequencer_seed)
    }

    /// 已锁定的等待上限。
    #[must_use]
    pub fn prove_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.config.prove_timeout_secs.max(1))
    }

    /// 提现申请（B7 链下侧入口；未来可挂 HTTP endpoint）：烧一张 owner
    /// 名下 exact 面额的 REAL 余额 note，并向托管账入队（§5.4 finality
    /// 门在 enqueue 时强制：REAL payout note 须来源 op 已证明且批次根
    /// 已记录）。
    ///
    /// # Errors
    /// 无 exact 面额 note / 签名或准入拒绝 / finality 门拒绝 → 文本错误。
    #[allow(dead_code)] // bin 构建当前无 HTTP 路由（场景测试 + 未来 endpoint 保留）
    pub fn request_withdrawal(
        &self,
        wallet: &[u8; 32],
        amount: u64,
        request_id: [u8; 32],
        payout_address: [u8; 32],
    ) -> Result<(), String> {
        use poker_appchain::note::AssetClass;
        let key = super::keys::owner_key_of(wallet);
        let secret = super::keys::spend_secret_of(wallet);
        let owner = key.public_bytes();
        let note = self.with_seq(|seq| {
            seq.state()
                .notes
                .values()
                .find(|e| {
                    e.note.owner == owner
                        && e.note.amount == amount
                        && e.note.table_id.is_none()
                        && e.note.asset_class == AssetClass::Real
                })
                .map(|e| e.note.clone())
        })
        .ok_or_else(|| format!("no exact {amount}-wei REAL note for withdrawal"))?;
        let effect = Operation::WithdrawRequest {
            spend: poker_appchain::settlement::SpendAuth {
                commitment: [0; 32],
                nullifier: [0; 32],
                sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
            },
            note: note.clone(),
            request_id,
            // P1 审计字段：收款人进效果摘要并被 spend 签名覆盖——请求方
            // 显式传入的 payout_address 即打款目标。
            payout_recipient: payout_address,
        }
        .effect_digest();
        let nf = poker_appchain::felt::felt_to_bytes32(&note.nullifier(&secret));
        let d = poker_appchain::keys::spend_digest(
            &note.commitment_bytes(),
            &nf,
            poker_appchain::ops::scope::WITHDRAW,
            &effect,
        );
        let frame = self
            .submit_operation(Operation::WithdrawRequest {
                spend: poker_appchain::settlement::SpendAuth {
                    commitment: note.commitment_bytes(),
                    nullifier: nf,
                    sig: key.sign(&d),
                },
                note: note.clone(),
                request_id,
                payout_recipient: payout_address,
            })
            .map_err(|e| format!("withdraw burn rejected: {e}"))?;
        // provenance 消费后保留（note_origins）+ finality 证据快照。
        let (provenance, finality) = self.with_seq(|seq| {
            (seq.withdrawal_provenance(&note), seq.finality_evidence())
        });
        let provenance = provenance.ok_or("withdrawn note lost provenance")?;
        self.custody
            .lock()
            .expect("custody lock")
            .enqueue_withdrawal(
                poker_appchain::vault::WithdrawalRequest {
                    request_id,
                    payout_address,
                    amount,
                },
                provenance,
                finality,
            )
            .map_err(|e| format!("custody enqueue: {e}"))?;
        tracing::info!(
            "[appchain] withdrawal queued: {} wei at burn op {} (request 0x{})",
            amount,
            frame.frame.index,
            crate::starknet::chain::hex_encode(&request_id)
        );
        Ok(())
    }
}

/// 初始化（main.rs 启动流程调用一次）：WAL 重放/挂载 + pipeline 装配 +
/// 后台管线。失败（WAL 损坏等）返回 Err——调用方决定降级或拒绝启动。
///
/// # Errors
/// 嵌入式 sequencer 配置（new 与 WAL replay 必须同参，否则重放分叉）。
///
/// max_seats 抬到 1000：settle 只释放入池（total_bet>0）的 seat，未入池
/// 玩家的 seat note 会随动态买卖（bots bust 重注入 / 真人不同额买入）在
/// 账本累积，默认 10 在混桌几十手内必触 "table full"。生产多运营方部署
/// 应改为按桌清算闲置 seat（v2 语义），此处与嵌入式 dev 模型对齐。
fn sequencer_config() -> SequencerConfig {
    let mut config = SequencerConfig::default();
    config.max_seats = 1000;
    config
}

/// WAL 目录不可创建 / WAL 重放失败 → 文本错误。
pub fn init(config: AppchainConfig) -> Result<Arc<AppchainRuntime>, String> {
    std::fs::create_dir_all(&config.wal_dir)
        .map_err(|e| format!("appchain wal dir {}: {e}", config.wal_dir))?;
    // custody secret 装配（env 优先 / WAL 目录 load-or-generate）——必须在
    // 任何 owner_key_of/spend_secret_of 派生（fee_policy、结算、桥）之前。
    super::keys::init_custody_secret(std::path::Path::new(&config.wal_dir))?;
    let wal_path = std::path::Path::new(&config.wal_dir).join("sequencer.wal");
    let metrics = Arc::new(MetricsRegistry::new());
    let seq_key = SequencerKey::from_seed(&config.sequencer_seed);

    // WAL 优先恢复（fail-closed 重放），空/不存在则全新内存态。
    // 撕裂尾帧容崩：生产方启动时把 WAL 截回有效前缀（强杀可能留下半帧，
    // 严格重放会整链拒绝并让网关等消费方一起拒启）。消费方（网关）保持
    // 严格重放——生产方治愈、消费方纪律不变。
    let mut sequencer = if wal_path.exists() {
        let mut s = Sequencer::replay(&wal_path, seq_key.public, sequencer_config(), Arc::clone(&metrics))
            .map_err(|e| format!("appchain WAL replay failed: {e}"))?;
        // replay 实例携带占位签名密钥（重放只验签）。生产方继续追加出帧，
        // 必须重设真实密钥——否则所有新帧签名无效，网关/桥整链拒绝
        // （2026-09-17 长跑复现：每次重启后锚定冻结的终极根因）。
        s.set_signing_key(seq_key.clone());
        s
    } else {
        Sequencer::new(seq_key.clone(), sequencer_config(), Arc::clone(&metrics))
    };
    sequencer
        .attach_wal(&wal_path)
        .map_err(|e| format!("appchain WAL attach: {e}"))?;
    let seq = Arc::new(Mutex::new(sequencer));

    // 本地 prover（REAL=STARK 全验证 / PLAY=host attestation；钉扎本进程 attestor）。
    let attestor = ed25519_dalek::SigningKey::from_bytes(&config.attestor_seed);
    let attestor_public = attestor.verifying_key().to_bytes();
    let engine = Arc::new(
        TexasAirLocalProver::new(attestor).with_verifier_key(attestor_public),
    );

    // REAL 出证策略：StarkRequired + 钉扎本进程 attestor key（fail-closed）。
    let real_policy = RealSettlementPolicy::stark_required(attestor_public);

    let pipeline = ProofPipeline::with_real_policy(
        PipelineConfig {
            workers: 2,
            batch_size: 1, // 嵌入式运行时逐 op 出批：水位连续推进，deposit→buyin 不被证明缺口卡住
            queue_bound: 4_096,
            high_watermark: 3_000,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        real_policy,
    );

    // ProvenCallback（生产装配点）：批次验证通过 → 推水位（batch_root 由
    // drive_pipeline_once 携带 root 一并记录，见 mark_proven_through_with_root）。
    let cb: ProvenCallback = {
        let seq = Arc::clone(&seq);
        Arc::new(move |through| {
            seq.lock().expect("sequencer lock").mark_proven_through(through);
        })
    };
    pipeline.set_on_batch_proven(cb);

    // provider：devnet 默认 mock；生产配置 starknet（桥接既有 chips/chain）；
    // monad（proof_play 主线）——L1Bridge DepositInitiated 事件桥（见 monad_bridge）。
    let provider: Arc<dyn VaultProvider> = match config.provider.as_str() {
        "starknet" => {
            let vault_address = crate::starknet::chain()
                .map(|c| c.config.vault_address.clone())
                .unwrap_or_default();
            if vault_address.is_empty() {
                tracing::warn!("[appchain] STARKNET_APPCHAIN_PROVIDER=starknet but no vault address — falling back to mock");
                Arc::new(super::bridge::MockVaultProvider::new())
            } else {
                Arc::new(super::bridge::StarknetVaultProvider::from_env(vault_address))
            }
        }
        "monad" => match super::monad_bridge::MonadVaultProvider::from_env() {
            Ok(p) => {
                tracing::info!(
                    "[appchain] monad provider ready (rpc={}, bridge=0x{})",
                    p.rpc_url_for_log(),
                    hex::encode(p.bridge_for_log())
                );
                Arc::new(p)
            }
            Err(e) => {
                tracing::warn!(
                    "[appchain] TEXAS_APPCHAIN_PROVIDER=monad but config incomplete ({e}) — falling back to mock"
                );
                Arc::new(super::bridge::MockVaultProvider::new())
            }
        },
        _ => Arc::new(super::bridge::MockVaultProvider::new()),
    };

    // 托管账：提现 finality 门默认开启（§5.4 fail-closed）+ finality 拒绝计数。
    let custody = CustodyLedger::new().with_metrics(Arc::clone(&metrics));

    let runtime = Arc::new(AppchainRuntime {
        config: config.clone(),
        metrics,
        pipeline,
        attestor_public,
        seq,
        custody: Mutex::new(custody),
        provider,
        bridge: Mutex::new(BridgeState::default()),
    });

    RUNTIME
        .set(Arc::clone(&runtime))
        .map_err(|_| "appchain runtime already initialized".to_string())?;

    // B7 后台管线（存款桥/提现执行/自动对账）。
    super::bridge::spawn_bridge_tasks(Arc::clone(&runtime));

    // 崩溃恢复（2026-09-17 长跑复现）：上一进程若死于"Settle op 已落 WAL
    // 但批次未出证"，该 op 会永久挡住 mark_proven 的连续前缀——之后所有
    // 存款 note 停在 Unproven，每手 BuyIn 被 "note not proven" 拒绝，全部
    // 回退 legacy 路径（结算不上 appchain），锚定冻结。启动时扫描水位之上
    // 的 Settle op，重建 ProofJob 重新出证；水位一旦越过缺口，被挡的
    // 存款/拆分 op 经 proven_marks 连续化自动归位（note 状态随之修复）。
    {
        let pending: Vec<u64> = runtime.with_seq(|seq| {
            let wm = seq.proven_watermark();
            seq.chain()
                .iter()
                .filter(|f| f.frame.index > wm)
                .filter_map(|f| match &f.frame.op {
                    Operation::Settle(_) => Some(f.frame.index),
                    _ => None,
                })
                .collect()
        });
        if !pending.is_empty() {
            tracing::info!(
                "[appchain] recovery: {} unproven settle op(s) above watermark {} — resubmitting proofs",
                pending.len(),
                runtime.with_seq(|seq| seq.proven_watermark()),
            );
            let rt = Arc::clone(&runtime);
            std::thread::spawn(move || {
                for idx in pending {
                    // 逐个取出 record 重新提交（chain 内记录即结算事实源）。
                    let job_record = rt.with_seq(|seq| {
                        seq.chain()
                            .iter()
                            .find(|f| f.frame.index == idx)
                            .and_then(|f| match &f.frame.op {
                                Operation::Settle(record) => Some((**record).clone()),
                                _ => None,
                            })
                    });
                    let Some(record) = job_record else { continue };
                    let policy = rt.fee_policy();
                    let priority = match record
                        .inputs
                        .first()
                        .map(|i| i.note.asset_class)
                        .unwrap_or(AssetClass::Play)
                    {
                        AssetClass::Real => poker_appchain::pipeline::Priority::Real,
                        AssetClass::Play => poker_appchain::pipeline::Priority::Play,
                    };
                    if let Err(e) = rt.pipeline.submit(poker_appchain::pipeline::ProofJob {
                        op_index: idx,
                        table_id: record.table_id,
                        record: std::sync::Arc::new(record),
                        policy,
                        priority,
                    }) {
                        tracing::warn!("[appchain] recovery: resubmit op {idx} rejected: {e}");
                        continue;
                    }
                    match rt.await_proven(idx, rt.prove_timeout()) {
                        Ok(()) => tracing::info!("[appchain] recovery: op {idx} proven (watermark advanced)"),
                        Err(e) => tracing::warn!("[appchain] recovery: op {idx} proof pending after timeout: {e}"),
                    }
                }
                tracing::info!("[appchain] recovery pass complete: watermark={}",
                    rt.with_seq(|seq| seq.proven_watermark()));
            });
        }
    }

    tracing::info!(
        "[appchain] runtime ready: wal={} asset={:?} provider={} attestor=0x{} reconcile={}s",
        config.wal_dir,
        config.asset_class,
        config.provider,
        crate::starknet::chain::hex_encode(&attestor_public),
        config.reconcile_secs,
    );
    Ok(runtime)
}

/// 测试脚手架：注入完整运行时（不落 WAL、mock provider），并覆盖全局句柄。
/// 仅 `cfg(test)` 编译；全局句柄被占用时返回 None（测试串行化由调用方保证）。
#[cfg(test)]
pub fn init_for_test(
    config: AppchainConfig,
    provider: Arc<dyn VaultProvider>,
) -> Option<Arc<AppchainRuntime>> {
    // 固定测试 custody secret（进程单例；不落盘、不依赖环境）。
    super::keys::init_custody_secret_for_test([0x42; 32]);
    let runtime = build_for_test(config, provider);
    RUNTIME.set(Arc::clone(&runtime)).ok()?;
    Some(runtime)
}

/// 构造测试 runtime（不触全局单例——faucet 等多场景单测各建局部实例，
/// 避开 OnceLock 单初始化约束）。
#[cfg(test)]
pub(crate) fn build_for_test(
    config: AppchainConfig,
    provider: Arc<dyn VaultProvider>,
) -> Arc<AppchainRuntime> {
    // custody secret 固定测试值（owner/spend 密钥派生依赖；OnceLock 首设
    // 生效——全部测试同值，重复 set 无害）。
    super::keys::init_custody_secret_for_test([0x42; 32]);
    let metrics = Arc::new(MetricsRegistry::new());
    let seq_key = SequencerKey::from_seed(&config.sequencer_seed);
    let sequencer = Sequencer::new(seq_key, sequencer_config(), Arc::clone(&metrics));
    let seq = Arc::new(Mutex::new(sequencer));

    let attestor = ed25519_dalek::SigningKey::from_bytes(&config.attestor_seed);
    let attestor_public = attestor.verifying_key().to_bytes();
    let engine = Arc::new(
        TexasAirLocalProver::new(attestor).with_verifier_key(attestor_public),
    );
    let real_policy = RealSettlementPolicy::stark_required(attestor_public);
    let pipeline = ProofPipeline::with_real_policy(
        PipelineConfig {
            workers: 1,
            batch_size: 1,
            queue_bound: 64,
            high_watermark: 64,
            batch_interval_ms: 1_000,
        },
        engine,
        Arc::clone(&metrics),
        real_policy,
    );
    let cb: ProvenCallback = {
        let seq = Arc::clone(&seq);
        Arc::new(move |through| {
            seq.lock().expect("sequencer lock").mark_proven_through(through);
        })
    };
    pipeline.set_on_batch_proven(cb);
    let custody = Mutex::new(CustodyLedger::new().with_metrics(Arc::clone(&metrics)));
    Arc::new(AppchainRuntime {
        config,
        metrics,
        pipeline,
        attestor_public,
        seq,
        custody,
        provider,
        bridge: Mutex::new(BridgeState::default()),
    })
}

/// 全局句柄访问（未初始化返回 None——Appchain 出口未启用）。
#[must_use]
pub fn runtime() -> Option<&'static Arc<AppchainRuntime>> {
    RUNTIME.get()
}

/// 嵌入式模式下的玩家余额（wei）：按 runtime 资产类聚合其存续 note。
///
/// 这是 monad/嵌入式会话的筹码权威视图——`get_available_chips` 与
/// `/api/auth` 的 chipsAmount 在 runtime 启用时优先走这里（替代 Starknet
/// PokerVault 链上查询）；dev faucet、L1Bridge 存款桥铸的 note 都在此
/// 汇总。锁筹（locked_chips）由调用方扣减。
pub fn note_balance_wei(wallet_felt: &[u8; 32]) -> Option<u128> {
    let rt = runtime()?;
    let owner = super::keys::owner_key_of(wallet_felt).public_bytes();
    let asset = rt.config.asset_class;
    let total: u128 = rt
        .with_seq(|s| {
            s.state()
                .notes_of(&owner)
                .iter()
                .filter(|n| n.asset_class == asset)
                .map(|n| n.amount as u128)
                .sum()
        });
    Some(total)
}

/// `note_balance_wei` 的字符串入口（EVM/Starknet 钱包 hex 均可，≤31B 即合法 felt）。
pub fn note_balance_wei_of_address(address: &str) -> Option<u128> {
    use starknet::core::types::Felt;
    let felt = Felt::from_hex(address.trim().trim_start_matches("0x")).ok()?;
    note_balance_wei(&felt.to_bytes_be())
}

/// dev faucet（发现 5/11 统一通道，嵌入式嵌入模式）：给钱包直铸 PLAY
/// 余额note——zchain 模式下浏览器 dev 直签玩家与 bot 无需链上 RPC/账户
/// 部署即可上筹码（e2e 语料线 M3-2）。
///
/// fail-closed 面：非嵌入模式（runtime 未启用）拒绝；REAL 桌面拒绝
/// （**绝不无储备铸 REAL**——exit.rs 存款桥纪律同源）；`asset_class`
/// 钉死 [`AssetClass::Play`] 且无 env 面（编译期常量，不存在的开关不
/// 会被误开）。`nonce` 传 0 时用当前纳秒（同钱包同额度的重复领取靠它
/// 区分 deposit_id，防止幂等键撞车）。
pub fn dev_faucet_credit(
    wallet_felt: [u8; 32],
    amount: u64,
    nonce: u64,
) -> Result<u64, String> {
    let rt = runtime().ok_or_else(|| {
        "appchain runtime 未启用（非嵌入模式）——dev faucet 不可用".to_string()
    })?;
    faucet_submit(rt, wallet_felt, amount, nonce)
}

/// faucet 注入核心（显式 runtime——测试建局部实例，不触全局单例）。
pub(crate) fn faucet_submit(
    rt: &AppchainRuntime,
    wallet_felt: [u8; 32],
    amount: u64,
    nonce: u64,
) -> Result<u64, String> {
    faucet_asset_guard(rt.config.asset_class)?;
    let nonce = if nonce == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 | (d.as_secs() << 32))
            .unwrap_or(1)
    } else {
        nonce
    };
    let owner = super::keys::owner_key_of(&wallet_felt).public_bytes();
    let deposit_id = poker_appchain::keys::blake2s32(&[
        b"texas-appchain.dev-faucet.v1",
        &wallet_felt,
        &amount.to_be_bytes(),
        &nonce.to_be_bytes(),
    ]);
    let frame = rt
        .submit_operation(Operation::Deposit {
            deposit_id,
            owner,
            asset_class: AssetClass::Play,
            amount,
        })
        .map_err(|e| format!("faucet deposit rejected: {e}"))?;
    // 存款段立即证明化（与 seat deposit 同语义——嵌入式铸造即对账锚，
    // 绝不越过未证明的结算推进连续前缀）。
    rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
    Ok(frame.frame.index)
}

/// 资产守卫（纯函数——REAL 拒绝面单独可测；**绝不无储备铸 REAL**）。
fn faucet_asset_guard(asset: AssetClass) -> Result<(), String> {
    if asset != AssetClass::Play {
        return Err(format!(
            "结算资产类为 {asset:?}——REAL 桌面禁用 dev faucet（绝不无储备铸 REAL）"
        ));
    }
    Ok(())
}
