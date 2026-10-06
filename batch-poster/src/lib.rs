//! # batch-poster —— 常驻批量上链 daemon（op-batcher 形态）
//!
//! 2026-10-01 立项（docs/TODO.md #50；调研结论见
//! out/rollup-batch-submitter-survey.md §9 映射与建议——独立 crate（§9.1）
//! + 持久化队列（§9.2）+ 专门 txmgr（§9.3）+ cadence（§9.6）+ 监控最小集
//! （§9.7）+ 逃生机制（§9.8）。参照物：op-batcher
//! 主循环（publishingLoop/receiptsLoop + max-channel-duration 式 cadence）
//! / Arbitrum batch_poster / StarkEx Dispatcher+Blockchain Writer+Catcher
//! 三件套。
//!
//! ## 驱动契约（终审修订）
//!
//! - **route=Legacy**：payload 直用 texas 预构建 calldata，两笔驱动
//!   RegisterSent →（txmgr.wait_call_visible 等 settlement_digest view
//!   可见——吸收 texas submit.rs 旧 wait_register_visible 语义，该实现
//!   2026-10-01 随 txmgr 切换删除）→ SettleSent（对齐 submit_settlement
//!   返回 (register, settle) 二元组——两笔交易非单笔直发）；
//! - **route=Dual**：按条目 dapv_entry 选合约入口
//!   （[`proof::dual_settle_entry_name`]），register_hand →
//!   verify_and_settle_dapv 顺序两笔经 txmgr；dual 腿重试耗尽 → 写
//!   sidecar 死信信号，texas 读后执行 Dual→Legacy 降级重投（WAL
//!   Downgraded 事件），poster 观察 WAL 路由变化后清死信、按 legacy
//!   保底 payload 重投；
//! - **fold 攒批**（poster 运营配置开关，不绑任何现状 env）：Dual 条目
//!   聚 K≤64 且 2 的幂（`stark-recursion/src/chain.rs:63` 政策、:165-175
//!   校验、FoldBatchPlan `:388`）→ [`proof::ProofSource`] 出证
//!   （[`proof::ScriptProofSource`] 包 prove-batch.sh 两阶段腿，program_hash
//!   对拍锚 prove-batch.sh EXPECTED_PH 行）→ fold 批 calldata
//!   （`verify_and_settle_dapv_fold_private`，
//!   `poker_contracts/src/poker_dual_settlement.cairo:255`）或 Monad 工件
//!   （[`monad::MonadProofEnvelope`]）。
//!
//! ## 批级键域（键域闭合）
//!
//! 批记录在 poster sidecar，`batch_key = keccak_root`（同时是 zchain 侧
//! 幂等键与 MonadProofEnvelope 主键）、`members: Vec<(table_id, hand_id)>`
//! ——单手键只做队列去重，批键做批幂等。批回执回填批记录并逐 member 写
//! receipt sidecar。
//!
//! ## 单写者协议
//!
//! poster 只读 queue WAL（游标扫描尾部，`settle_queue::wal::scan_from`）；
//! 拾取/批/回执/死信写自有 sidecar（协议见 settle-queue crate 文档）；
//! texas 读 sidecar 转发 settle_receipt（REST/WS 数据源保持进程内权威
//! 不动）。
//!
//! ## 逃生与观测
//!
//! - [`PosterDriver::status`]（survey §9.7 监控最小集）+ HTTP JSON 端点
//!   （[`status::serve_status_once`]）；
//! - 手动 drain（[`PosterDriver::drain`]）：停止拾取、完成在途后退出。

pub mod batch;
pub mod config;
pub mod monad;
pub mod proof;
pub mod status;

use std::collections::HashMap;
use std::sync::Arc;

use balance_rollup::BalanceRollup;
use settle_queue::sidecar::{
    BatchRecord, BatchState, DeadRecord, InFlightTask, PosterSidecar, ReceiptRecord,
};
use settle_queue::state::SubmitPhase;
use settle_queue::task::{
    BalanceEntry, FoldStatement, LegCalldata, SettleKey, SettlePayload, SettleRoute, SettleTask,
};
use settle_queue::wal::{self, WalEvent};
use starknet_txmgr::{
    Call, ReplayVerdict, SendOutcome, StarknetSend, TxError, TxManager, wait_call_visible,
};
use starknet_types_core::felt::Felt;

pub use config::PosterConfig;
pub use status::PosterStatus;

/// poster 错误。
#[derive(Debug, thiserror::Error)]
pub enum PosterError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("wal: {0}")]
    Wal(#[from] wal::WalError),
    #[error("send: {0}")]
    Send(String),
    #[error("proof: {0}")]
    Proof(String),
    #[error("balance rollup: {0}")]
    Balance(#[from] balance_rollup::RollupError),
    #[error("ledger mirror: {0}")]
    Ledger(#[from] balance_rollup::ledger::LedgerError),
    #[error("config: {0}")]
    Config(String),
}

/// 逐手驱动相位（settle-queue 状态机的 poster 驱动视图；Picked = 已拾取
/// 未广播）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrivePhase {
    Picked,
    RegisterSent,
    RegisterVisible,
    SettleSent,
}

impl DrivePhase {
    fn submit_phase(self) -> Option<SubmitPhase> {
        match self {
            DrivePhase::Picked => None,
            DrivePhase::RegisterSent => Some(SubmitPhase::RegisterSent),
            DrivePhase::RegisterVisible => Some(SubmitPhase::RegisterVisible),
            DrivePhase::SettleSent => Some(SubmitPhase::SettleSent),
        }
    }
}

/// poster 内的待驱动任务。
pub struct PendingTask {
    pub task: SettleTask,
    pub phase: DrivePhase,
    pub attempts: u32,
    pub picked_at: u64,
    pub txs: Vec<String>,
    /// dual 死信等待 texas 降级中（不驱动）。
    pub blocked: bool,
    /// 已写回执/终态（tick 末清理）。
    pub finished: bool,
}

impl PendingTask {
    fn new(task: SettleTask, now: u64) -> Self {
        Self {
            task,
            phase: DrivePhase::Picked,
            attempts: 0,
            picked_at: now,
            txs: Vec::new(),
            blocked: false,
            finished: false,
        }
    }

    /// fold 成员资格：Dual、可入批（有语句面）、尚未开腿。
    fn fold_eligible(&self) -> bool {
        self.task.route == SettleRoute::Dual
            && self.task.payload.fold_statement.is_some()
            && self.phase == DrivePhase::Picked
            && !self.blocked
    }
}

/// fold 批运行时。
pub struct BatchRuntime {
    pub record: BatchRecord,
    /// 批成员（顺序 = 语句面顺序；提交逐 member）。
    pub members: Vec<PendingTask>,
    /// 出证产物（Submitting 后存在；恢复期缺失则回 Forming 重出证）。
    pub artifact: Option<proof::ProofArtifact>,
    /// 出证/提交重试计数。
    pub attempts: u32,
    /// 下一个待提交成员下标。
    pub next_member: usize,
}

/// 一轮 tick 的观测报告。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickReport {
    pub picked: usize,
    pub downgrades_applied: usize,
    pub build_dead_dropped: usize,
    pub tasks_driven: usize,
    pub receipts_written: usize,
    pub dead_letters_written: usize,
    pub batches_formed: usize,
    pub batches_receipted: usize,
    /// 余额树入树手数（escape 地基随回执推进）。
    pub balance_applied: usize,
    /// 回执但缺 balance_entry 的手数（升级前历史条目——未入树，可观测）。
    pub balance_skipped: usize,
}

/// 常驻驱动器。
pub struct PosterDriver<S: StarknetSend, P: proof::ProofSource> {
    cfg: PosterConfig,
    sidecar: PosterSidecar,
    txmgr: Arc<TxManager<S>>,
    proofs: Arc<P>,
    cursor: u64,
    pending: Vec<PendingTask>,
    batches: Vec<BatchRuntime>,
    draining: bool,
    /// 累加链尾（上一 Receipted 批的 batch_fact；None = genesis 0x0）。
    last_batch_fact: Option<String>,
    /// 余额树（escape 地基；cfg.balance.enabled 时 Some——回执驱动推进，
    /// 批 Receipted 快照根入批记录 + 伴随工件）。
    rollup: Option<BalanceRollup>,
    /// 账本镜像（escape-ledger：账本面增量根随批推进——与 rollup 同点
    /// 应用，幂等源仍是 rollup applied 集合）。
    ledger: Option<balance_rollup::ledger::LedgerMirror>,
    legacy_visibility_selector: Felt,
    fold_settle_selector: Felt,
}

// 入口 selector（starknet_keccak 镜像：keccak256 摘要高 6 位清零入域——
// starknet-core utils.rs starknet_keccak 同式；texas 用
// `starknet::core::utils::starknet_keccak`（submit.rs 的 calldata 构建同源），
// 本 crate 不引重型 starknet 依赖，按同公式本地实现）。
fn selector_of_name(name: &str) -> Felt {
    use sha3::Digest as _;
    let mut hash: [u8; 32] = sha3::Keccak256::digest(name.as_bytes()).into();
    hash[0] &= 0b0000_0011;
    Felt::from_bytes_be(&hash)
}

/// 批 statements 伴随工件（DA L1，`<batch_key>.statements.json`）：批
/// fact 的 preimage 全量公开——每条 FoldStatement（program_hash /
/// hand_binding / fact）随批落盘，任何人不依赖 operator 即可离线重算
/// `keccak_batch_root(statements) == keccak_root`（groth16-wrap 同式、
/// zchain SettleBatch 逐字一致）完成 fact ↔ 语句面绑定复核，防抵赖。
/// M2 落 spool 目录；链上 calldata 公开腿随 M4/M5（与 balance_root
/// 同节奏，见 docs/design 排期 §2.2）。
pub(crate) fn write_statements_companion(
    spool_dir: &std::path::Path,
    input: &batch::FoldBatchInput,
    batch_fact: &str,
    program_hash: &str,
    keccak_root_hex: &str,
    at: u64,
) -> std::io::Result<()> {
    #[derive(serde::Serialize)]
    struct StatementsArtifact<'a> {
        /// 批键 = keccak_batch_root(statements)（离线复核锚）。
        keccak_root: &'a str,
        batch_fact: &'a str,
        acc_prev: &'a str,
        program_hash: &'a str,
        members: &'a [SettleKey],
        /// fact preimage 逐条语句（~2KB/批量级）。
        statements: &'a [FoldStatement],
        at: u64,
    }
    let name = keccak_root_hex.trim_start_matches("0x");
    let path = spool_dir.join(format!("{name}.statements.json"));
    settle_queue::sidecar::atomic_write_json(
        &path,
        &StatementsArtifact {
            keccak_root: keccak_root_hex,
            batch_fact,
            acc_prev: &input.acc_prev,
            program_hash,
            members: &input.members,
            statements: &input.statements,
            at,
        },
    )
}

/// 余额根伴随工件（spool 目录，`<batch_key>.balance.json`）：随 fold 批
/// 落盘的余额根登记面（escape 地基 M2——「随批上链」的载体；链上登记
/// 腿在 M4/M5 接合约入口）。**刻意不动 MonadProofEnvelope**：那是 zchain
/// 侧冻结键集断言的跨仓契约，加字段须跨仓同步——伴随文件同目录同名
/// 前缀，zchain 消费方可选读，不读不影响结算。
pub(crate) fn write_balance_companion(
    spool_dir: &std::path::Path,
    batch_key: &str,
    balance_root: &str,
    members: &[SettleKey],
    at: u64,
) -> std::io::Result<()> {
    #[derive(serde::Serialize)]
    struct BalanceCompanion<'a> {
        /// 批键 = keccak_root（与信封主键同键域，关联读）。
        keccak_root: &'a str,
        /// 批完成时的余额树根（累计面，checkpoint 语料可回放复核）。
        balance_root: &'a str,
        members: &'a [SettleKey],
        at: u64,
    }
    let name = batch_key.trim_start_matches("0x");
    let path = spool_dir.join(format!("{name}.balance.json"));
    settle_queue::sidecar::atomic_write_json(
        &path,
        &BalanceCompanion {
            keccak_root: batch_key,
            balance_root,
            members,
            at,
        },
    )
}

impl<S: StarknetSend, P: proof::ProofSource> PosterDriver<S, P> {
    pub fn new(cfg: PosterConfig, send: Arc<S>, proofs: Arc<P>) -> Result<Self, PosterError> {
        cfg.validate().map_err(PosterError::Config)?;
        let sidecar = PosterSidecar::open(&cfg.sidecar_dir)?;
        let txmgr = Arc::new(TxManager::new(send, cfg.txmgr.clone()));
        // 余额树（escape 地基）：叶子格式随隐私档位（docs §3——
        // transparent=明文叶 / shielded=承诺叶）。
        let rollup = match (&cfg.privacy, cfg.balance.enabled) {
            (Some(plan), true) => {
                let leaf = match plan.leaf_format {
                    privacy_profile::BalanceLeafFormat::Plain => {
                        balance_rollup::LeafFormat::Plain
                    }
                    privacy_profile::BalanceLeafFormat::Commitment => {
                        balance_rollup::LeafFormat::Commitment
                    }
                };
                Some(
                    BalanceRollup::open(
                        &cfg.balance.state_path,
                        &cfg.balance.checkpoint_path,
                        leaf,
                    )
                    .map_err(PosterError::from)?,
                )
            }
            _ => None,
        };
        let ledger = match (&cfg.privacy, cfg.balance.enabled) {
            (Some(_), true) => Some(
                balance_rollup::ledger::LedgerMirror::open(
                    &cfg.balance.ledger_state_path,
                    cfg.balance.ledger_unit_divisor,
                )
                .map_err(PosterError::from)?,
            ),
            _ => None,
        };
        Ok(Self {
            txmgr,
            sidecar,
            cfg,
            proofs,
            cursor: 0,
            pending: Vec::new(),
            batches: Vec::new(),
            draining: false,
            last_batch_fact: None,
            rollup,
            ledger,
            legacy_visibility_selector: selector_of_name("settlement_digest"),
            fold_settle_selector: selector_of_name(proof::FOLD_SETTLE_ENTRY),
        })
    }

    pub fn sidecar(&self) -> &PosterSidecar {
        &self.sidecar
    }

    pub fn draining(&self) -> bool {
        self.draining
    }

    /// 手动 drain 逃生口：置位后停止拾取新任务，完成在途后 [`Self::run`]
    /// 返回。
    pub fn drain(&mut self) {
        self.draining = true;
    }

    /// 崩溃恢复：WAL 全量重放 + sidecar 对账（回执幂等跳过、终态死信跳过、
    /// 已降级清死信重投、未终态批装载）——「重启对账续投」。
    pub fn recover(&mut self) -> Result<(), PosterError> {
        let state = wal::replay(&self.cfg.queue_wal)?;
        self.cursor = state.last_seq();
        let poster_state = self.sidecar.read_state()?;
        self.draining = poster_state.as_ref().is_some_and(|s| s.draining);
        let inflight: HashMap<SettleKey, InFlightTask> = poster_state
            .map(|s| s.in_flight.into_iter().map(|t| (t.key, t)).collect())
            .unwrap_or_default();
        let dead: HashMap<SettleKey, DeadRecord> = self
            .sidecar
            .list_dead()?
            .into_iter()
            .map(|d| (d.key, d))
            .collect();

        for record in state.records() {
            let key = record.task.key;
            // 回执幂等：已 Receipted 的键不重投。
            if self.sidecar.read_receipt(&key)?.is_some() {
                continue;
            }
            // WAL 终态（构建期死信）不驱动。
            if record.state.is_terminal() {
                continue;
            }
            let mut blocked = false;
            if let Some(d) = dead.get(&key) {
                match (d.route_at_death, record.task.route) {
                    (SettleRoute::Legacy, _) => continue, // 终态死信（含降级后仍耗尽）
                    (SettleRoute::Dual, SettleRoute::Legacy) => {
                        // texas 已降级（WAL 路由已变）：清死信、按 legacy 重投。
                        self.sidecar.clear_dead(&key)?;
                    }
                    (SettleRoute::Dual, SettleRoute::Dual) => blocked = true, // 等 texas 降级
                }
            }
            let snap = inflight.get(&key);
            let mut t =
                PendingTask::new(record.task.clone(), snap.map(|s| s.picked_at).unwrap_or(0));
            if let Some(s) = snap {
                t.phase = s
                    .phase
                    .map(|p| match p {
                        SubmitPhase::RegisterSent => DrivePhase::RegisterSent,
                        SubmitPhase::RegisterVisible => DrivePhase::RegisterVisible,
                        SubmitPhase::SettleSent => DrivePhase::SettleSent,
                    })
                    .unwrap_or(DrivePhase::Picked);
                t.attempts = s.attempts;
                t.txs = s.txs.clone();
            }
            t.blocked = blocked;
            self.pending.push(t);
        }

        // 未终态批装载（成员从 pending 移入；已回执成员计数推进）。
        for rec in self.sidecar.list_batches()? {
            if matches!(rec.state, BatchState::Receipted | BatchState::Dead) {
                continue;
            }
            let members: Vec<PendingTask> = rec
                .members
                .iter()
                .filter_map(|k| self.take_pending(k))
                .collect();
            let next_member = members
                .iter()
                .filter(|m| {
                    self.sidecar
                        .read_receipt(&m.task.key)
                        .ok()
                        .flatten()
                        .is_some()
                })
                .count();
            self.batches.push(BatchRuntime {
                record: rec,
                members,
                artifact: None,
                attempts: 0,
                next_member,
            });
        }
        // 累加链尾 = 最近一个 Receipted 批的批键（信封 acc_prev 由 zchain 侧
        // 复核链式咬合）。
        self.last_batch_fact = self
            .sidecar
            .list_batches()?
            .into_iter()
            .filter(|b| b.state == BatchState::Receipted)
            .max_by_key(|b| b.created_at)
            .map(|b| b.batch_key);
        Ok(())
    }

    fn take_pending(&mut self, key: &SettleKey) -> Option<PendingTask> {
        let idx = self.pending.iter().position(|t| t.task.key == *key)?;
        Some(self.pending.remove(idx))
    }

    /// 一轮驱动（系统时钟）。
    pub async fn tick(&mut self) -> Result<TickReport, PosterError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.tick_at(now).await
    }

    /// 一轮驱动（注入时钟——测试确定性）。
    pub async fn tick_at(&mut self, now: u64) -> Result<TickReport, PosterError> {
        let mut report = TickReport::default();
        // 1) WAL 增量扫描（游标推进）。
        let (events, cursor) = wal::scan_from(&self.cfg.queue_wal, self.cursor)?;
        for (_, event) in events {
            match event {
                WalEvent::Enqueued { task } => {
                    if self.draining {
                        continue; // drain 期不拾取。
                    }
                    if self.pickable(&task.key)? {
                        self.pending.push(PendingTask::new(*task, now));
                        report.picked += 1;
                    }
                }
                WalEvent::Downgraded { key } => {
                    if let Some(t) = self.pending.iter_mut().find(|t| t.task.key == key) {
                        // fail-closed：降级必须带 legacy 保底 payload
                        //（无保底 = 投递期死信，绝不拿 dual calldata 冒充）。
                        if t.task.legacy_fallback.is_none() {
                            self.sidecar.write_dead(&DeadRecord {
                                key,
                                route_at_death: SettleRoute::Legacy,
                                reason: "downgraded without legacy fallback payload".into(),
                                attempts: t.attempts,
                                at: now,
                            })?;
                            t.blocked = true;
                        } else {
                            t.task.route = SettleRoute::Legacy;
                            t.attempts = 0;
                            t.phase = DrivePhase::Picked;
                            t.txs.clear();
                            t.blocked = false;
                            self.sidecar.clear_dead(&key)?;
                        }
                        report.downgrades_applied += 1;
                    }
                }
                WalEvent::BuildDeadLettered { key, .. } => {
                    // texas 构建期死信：条目终态，poster 停驱动。
                    self.pending.retain(|t| t.task.key != key);
                    report.build_dead_dropped += 1;
                }
            }
        }
        self.cursor = cursor;

        // 2) 批推进（先于逐手——fold 优先消费 dual 候选）。
        self.drive_batches_at(now, &mut report).await?;
        // 3) 攒批。
        if self.cfg.fold.enabled && !self.draining {
            self.form_batches_at(now, &mut report)?;
        }
        // 4) 逐手推进。
        self.drive_tasks_at(now, &mut report).await?;
        // 5) poster-state 落盘。
        self.persist(now)?;
        Ok(report)
    }

    fn pickable(&self, key: &SettleKey) -> Result<bool, PosterError> {
        if self.sidecar.read_receipt(key)?.is_some() {
            return Ok(false); // 回执幂等。
        }
        if self.sidecar.read_dead(key)?.is_some() {
            // 死信在案：Dual 等降级事件（tick/recover 处理）、Legacy 终态
            //——都不在此重拾，避免降级前重发 dual 腿/复活终态。
            return Ok(false);
        }
        Ok(true)
    }

    fn route_contract(&self, route: SettleRoute) -> Felt {
        match route {
            SettleRoute::Legacy => self.cfg.legacy_settlement,
            SettleRoute::Dual => self.cfg.dual_settlement,
        }
    }

    fn leg_call(&self, route: SettleRoute, leg: &LegCalldata) -> Result<Call, PosterError> {
        let contract = self.route_contract(route);
        let selector = config::parse_felt_hex(&leg.selector)
            .ok_or_else(|| PosterError::Config(format!("selector hex 非法: {}", leg.selector)))?;
        let calldata = leg
            .calldata
            .iter()
            .map(|w| config::parse_felt_hex(w))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| PosterError::Config("calldata hex 非法".into()))?;
        Ok(Call::new(contract, selector, calldata))
    }

    fn fold_settle_call(
        &self,
        hand_binding_hex: &str,
        hand_id: u32,
        segment: &[String],
    ) -> Result<Call, PosterError> {
        let mut calldata = vec![
            config::parse_felt_hex(hand_binding_hex)
                .ok_or_else(|| PosterError::Config("hand_binding hex 非法".into()))?,
            Felt::from(hand_id),
        ];
        for w in segment {
            calldata.push(
                config::parse_felt_hex(w)
                    .ok_or_else(|| PosterError::Config("segment word hex 非法".into()))?,
            );
        }
        Ok(Call::new(
            self.cfg.dual_settlement,
            self.fold_settle_selector,
            calldata,
        ))
    }

    fn max_attempts_for(&self, route: SettleRoute) -> u32 {
        match route {
            SettleRoute::Dual => self.cfg.dual_max_attempts,
            SettleRoute::Legacy => self.cfg.legacy_max_attempts,
        }
    }

    /// 回执落盘 + 余额树推进（escape 地基：先入树落盘、后写 receipt——
    /// 幂等由 rollup applied 集合保证，崩溃任一侧都不重放）。缺
    /// `balance_entry` 的回执（升级前历史条目）跳过入树但计数可观测；
    /// 树拒绝（非零和/下穿）= tick 级错误停驱动——余额树与链上事实分歧
    /// 绝不静默。
    fn write_receipt(
        &mut self,
        key: SettleKey,
        route: SettleRoute,
        txs: Vec<String>,
        batch_key: Option<String>,
        balance: Option<&BalanceEntry>,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        match (self.rollup.as_mut(), balance) {
            (Some(rollup), Some(entry)) => {
                let players = entry
                    .players
                    .iter()
                    .map(|h| config::parse_felt_hex(h))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| {
                        PosterError::Proof(format!("{key}: balance_entry player hex 非法"))
                    })?;
                rollup
                    .apply(
                        key.table_id,
                        key.hand_id,
                        &players,
                        &entry.deltas_wei,
                        batch_key.as_deref(),
                        now,
                    )
                    .map_err(PosterError::from)?;
                if let Some(ledger) = self.ledger.as_mut() {
                    let felt_bytes: Vec<[u8; 32]> = players
                        .iter()
                        .map(|f| f.to_bytes_be())
                        .collect();
                    ledger
                        .apply_entry(&felt_bytes, &entry.deltas_wei)
                        .map_err(PosterError::from)?;
                }
                report.balance_applied += 1;
            }
            (Some(_), None) => {
                report.balance_skipped += 1;
                eprintln!(
                    "[batch-poster] {key} 回执但缺 balance_entry（升级前历史条目）——未入余额树"
                );
            }
            (None, _) => {}
        }
        self.sidecar.write_receipt(&ReceiptRecord {
            key,
            route,
            txs,
            batch_key,
            at: now,
        })?;
        Ok(())
    }

    /// 一腿失败：poster 接管 txmgr 停机位（resume——poster 是停机位的
    /// 「人工」恢复代理，有界重试纪律在本层），按路由上限计数，耗尽写
    /// 投递期死信（dual = 降级候选；legacy = 终态）。
    fn leg_failed(
        &mut self,
        idx: usize,
        reason: String,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        self.txmgr.resume_after_halt();
        let route = self.pending[idx].task.route;
        let key = self.pending[idx].task.key;
        let attempts = self.pending[idx].attempts + 1;
        self.pending[idx].attempts = attempts;
        if attempts >= self.max_attempts_for(route) {
            self.sidecar.write_dead(&DeadRecord {
                key,
                route_at_death: route,
                reason,
                attempts,
                at: now,
            })?;
            report.dead_letters_written += 1;
            if route == SettleRoute::Dual {
                // 降级候选：保留在 pending（blocked），等 texas 写 WAL 降级。
                self.pending[idx].blocked = true;
            } else {
                // Legacy 终态死信：停发观察。
                self.pending[idx].finished = true;
            }
        }
        Ok(())
    }

    async fn drive_tasks_at(
        &mut self,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        let account = self.cfg.operator_account;
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].blocked || self.pending[i].finished {
                i += 1;
                continue;
            }
            let route = self.pending[i].task.route;
            let key = self.pending[i].task.key;
            let hand_id = key.hand_id;
            let payload: SettlePayload = self.pending[i].task.effective_payload().clone();
            match self.pending[i].phase {
                DrivePhase::Picked => {
                    let call = self.leg_call(route, &payload.register)?;
                    match self
                        .txmgr
                        .submit_ordered(account, "register", vec![call])
                        .await
                    {
                        Ok(SendOutcome::Receipted(r)) => {
                            self.pending[i].phase = DrivePhase::RegisterSent;
                            self.pending[i].txs.push(format!("{:#x}", r.tx_hash));
                            report.tasks_driven += 1;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::RegisterReplay)) => {
                            // 已注册幂等重放 → register 相已完成（可见性由
                            // 下一步 view 断言/直通）。
                            self.pending[i].phase = DrivePhase::RegisterSent;
                            report.tasks_driven += 1;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::SettleReplay)) => {
                            // 整手已结算：终态回执。
                            let balance = self.pending[i].task.balance_entry.clone();
                            self.write_receipt(
                                key,
                                route,
                                self.pending[i].txs.clone(),
                                None,
                                balance.as_ref(),
                                now,
                                report,
                            )?;
                            self.pending[i].finished = true;
                            report.receipts_written += 1;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::NotReplay)) => {
                            // txmgr 不产生该组合（NotReplay 不会以幂等语义返回）
                            //——防御分支：计失败。
                            self.leg_failed(
                                i,
                                "register leg: not-replay invariant".into(),
                                now,
                                report,
                            )?;
                        }
                        Err(TxError::Broadcast { last, .. }) => {
                            self.leg_failed(i, format!("register leg: {last}"), now, report)?;
                        }
                        Err(e) => return Err(PosterError::Send(e.to_string())),
                    }
                }
                DrivePhase::RegisterSent => match route {
                    SettleRoute::Legacy => {
                        // 两笔包含时差：等 register 在链上可见再发 settle
                        //（旧 wait_register_visible 语义，判定归 txmgr 层）。
                        match wait_call_visible(
                            self.txmgr.send(),
                            self.cfg.legacy_settlement,
                            self.legacy_visibility_selector,
                            vec![Felt::from(hand_id)],
                            &self.cfg.visible,
                        )
                        .await
                        {
                            Ok(()) => {
                                self.pending[i].phase = DrivePhase::RegisterVisible;
                                report.tasks_driven += 1;
                            }
                            Err(e) => {
                                self.leg_failed(
                                    i,
                                    format!("register visibility: {e}"),
                                    now,
                                    report,
                                )?;
                            }
                        }
                    }
                    // dual 路：register_hand 的可见性 view 待合约接口接线，
                    // 骨架直通（两笔仍顺序提交——第二笔在下一 tick）。
                    SettleRoute::Dual => {
                        self.pending[i].phase = DrivePhase::RegisterVisible;
                        report.tasks_driven += 1;
                    }
                },
                DrivePhase::RegisterVisible | DrivePhase::SettleSent => {
                    let entry =
                        proof::dual_settle_entry_name(self.pending[i].task.dapv_entry.as_deref());
                    let tag = match route {
                        SettleRoute::Legacy => "settle",
                        SettleRoute::Dual => entry,
                    };
                    let call = self.leg_call(route, &payload.settle)?;
                    match self.txmgr.submit_ordered(account, tag, vec![call]).await {
                        Ok(SendOutcome::Receipted(r)) => {
                            let mut txs = self.pending[i].txs.clone();
                            txs.push(format!("{:#x}", r.tx_hash));
                            let balance = self.pending[i].task.balance_entry.clone();
                            self.write_receipt(
                                key,
                                route,
                                txs,
                                None,
                                balance.as_ref(),
                                now,
                                report,
                            )?;
                            self.pending[i].finished = true;
                            report.receipts_written += 1;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::SettleReplay)) => {
                            let balance = self.pending[i].task.balance_entry.clone();
                            self.write_receipt(
                                key,
                                route,
                                self.pending[i].txs.clone(),
                                None,
                                balance.as_ref(),
                                now,
                                report,
                            )?;
                            self.pending[i].finished = true;
                            report.receipts_written += 1;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::RegisterReplay)) => {
                            // settle 腿出现注册相文案 = 异常，计失败。
                            self.leg_failed(
                                i,
                                "settle leg: register-replay text".into(),
                                now,
                                report,
                            )?;
                        }
                        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::NotReplay)) => {
                            self.leg_failed(
                                i,
                                "settle leg: not-replay invariant".into(),
                                now,
                                report,
                            )?;
                        }
                        Err(TxError::Broadcast { last, .. }) => {
                            self.leg_failed(i, format!("settle leg: {last}"), now, report)?;
                        }
                        Err(e) => return Err(PosterError::Send(e.to_string())),
                    }
                }
            }
            i += 1;
        }
        self.pending.retain(|t| !t.finished);
        Ok(())
    }

    fn form_batches_at(&mut self, now: u64, report: &mut TickReport) -> Result<(), PosterError> {
        let candidates: Vec<usize> = (0..self.pending.len())
            .filter(|&i| self.pending[i].fold_eligible())
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let count = candidates.len();
        let oldest = self
            .pending
            .iter()
            .filter(|t| t.fold_eligible())
            .map(|t| t.picked_at)
            .min()
            .unwrap_or(now);
        let age = now.saturating_sub(oldest);
        if !batch::should_publish(count, age, &self.cfg.cadence) {
            return Ok(());
        }
        let size = batch::plan_batch_size(count, self.cfg.cadence.max_batch_hands);
        if size == 0 || size > count {
            return Ok(());
        }
        let chosen: Vec<usize> = candidates.into_iter().take(size).collect();
        let statements: Vec<FoldStatement> = chosen
            .iter()
            .filter_map(|&i| self.pending[i].task.payload.fold_statement.clone())
            .collect();
        if statements.len() != size {
            return Ok(()); // 语句面缺失（理论不可达——fold_eligible 已筛）。
        }
        let key = batch::compute_batch_key(&statements).map_err(PosterError::Proof)?;
        let batch_key_hex = format!("0x{}", hex::encode(key));
        // 批幂等：sidecar 已有同键未终态批（恢复冲突）则不再形成。
        if let Some(existing) = self.sidecar.read_batch(&batch_key_hex)?
            && !matches!(existing.state, BatchState::Receipted | BatchState::Dead)
        {
            return Ok(());
        }
        let members: Vec<SettleKey> = chosen.iter().map(|&i| self.pending[i].task.key).collect();
        let record = BatchRecord {
            batch_key: batch_key_hex,
            members,
            state: BatchState::Forming,
            receipt_tx: None,
            balance_root: None,
            created_at: now,
        };
        self.sidecar.write_batch(&record)?;
        // rev 移除保下标有效，再逆回保持语句面顺序。
        let mut taken: Vec<PendingTask> = chosen
            .into_iter()
            .rev()
            .map(|i| self.pending.remove(i))
            .collect();
        taken.reverse();
        for t in taken.iter_mut() {
            t.phase = DrivePhase::Picked;
            t.blocked = false;
            t.finished = false;
        }
        self.batches.push(BatchRuntime {
            record,
            members: taken,
            artifact: None,
            attempts: 0,
            next_member: 0,
        });
        report.batches_formed += 1;
        Ok(())
    }

    async fn drive_batches_at(
        &mut self,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        let mut receipted = Vec::new();
        for bi in 0..self.batches.len() {
            match self.batches[bi].record.state {
                BatchState::Forming | BatchState::Proving => {
                    self.prove_batch_step(bi, now, report).await?;
                }
                BatchState::Submitting => {
                    self.submit_batch_step(bi, now, report).await?;
                    if self.batches[bi].record.state == BatchState::Receipted {
                        receipted.push(bi);
                    }
                }
                BatchState::Receipted | BatchState::Dead => {}
            }
        }
        for bi in receipted.into_iter().rev() {
            self.batches.remove(bi);
        }
        Ok(())
    }

    /// 出证步（Forming/Proving → Submitting | Dead）。program_hash 对拍锚 +
    /// 批根两宿主交叉核对 + Monad 信封落盘。
    async fn prove_batch_step(
        &mut self,
        bi: usize,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        let statements: Vec<FoldStatement> = self.batches[bi]
            .members
            .iter()
            .filter_map(|m| m.task.payload.fold_statement.clone())
            .collect();
        let keys: Vec<SettleKey> = self.batches[bi]
            .members
            .iter()
            .map(|m| m.task.key)
            .collect();
        let acc_prev = self.last_batch_fact.clone().unwrap_or_else(|| "0x0".into());
        let input = batch::FoldBatchInput {
            members: keys,
            statements,
            acc_prev: acc_prev.clone(),
        };
        match self.proofs.prove_batch(&input).await {
            Ok(artifact) => {
                // 对拍锚：program_hash 与钉扎值（prove-batch.sh EXPECTED_PH 行）一致。
                if !artifact
                    .program_hash
                    .eq_ignore_ascii_case(&self.cfg.fold.expected_program_hash)
                {
                    return Err(PosterError::Proof(format!(
                        "program_hash {} != 钉扎 {}（拒绝上链）",
                        artifact.program_hash, self.cfg.fold.expected_program_hash
                    )));
                }
                // 批根交叉核对（ProofSource 派生 vs poster 宿主派生）。
                let host =
                    batch::compute_batch_key(&input.statements).map_err(PosterError::Proof)?;
                if artifact.keccak_root != host {
                    return Err(PosterError::Proof("keccak 批根两宿主不一致".into()));
                }
                // Monad 工件落盘（TEXAS_MONAD_SPOOL_DIR）。
                let envelope = monad::MonadProofEnvelope::from_artifact(&artifact, &acc_prev, now);
                envelope.spool_to(&self.cfg.monad_spool_dir)?;
                // DA L1：批 statements preimage 随批公开（fact 绑定语句面，
                // 防抵赖）。
                let keccak_root_hex = format!("0x{}", hex::encode(artifact.keccak_root));
                write_statements_companion(
                    &self.cfg.monad_spool_dir,
                    &input,
                    &artifact.batch_fact,
                    &artifact.program_hash,
                    &keccak_root_hex,
                    now,
                )?;
                self.batches[bi].artifact = Some(artifact);
                self.batches[bi].record.state = BatchState::Submitting;
                self.sidecar.write_batch(&self.batches[bi].record)?;
                report.tasks_driven += 1;
            }
            Err(e) => {
                eprintln!(
                    "[batch-poster] fold 批出证失败（第 {} 次）: {e}",
                    self.batches[bi].attempts + 1
                );
                self.batches[bi].attempts += 1;
                if self.batches[bi].attempts >= self.cfg.fold.max_proof_attempts {
                    // 批死信：成员退回逐手 dual 驱动（语句面保留，可再入批）。
                    self.kill_batch(bi)?;
                    report.dead_letters_written += 1;
                } else {
                    self.batches[bi].record.state = BatchState::Forming; // 下轮重试
                }
            }
        }
        Ok(())
    }

    /// 批死信：批记录 Dead + 成员退回 pending（逐手 dual 驱动）。
    fn kill_batch(&mut self, bi: usize) -> Result<(), PosterError> {
        self.batches[bi].record.state = BatchState::Dead;
        self.sidecar.write_batch(&self.batches[bi].record)?;
        let mut members = std::mem::take(&mut self.batches[bi].members);
        for m in members.iter_mut() {
            m.phase = DrivePhase::Picked;
            m.blocked = false;
            m.finished = false;
        }
        self.pending.append(&mut members);
        Ok(())
    }

    /// 批提交步（逐 member fold 入口；一个 member 一步）。
    async fn submit_batch_step(
        &mut self,
        bi: usize,
        now: u64,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        let account = self.cfg.operator_account;
        let next = self.batches[bi].next_member;
        if next >= self.batches[bi].members.len() {
            self.batches[bi].record.state = BatchState::Receipted;
            self.sidecar.write_batch(&self.batches[bi].record)?;
            return Ok(());
        }
        let Some(artifact) = self.batches[bi].artifact.clone() else {
            // 恢复路径：Submitting 但产物缺失（进程重启丢内存态）→ 回 Forming
            // 重出证（批键幂等保证不会重复上链）。
            self.batches[bi].record.state = BatchState::Forming;
            self.sidecar.write_batch(&self.batches[bi].record)?;
            return Ok(());
        };
        if next >= artifact.outputs.len() {
            return Err(PosterError::Proof("批公开段与成员数不符".into()));
        }
        let member = &self.batches[bi].members[next];
        let key = member.task.key;
        let statement = member
            .task
            .payload
            .fold_statement
            .clone()
            .ok_or_else(|| PosterError::Proof("批成员缺语句面".into()))?;
        let call = self.fold_settle_call(
            &statement.hand_binding,
            key.hand_id,
            &artifact.outputs[next],
        )?;
        let outcome = self
            .txmgr
            .submit_ordered(account, "fold_settle", vec![call])
            .await;
        match outcome {
            Ok(SendOutcome::Receipted(r)) => {
                let tx_hash = format!("{:#x}", r.tx_hash);
                self.record_batch_member(bi, key, now, Some(tx_hash.clone()), report)?;
                self.batches[bi].next_member += 1;
                if self.batches[bi].next_member == self.batches[bi].members.len() {
                    self.seal_batch_receipted(bi, now, Some(tx_hash))?;
                    // 累加链尾推进（下一批 acc_prev）。
                    self.last_batch_fact = Some(artifact.batch_fact.clone());
                    report.batches_receipted += 1;
                }
            }
            Ok(SendOutcome::IdempotentReplay(_)) => {
                // 幂等重放 = 该成员已结算：按已回执推进。
                self.record_batch_member(bi, key, now, None, report)?;
                self.batches[bi].next_member += 1;
                if self.batches[bi].next_member == self.batches[bi].members.len() {
                    self.seal_batch_receipted(bi, now, None)?;
                    self.last_batch_fact = Some(artifact.batch_fact.clone());
                    report.batches_receipted += 1;
                }
            }
            Err(TxError::Broadcast { .. }) => {
                self.txmgr.resume_after_halt();
                self.batches[bi].attempts += 1;
                if self.batches[bi].attempts >= self.cfg.fold.max_proof_attempts {
                    self.kill_batch(bi)?;
                    report.dead_letters_written += 1;
                }
            }
            Err(e) => return Err(PosterError::Send(e.to_string())),
        }
        Ok(())
    }

    /// 批成员回执（逐 member receipt sidecar；批键随行；余额树推进）。
    fn record_batch_member(
        &mut self,
        bi: usize,
        key: SettleKey,
        now: u64,
        tx: Option<String>,
        report: &mut TickReport,
    ) -> Result<(), PosterError> {
        let batch_key = self.batches[bi].record.batch_key.clone();
        let balance = self
            .batches[bi]
            .members
            .iter()
            .find(|m| m.task.key == key)
            .and_then(|m| m.task.balance_entry.clone());
        let txs = tx.map(|t| vec![t]).unwrap_or_default();
        self.write_receipt(
            key,
            SettleRoute::Dual,
            txs,
            Some(batch_key),
            balance.as_ref(),
            now,
            report,
        )?;
        report.receipts_written += 1;
        Ok(())
    }

    fn persist(&self, now: u64) -> Result<(), PosterError> {
        let in_flight: Vec<InFlightTask> = self
            .pending
            .iter()
            .map(|t| InFlightTask {
                key: t.task.key,
                route: t.task.route,
                phase: t.phase.submit_phase(),
                txs: t.txs.clone(),
                attempts: t.attempts,
                picked_at: t.picked_at,
            })
            .collect();
        self.sidecar.write_state(&settle_queue::PosterStateFile {
            version: 1,
            cursor: self.cursor,
            in_flight,
            draining: self.draining,
            updated_at: now,
        })?;
        Ok(())
    }

    /// 批回执封印：状态 Receipted + 余额树根快照入批记录 + spool 伴随
    /// 工件（`<batch_key>.balance.json`——随 fold 批落盘的余额根登记面，
    /// 不动 MonadProofEnvelope 跨仓契约）。
    fn seal_batch_receipted(
        &mut self,
        bi: usize,
        now: u64,
        receipt_tx: Option<String>,
    ) -> Result<(), PosterError> {
        if self.rollup.is_some() {
            let root = self
                .rollup
                .as_ref()
                .expect("rollup 与 is_some 同臂")
                .root_hex();
            self.batches[bi].record.balance_root = Some(root.clone());
            let record_key = self.batches[bi].record.batch_key.clone();
            let members = self.batches[bi].record.members.clone();
            write_balance_companion(&self.cfg.monad_spool_dir, &record_key, &root, &members, now)
                .map_err(PosterError::Io)?;
        }
        if let Some(ledger) = self.ledger.as_mut() {
            let artifact =
                ledger.seal_batch(&self.batches[bi].record.batch_key, now)?;
            let path = self.cfg.monad_spool_dir.join(format!(
                "{}.ledger-root.json",
                self.batches[bi].record.batch_key.trim_start_matches("0x")
            ));
            settle_queue::sidecar::atomic_write_json(&path, &artifact)
                .map_err(PosterError::Io)?;
        }
        self.batches[bi].record.state = BatchState::Receipted;
        self.batches[bi].record.receipt_tx = receipt_tx;
        self.sidecar.write_batch(&self.batches[bi].record)?;
        Ok(())
    }

    /// 运行状态快照（survey §9.7 监控最小集）。
    pub fn status(&self) -> PosterStatus {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let open: Vec<&BatchRuntime> = self
            .batches
            .iter()
            .filter(|b| !matches!(b.record.state, BatchState::Receipted | BatchState::Dead))
            .collect();
        PosterStatus {
            pending_tasks: self.pending.len(),
            pending_batches: open.len(),
            // 最老未决批年龄：对 created_at 取 **min**（最早创建）再算
            // 年龄——max 会给出最年轻批的年龄，监控语义相反。
            oldest_batch_age_secs: open
                .iter()
                .map(|b| b.record.created_at)
                .min()
                .map(|c| now.saturating_sub(c)),
            in_flight_txs: self.txmgr.in_flight().len(),
            txmgr_halted: self.txmgr.halted(),
            draining: self.draining,
            operator_balance: None,
            balance_root_head: self.rollup.as_ref().map(|r| r.root_hex()),
            balance_applied_hands: self.rollup.as_ref().map(|r| r.applied_hands()),
        }
    }

    /// daemon 主循环（op-batcher publishingLoop 形态）。drain 置位且在途
    /// 清空后返回；单轮失败不退出（错误打印 + status 观测）。
    pub async fn run(&mut self) -> Result<(), PosterError> {
        self.recover()?;
        loop {
            if let Err(e) = self.tick().await {
                eprintln!("[batch-poster] tick error: {e}");
            }
            if self.draining && self.pending.is_empty() && self.batches.is_empty() {
                return Ok(());
            }
            tokio::time::sleep(self.cfg.poll_interval).await;
        }
    }
}
