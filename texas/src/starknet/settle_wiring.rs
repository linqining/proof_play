//! texas ↔ settle-queue 接线（rollup-components follow-up 条目 1，
//! 2026-10-01）。
//!
//! ## 协议端点（单写者协议，见 settle-queue crate 文档）
//!
//! - **queue WAL（`queue.jsonl`，texas 独占写）**：入队
//!   （[`QueueWal::enqueue`]——对账通过的 settlement 预构建 calldata）、
//!   构建期死信（[`QueueWal::build_dead_letter`]——对账拒绝/构建失败）、
//!   Dual→Legacy 降级（[`QueueWal::downgrade`]——依据 poster sidecar
//!   投递期死信回读触发）。poster 只读 WAL。
//! - **poster sidecar（poster 独占写，本层只读回读）**：`receipts/` 回执
//!   → 转发 settle_receipt + 离桌释放冲刷 + session 续钟（[`SettleWiring::poll`]）；
//!   `dead/` 投递期死信 → Dual 路即降级重投（WAL `Downgraded`）。
//!
//! ## 进程内结算状态的队列/sidecar 表达
//!
//! 旧 hooks.rs 的进程内三件套（`PENDING_SETTLE` / `SETTLE_OK` /
//! `SETTLE_ATTEMPTS`，重启即丢）已删除，等价语义：
//!
//! | 旧状态 | 队列/sidecar 表达 |
//! |---|---|
//! | `PENDING_SETTLE`（待投递快照 + tick 重投） | WAL `Enqueued`（重启不丢）+ poster 驱动投递 |
//! | `SETTLE_OK`（成功幂等跳过） | sidecar `receipts/<key>.json`（[`is_settled`]）+ settle_receipt 业务终态 |
//! | `SETTLE_ATTEMPTS`（重试上限） | poster 运营配置（`*_max_attempts`）+ 投递期死信 `dead/<key>.json` |
//!
//! prove_log 仍是对账事实源（`take_settle_input` 提取输入），本层只管
//! 投递持久化。
//!
//! ## 路径约定（与 batch-poster 的 `TEXAS_POSTER_*` 缺省一致；两进程部署
//! 时必须指向同一目录——绝对路径配置）
//!
//! - WAL：`TEXAS_SETTLE_QUEUE_WAL`（缺省 `settle-queue/queue.jsonl`；
//!   poster 侧 `TEXAS_POSTER_QUEUE_WAL` 同缺省）；
//! - sidecar：`TEXAS_SETTLE_SIDECAR_DIR`（缺省 `poster-sidecar`；poster 侧
//!   `TEXAS_POSTER_SIDECAR_DIR` 同缺省）。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use settle_queue::sidecar::{DeadRecord, PosterSidecar, ReceiptRecord};
use settle_queue::task::{
    BalanceEntry, FoldStatement, LegCalldata, SettleKey, SettlePayload, SettleTask,
};
use settle_queue::wal::{EnqueueError, QueueWal};

/// 入队时的显示元数据缓存：sidecar 回执（`ReceiptRecord`）只携带键/路由/
/// 交易哈希，而 settle_receipt 的展示锚（aggregate digest / 合约地址）与
/// session 续钟的参与者名单都在 settlement 里——入队时缓存，回执转发时
/// 取用。**缓存缺失只影响展示与续钟，不影响投递正确性**（进程重启后的
/// 历史手无从重建，回执照转、续钟跳过）。
#[derive(Debug, Clone, Default)]
pub struct EnqueueEnrichment {
    /// legacy 出口的聚合摘要（0x-hex；settle_receipt 展示锚）。
    pub aggregate_digest: Option<String>,
    /// 结算合约地址（D3 元数据下发）。
    pub contract: Option<String>,
    /// 重映射后的参与者（结算成功后的 session 续钟名单）。
    pub players_remapped: Vec<starknet_crypto::Felt>,
}

/// texas 侧接线实例（WAL 写者 + sidecar 读者）。
pub struct SettleWiring {
    wal: Mutex<QueueWal>,
    sidecar: PosterSidecar,
    /// 已写降级事件的 Dual 死信键（进程内幂等：poster 清死信前不重写；
    /// WAL 侧 fold 本身幂等，重启后重复一条 `Downgraded` 无害）。
    downgraded: Mutex<HashSet<SettleKey>>,
    /// 已转发回执的键（进程内去重；重启后由 settle_receipt upsert 幂等
    /// 兜底——重复转发无副作用）。
    forwarded: Mutex<HashSet<SettleKey>>,
    /// 入队显示元数据（见 [`EnqueueEnrichment`]）。
    enrichment: Mutex<HashMap<SettleKey, EnqueueEnrichment>>,
}

impl SettleWiring {
    /// 打开（或创建）WAL 与 sidecar 目录。WAL 打开即重放（撕裂尾行修复、
    /// 去重索引重建——崩溃恢复见 settle-queue wal.rs）。
    pub fn open(
        wal_path: impl AsRef<std::path::Path>,
        sidecar_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self, String> {
        let wal = QueueWal::open(wal_path).map_err(|e| format!("queue wal open: {e}"))?;
        let sidecar = PosterSidecar::open(sidecar_dir).map_err(|e| format!("sidecar open: {e}"))?;
        Ok(Self {
            wal: Mutex::new(wal),
            sidecar,
            downgraded: Mutex::new(HashSet::new()),
            forwarded: Mutex::new(HashSet::new()),
            enrichment: Mutex::new(HashMap::new()),
        })
    }

    /// append 入队（幂等去重由 [`QueueWal::enqueue`] 保证）。
    fn enqueue(&self, task: SettleTask) -> Result<(), EnqueueError> {
        let mut wal = self
            .wal
            .lock()
            .map_err(|e| EnqueueError::Io(format!("wal lock poisoned: {e}")))?;
        wal.enqueue(task).map(|_| ())
    }

    /// legacy 条目入队：register_aggregate / settle_hand 两腿 calldata
    /// （poster 按 `SettleRoute::Legacy` 直投）。calldata 构建不动——本层
    /// 只做 felt → hex 载体转换；余额增量语料（escape 地基）随条目携带。
    pub fn enqueue_legacy(
        &self,
        table_id: u32,
        settlement: &super::submit::HandSettlement,
        contract: Option<&str>,
    ) -> Result<(), EnqueueError> {
        let balance_entry =
            Self::balance_entry_from(&settlement.players_remapped, &settlement.deltas)?;
        self.enqueue_legacy_parts(
            table_id,
            settlement.hand_id,
            &settlement.register_calldata,
            &settlement.settle_calldata,
            Some(&settlement.aggregate_digest),
            &settlement.players_remapped,
            Some(balance_entry),
            contract,
        )
    }

    /// HandSettlement → 队列余额增量语料（chips × WEI_PER_CHIP = wei）。
    /// 溢出 fail-closed——escape 地基语料缺一只手都不可静默。
    fn balance_entry_from(
        players: &[starknet_crypto::Felt],
        deltas_chips: &[i128],
    ) -> Result<BalanceEntry, EnqueueError> {
        let deltas_wei = deltas_chips
            .iter()
            .map(|d| {
                i128::try_from(super::config::WEI_PER_CHIP)
                    .ok()
                    .and_then(|scale| d.checked_mul(scale))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                EnqueueError::Io(
                    std::io::Error::other("balance entry wei overflow").to_string(),
                )
            })?;
        Ok(BalanceEntry {
            players: players.iter().map(|f| format!("{f:#x}")).collect(),
            deltas_wei,
        })
    }

    /// [`enqueue_legacy`] 的部件形态（测试直接构造，无需完整
    /// HandSettlement）。
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_legacy_parts(
        &self,
        table_id: u32,
        hand_id: u32,
        register_calldata: &[starknet_crypto::Felt],
        settle_calldata: &[starknet_crypto::Felt],
        aggregate_digest: Option<&[u8; 32]>,
        players_remapped: &[starknet_crypto::Felt],
        balance_entry: Option<BalanceEntry>,
        contract: Option<&str>,
    ) -> Result<(), EnqueueError> {
        let key = SettleKey::new(table_id, hand_id);
        let mut task = SettleTask::legacy(
            key,
            SettlePayload {
                register: leg(
                    super::chain::selector("register_aggregate"),
                    register_calldata,
                ),
                settle: leg(super::chain::selector("settle_hand"), settle_calldata),
                fold_statement: None,
            },
            now_secs(),
        );
        if let Some(entry) = balance_entry {
            task = task.with_balance_entry(entry);
        }
        self.enqueue(task)?;
        self.cache_enrichment(
            key,
            EnqueueEnrichment {
                aggregate_digest: aggregate_digest
                    .map(|d| format!("0x{}", super::chain::hex_encode(d))),
                contract: contract
                    .filter(|c| !c.trim().is_empty())
                    .map(str::to_string),
                players_remapped: players_remapped.to_vec(),
            },
        );
        Ok(())
    }

    /// Dual 条目入队（payload = register_hand + verify_and_settle_dapv* 两腿；
    /// `legacy_fallback` = legacy 保底腿——poster 降级重投用）。当前生产
    /// dual 路径仍由 [`super::dual_settle::submit_dual_settlement`] 直发
    /// （txmgr 发送面；proved/combined/原子 bundle 语义无法预构建为两腿
    /// 队列 payload）；本入口是接线契约的完整实现，供测试与后续迁移。
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_dual(
        &self,
        table_id: u32,
        hand_id: u32,
        dapv_entry: &str,
        register: (starknet_crypto::Felt, &[starknet_crypto::Felt]),
        settle: (starknet_crypto::Felt, &[starknet_crypto::Felt]),
        legacy_fallback: Option<SettlePayload>,
        fold_statement: Option<FoldStatement>,
        balance_entry: Option<BalanceEntry>,
    ) -> Result<(), EnqueueError> {
        let payload = SettlePayload {
            register: leg(register.0, register.1),
            settle: leg(settle.0, settle.1),
            fold_statement,
        };
        let mut task = SettleTask::dual(
            SettleKey::new(table_id, hand_id),
            dapv_entry.to_string(),
            payload,
            legacy_fallback,
            now_secs(),
        );
        if let Some(entry) = balance_entry {
            task = task.with_balance_entry(entry);
        }
        self.enqueue(task)
    }

    /// 构建期死信（对账拒绝/构建失败——hooks 的 refuse_settlement 与
    /// settlement build 失败路径）。入队前死信 = 墓碑（后续 enqueue 拒绝）；
    /// 已入队条目 = 终态 `DeadLetter(Build)`，poster 停驱动。
    pub fn build_dead_letter(
        &self,
        table_id: u32,
        hand_id: u32,
        reason: &str,
    ) -> Result<(), String> {
        let mut wal = self
            .wal
            .lock()
            .map_err(|e| format!("wal lock poisoned: {e}"))?;
        wal.build_dead_letter(SettleKey::new(table_id, hand_id), reason.to_string())
            .map(|_| ())
            .map_err(|e| format!("build dead letter append: {e}"))
    }

    /// sidecar 回读一轮：
    /// 1. `dead/` 中 Dual 路死信 → WAL `Downgraded`（poster 下轮观察到
    ///    路由已变 Legacy 后清死信、按 legacy 保底重投）；Legacy 死信 =
    ///    终态，停发观察（不动）。
    /// 2. `receipts/` 新回执 → 返回给调用方转发（本实例内去重）。
    pub fn poll(&self) -> Vec<ReceiptRecord> {
        // 1) Dual 死信 → 降级（进程内幂等）。
        if let Ok(deads) = self.sidecar.list_dead() {
            for dead in deads {
                self.downgrade_if_candidate(&dead);
            }
        }
        // 2) 新回执收集。
        let mut out = Vec::new();
        if let Ok(receipts) = self.sidecar.list_receipts() {
            for rec in receipts {
                let fresh = self
                    .forwarded
                    .lock()
                    .map(|mut g| g.insert(rec.key))
                    .unwrap_or(false);
                if fresh {
                    out.push(rec);
                }
            }
        }
        out
    }

    /// Dual 投递期死信 → WAL 降级（幂等：同一死信只写一次；写失败回滚
    /// 幂等标记等下轮重试）。
    fn downgrade_if_candidate(&self, dead: &DeadRecord) {
        if !dead.downgrade_candidate() {
            return; // Legacy 死信 = 终态（含降级后仍耗尽）。
        }
        let first = self
            .downgraded
            .lock()
            .map(|mut g| g.insert(dead.key))
            .unwrap_or(false);
        if !first {
            return;
        }
        let result = self
            .wal
            .lock()
            .map_err(|e| e.to_string())
            .and_then(|mut wal| {
                wal.downgrade(dead.key)
                    .map_err(|e| format!("downgrade append: {e}"))
            });
        match result {
            Ok(_seq) => tracing::info!(
                "[settle-wiring] {} dual delivery dead-lettered (attempts {}, reason: {}) — \
                 WAL Downgraded，poster 将按 legacy 保底重投",
                dead.key,
                dead.attempts,
                dead.reason
            ),
            Err(e) => {
                tracing::error!("[settle-wiring] {} {e} — 下轮重试", dead.key);
                if let Ok(mut g) = self.downgraded.lock() {
                    g.remove(&dead.key); // 回滚幂等标记。
                }
            }
        }
    }

    /// sidecar 回执在案（队列投递路径的 settled 判定；重启后仍成立）。
    pub fn receipted(&self, key: &SettleKey) -> bool {
        self.sidecar.read_receipt(key).ok().flatten().is_some()
    }

    /// 入队时的显示元数据（见 [`EnqueueEnrichment`]）。
    pub fn enrichment_of(&self, key: &SettleKey) -> Option<EnqueueEnrichment> {
        self.enrichment
            .lock()
            .ok()
            .and_then(|g| g.get(key).cloned())
    }

    fn cache_enrichment(&self, key: SettleKey, e: EnqueueEnrichment) {
        if let Ok(mut g) = self.enrichment.lock() {
            g.insert(key, e);
        }
    }
}

/// felt 腿 → 队列载体（selector + hex 词；poster 原样透传不重建语义）。
fn leg(selector: starknet_crypto::Felt, calldata: &[starknet_crypto::Felt]) -> LegCalldata {
    LegCalldata {
        selector: format!("{selector:#x}"),
        calldata: calldata.iter().map(|f| format!("{f:#x}")).collect(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

static WIRING: OnceLock<Result<SettleWiring, String>> = OnceLock::new();

/// 进程级接线单例（首次调用打开 WAL + sidecar；打开失败缓存错误并返回
/// None——调用方按结算丢失路径上报，绝不静默丢件）。
pub fn wiring() -> Option<&'static SettleWiring> {
    let cell = WIRING.get_or_init(|| {
        let wal = std::env::var("TEXAS_SETTLE_QUEUE_WAL")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("settle-queue/queue.jsonl"));
        let sidecar = std::env::var("TEXAS_SETTLE_SIDECAR_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("poster-sidecar"));
        SettleWiring::open(&wal, &sidecar)
    });
    cell.as_ref().ok()
}

/// hooks 的入队入口（legacy 路）：queue 不可用/写入失败 → Err（调用方按
/// 结算丢失 fail-closed 上报）；Duplicate/Terminal = 幂等跳过（对账事实源
/// 仍是 prove_log），Ok 返回。
pub fn enqueue_legacy_settlement(
    table_id: u32,
    settlement: &super::submit::HandSettlement,
    contract: &str,
) -> Result<(), String> {
    let Some(w) = wiring() else {
        return Err("settle queue unavailable (WAL/sidecar open failed)".to_string());
    };
    match w.enqueue_legacy(table_id, settlement, Some(contract)) {
        Ok(()) => Ok(()),
        Err(EnqueueError::Duplicate(key)) => {
            tracing::info!(
                "[settle-wiring] table {table_id} hand {} already queued ({key}) — enqueue skipped",
                settlement.hand_id
            );
            Ok(())
        }
        Err(EnqueueError::Terminal(key)) => {
            tracing::warn!(
                "[settle-wiring] table {table_id} hand {} key {key} already terminal in queue — \
                 enqueue skipped (business verdict: settle_receipt)",
                settlement.hand_id
            );
            Ok(())
        }
        Err(EnqueueError::Io(e)) => Err(format!("queue enqueue io: {e}")),
    }
}

/// 构建期死信（对账拒绝/构建失败）。写入失败仅告警——死信是防复活墓碑，
/// 失败时 settle_receipt 的 Refused/Failed 回执仍是业务终态记录。
pub fn dead_letter_hand(table_id: u32, hand_id: u32, reason: &str) {
    let Some(w) = wiring() else {
        tracing::error!(
            "[settle-wiring] table {table_id} hand {hand_id} build dead-letter not written \
             (queue unavailable): {reason}"
        );
        return;
    };
    if let Err(e) = w.build_dead_letter(table_id, hand_id, reason) {
        tracing::error!(
            "[settle-wiring] table {table_id} hand {hand_id} build dead-letter write failed: {e}"
        );
    }
}

/// 幂等 settled 判定（替代旧进程内 `SETTLE_OK`）：
/// 1. poster sidecar 回执在案（队列投递路径——重启后仍成立）；
/// 2. 进程内业务终态（dual 直发 / appchain 出口不经队列，settle_receipt
///    的 Settled 印章是权威）。
pub fn is_settled(table_id: u32, hand_id: u32) -> bool {
    let key = SettleKey::new(table_id, hand_id);
    if wiring().is_some_and(|w| w.receipted(&key)) {
        return true;
    }
    super::settle_receipt::get(table_id, hand_id)
        .is_some_and(|r| r.status == super::settle_receipt::SettleStatus::Settled.as_str())
}

/// sidecar 回读节流（game tick 按桌高频调用；回读限频 1 次/秒）。
static LAST_POLL: Mutex<Option<std::time::Instant>> = Mutex::new(None);

/// tick 驱动的回读入口（旧 `retry_pending_settlement` 的重投语义已归
/// poster；本入口做 texas 侧观察：死信降级 + 回执转发）。返回新回执。
pub fn poll_throttled() -> Vec<ReceiptRecord> {
    {
        let mut last = LAST_POLL.lock().unwrap_or_else(|p| p.into_inner());
        if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1)) {
            return Vec::new();
        }
        *last = Some(std::time::Instant::now());
    }
    wiring().map(|w| w.poll()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use settle_queue::task::SettleRoute;
    use settle_queue::wal::{self, replay};

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "texas-settle-wiring-{tag}-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn felt(v: u64) -> starknet_crypto::Felt {
        starknet_crypto::Felt::from(v)
    }

    /// legacy 入队 → WAL Enqueued（selector/calldata hex 透传 + 展示元数据
    /// 缓存）+ 重复键幂等拒绝 + 重启（重开）后去重索引仍在。
    #[test]
    fn legacy_enqueue_dedup_across_restart() {
        let dir = tmpdir("legacy-dedup");
        let wal_path = dir.join("queue.jsonl");
        let key = SettleKey::new(7, 42);
        {
            let w = SettleWiring::open(&wal_path, dir.join("poster")).unwrap();
            w.enqueue_legacy_parts(
                7,
                42,
                &[felt(1), felt(2)],
                &[felt(3)],
                Some(&[0xAB; 32]),
                &[felt(0xA11)],
                Some(BalanceEntry {
                    players: vec![format!("{:#x}", felt(0xA11))],
                    deltas_wei: vec![5_000_000_000_000_000, -5_000_000_000_000_000],
                }),
                Some("0xcontract"),
            )
            .unwrap();
            // 同键重复入队：Duplicate（包装层转幂等 Ok）。
            let err = w
                .enqueue_legacy_parts(7, 42, &[], &[], None, &[], None, None)
                .unwrap_err();
            assert!(matches!(err, EnqueueError::Duplicate(_)), "{err:?}");
            // 入队元数据缓存（digest hex / 合约 / 参与者）。
            let e = w.enrichment_of(&key).unwrap();
            assert_eq!(
                e.aggregate_digest.as_deref(),
                Some(format!("0x{}", "ab".repeat(32)).as_str())
            );
            assert_eq!(e.contract.as_deref(), Some("0xcontract"));
            assert_eq!(e.players_remapped, vec![felt(0xA11)]);
        }
        // 重启：WAL 重放后去重索引仍在；元数据缓存丢失（设计如此——只影响
        // 展示/续钟）。
        let w = SettleWiring::open(&wal_path, dir.join("poster")).unwrap();
        let err = w
            .enqueue_legacy_parts(7, 42, &[], &[], None, &[], None, None)
            .unwrap_err();
        assert!(matches!(err, EnqueueError::Duplicate(_)));
        assert!(w.enrichment_of(&key).is_none());
        // WAL 事实：Legacy 任务、selector/calldata hex 逐词一致。
        let st = replay(&wal_path).unwrap();
        let rec = st.record(&key).unwrap();
        assert_eq!(rec.task.route, SettleRoute::Legacy);
        assert_eq!(
            rec.task.payload.register.calldata,
            vec!["0x1".to_string(), "0x2".to_string()]
        );
        assert_eq!(rec.task.payload.settle.calldata, vec!["0x3".to_string()]);
        // 余额增量语料随条目入 WAL（escape 地基 rollup 的输入面）。
        let entry = rec.task.balance_entry.clone().expect("balance_entry 随条目");
        assert_eq!(entry.players, vec![format!("{:#x}", felt(0xA11))]);
        assert_eq!(
            entry.deltas_wei,
            vec![5_000_000_000_000_000, -5_000_000_000_000_000]
        );
        assert_eq!(
            rec.task.payload.register.selector,
            format!("{:#x}", super::super::chain::selector("register_aggregate"))
        );
        assert_eq!(
            rec.task.payload.settle.selector,
            format!("{:#x}", super::super::chain::selector("settle_hand"))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 构建期死信墓碑：入队前死信 → 后续 enqueue 拒绝 Terminal（不复活）。
    #[test]
    fn build_dead_letter_tombstone_blocks_enqueue() {
        let dir = tmpdir("dead-tomb");
        let wal_path = dir.join("queue.jsonl");
        let w = SettleWiring::open(&wal_path, dir.join("poster")).unwrap();
        w.build_dead_letter(9, 1, "cross-check FAILED: rake mismatch")
            .unwrap();
        let err = w
            .enqueue_legacy_parts(9, 1, &[], &[], None, &[], None, None)
            .unwrap_err();
        assert!(matches!(err, EnqueueError::Terminal(_)), "{err:?}");
        let st = replay(&wal_path).unwrap();
        assert_eq!(
            st.build_dead_reason(&SettleKey::new(9, 1)),
            Some("cross-check FAILED: rake mismatch")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Dual 投递期死信回读 → WAL Downgraded（幂等：同一死信只写一次；
    /// Legacy 死信不动）；poster 视角（scan_from）能观察到降级事件。
    #[test]
    fn dual_dead_letter_readback_downgrades() {
        let dir = tmpdir("dead-downgrade");
        let wal_path = dir.join("queue.jsonl");
        let sidecar_dir = dir.join("poster");
        let w = SettleWiring::open(&wal_path, &sidecar_dir).unwrap();

        let key = SettleKey::new(3, 77);
        let fallback = SettlePayload {
            register: LegCalldata {
                selector: "0xleg1".into(),
                calldata: vec![],
            },
            settle: LegCalldata {
                selector: "0xleg2".into(),
                calldata: vec![],
            },
            fold_statement: None,
        };
        w.enqueue_dual(
            3,
            77,
            "v2",
            (felt(0x11), &[]),
            (felt(0x22), &[]),
            Some(fallback),
            None,
            None,
        )
        .unwrap();

        // poster 写投递期死信（Dual = 降级候选）。
        let sidecar = PosterSidecar::open(&sidecar_dir).unwrap();
        sidecar
            .write_dead(&DeadRecord {
                key,
                route_at_death: SettleRoute::Dual,
                reason: "dual leg retries exhausted".into(),
                attempts: 8,
                at: 100,
            })
            .unwrap();

        // 第一轮回读：写 Downgraded；第二轮：幂等不再写。
        w.poll();
        let seq_after_first = replay(&wal_path).unwrap().last_seq();
        w.poll();
        assert_eq!(
            replay(&wal_path).unwrap().last_seq(),
            seq_after_first,
            "同一死信只降级一次"
        );

        // WAL 事实：路由迁 Legacy（legacy 保底生效）。
        let st = replay(&wal_path).unwrap();
        let rec = st.record(&key).unwrap();
        assert_eq!(rec.task.route, SettleRoute::Legacy);
        assert!(rec.downgraded);
        assert_eq!(rec.task.effective_payload().settle.selector, "0xleg2");

        // poster 游标扫描可见降级事件（poster 清死信、按 legacy 重投的触发）。
        let (events, _) = wal::scan_from(&wal_path, 0).unwrap();
        assert!(events.iter().any(|(_, e)| matches!(
            e,
            settle_queue::WalEvent::Downgraded { key: k } if *k == key
        )));

        // Legacy 死信（降级后仍耗尽）= 终态，不再降级。
        sidecar
            .write_dead(&DeadRecord {
                key,
                route_at_death: SettleRoute::Legacy,
                reason: "downgraded and still exhausted".into(),
                attempts: 8,
                at: 200,
            })
            .unwrap();
        let seq_before = replay(&wal_path).unwrap().last_seq();
        w.poll();
        assert_eq!(replay(&wal_path).unwrap().last_seq(), seq_before);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// sidecar 回执回读：新回执逐条去重返回；receipted 判定。
    #[test]
    fn receipt_readback_forward_once() {
        let dir = tmpdir("receipts");
        let sidecar_dir = dir.join("poster");
        let w = SettleWiring::open(dir.join("queue.jsonl"), &sidecar_dir).unwrap();
        let sidecar = PosterSidecar::open(&sidecar_dir).unwrap();
        let key = SettleKey::new(5, 6);
        sidecar
            .write_receipt(&ReceiptRecord {
                key,
                route: SettleRoute::Legacy,
                txs: vec!["0xtx1".into(), "0xtx2".into()],
                batch_key: None,
                at: 1,
            })
            .unwrap();

        let first = w.poll();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].key, key);
        // 第二轮：已转发去重。
        assert!(w.poll().is_empty());
        // settled 判定（队列路径）。
        assert!(w.receipted(&key));
        std::fs::remove_dir_all(&dir).ok();
    }
}
