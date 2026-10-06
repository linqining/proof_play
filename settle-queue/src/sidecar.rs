//! poster 独占 sidecar（单写者协议的另一半）。
//!
//! 目录形态（全部由 batch-poster 写、texas 只读）：
//!
//! ```text
//! <sidecar>/
//!   poster-state.json        # 拾取游标 + 在途快照（poster 崩溃恢复面）
//!   receipts/<table>-<hand>.json   # 投递回执（Receipted 的事实载体）
//!   dead/<table>-<hand>.json       # 投递期死信（Delivery 死信双源之一）
//!   batches/<batch_key>.json       # fold 批记录（批级键域，键=keccak_root）
//! ```
//!
//! 写入一律 [`atomic_write_json`]：同目录临时文件 + rename（POSIX 原子），
//! 读侧永远看到完整 JSON——poster 崩溃不会留下半文件。
//!
//! **DeadLetter 双源归属**：构建期死信在 WAL（texas 写，
//! [`crate::wal::WalEvent::BuildDeadLettered`]）；投递期死信在本目录
//! `dead/<key>.json`（poster 写）。texas 扫描本目录观察 Dual 路投递期死信
//! → 写 WAL 降级事件（Dual→Legacy）→ poster 下轮看到 WAL 路由已变 →
//! [`PosterSidecar::clear_dead`] 后按 Legacy 重投。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::state::SubmitPhase;
use crate::task::{SettleKey, SettleRoute};

/// sidecar 交易哈希载体（hex 字符串，poster 不解析）。
pub type TxHashHex = String;

/// poster-state.json：游标 + 在途快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosterStateFile {
    /// sidecar 格式版本。
    pub version: u32,
    /// queue WAL 已消费到的 seq（游标扫描尾部）。
    pub cursor: u64,
    /// 在途任务（Picked/Submitted 快照——poster 崩溃恢复面）。
    pub in_flight: Vec<InFlightTask>,
    /// drain 逃生口已触发（停止拾取，完成在途后退出）。
    #[serde(default)]
    pub draining: bool,
    /// 最近一次写入时刻（unix 秒）。
    pub updated_at: u64,
}

/// 在途任务快照（poster 写；Enqueued→Picked 之后、Receipted/DeadLetter
/// 之前的全部中间态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InFlightTask {
    pub key: SettleKey,
    /// 拾取时的路由（Dual 条目可能已被 texas 降级——恢复时与 WAL 对账）。
    pub route: SettleRoute,
    /// 两笔时序子态；`None` = 已拾取未广播（Picked 相位）。
    pub phase: Option<SubmitPhase>,
    /// 已广播的交易哈希（按序）。
    pub txs: Vec<TxHashHex>,
    /// 投递重试计数。
    pub attempts: u32,
    /// 拾取时刻（unix 秒）。
    pub picked_at: u64,
}

/// receipts/<key>.json：投递回执（投递终态 Receipted 的事实载体；
/// **Receipted ≠ 业务终态**——业务终态权威是 settle_receipt 的 SettleStatus）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    pub key: SettleKey,
    /// 完成投递的路由（降级重投后为 Legacy）。
    pub route: SettleRoute,
    /// 交易哈希（register, settle 两笔，按序）。
    pub txs: Vec<TxHashHex>,
    /// fold 批完成时携带批键（批回执回填批记录并逐 member 写回执）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_key: Option<String>,
    /// 完成时刻（unix 秒）。
    pub at: u64,
}

/// dead/<key>.json：投递期死信（poster 写；构建期死信在 WAL——双源归属）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadRecord {
    pub key: SettleKey,
    /// 死亡时的路由：Dual = 降级候选（texas 读后降级重投）；Legacy（或
    /// 降级后仍耗尽）= 终态死信，停发观察。
    pub route_at_death: SettleRoute,
    pub reason: String,
    pub attempts: u32,
    /// 死信时刻（unix 秒）。
    pub at: u64,
}

impl DeadRecord {
    /// 是否为 Dual→Legacy 降级候选（texas 据此写 WAL 降级事件）。
    pub fn downgrade_candidate(&self) -> bool {
        self.route_at_death == SettleRoute::Dual
    }
}

/// fold 批记录状态（批级键域，键 = batch_key/keccak_root）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BatchState {
    /// 已形成（成员/批键落盘，未出证）。
    Forming,
    /// 出证中（ProofSource 已受理）。
    Proving,
    /// 批 calldata 提交中（逐 member verify_and_settle_dapv_fold_private）。
    Submitting,
    /// 批回执已回填（逐 member 回执已写）。
    Receipted,
    /// 批死信（出证/提交耗尽——成员退回逐手 dual 驱动）。
    Dead,
}

/// batches/<batch_key>.json：fold 批记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    /// 批键 = keccak_root（hex；同时是 zchain 侧幂等键与
    /// MonadProofEnvelope 主键——键域闭合）。
    pub batch_key: String,
    /// 批成员（单手键引用；批键做批幂等，单手键只做队列去重）。
    pub members: Vec<SettleKey>,
    pub state: BatchState,
    /// 批级回执交易（Receipted 时存在；逐 member 回执在 receipts/）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_tx: Option<TxHashHex>,
    /// 批完成时的余额树根（escape 地基，M2；balance-rollup 随批推进后
    /// 的累计根，None = rollup 未启用）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_root: Option<String>,
    pub created_at: u64,
}

/// poster sidecar 目录句柄（写者 = poster；texas 以同一类型只读——
/// 单写者协议靠进程约定 + 本类型文档钉板）。
#[derive(Debug, Clone)]
pub struct PosterSidecar {
    dir: PathBuf,
}

impl PosterSidecar {
    /// 打开（创建）sidecar 目录。
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join("receipts"))?;
        fs::create_dir_all(dir.join("dead"))?;
        fs::create_dir_all(dir.join("batches"))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // ---- poster-state.json（游标 + 在途快照）----

    pub fn read_state(&self) -> std::io::Result<Option<PosterStateFile>> {
        read_json(&self.dir.join("poster-state.json"))
    }

    pub fn write_state(&self, state: &PosterStateFile) -> std::io::Result<()> {
        atomic_write_json(&self.dir.join("poster-state.json"), state)
    }

    // ---- receipts/<key>.json ----

    pub fn write_receipt(&self, rec: &ReceiptRecord) -> std::io::Result<()> {
        atomic_write_json(
            &self
                .dir
                .join("receipts")
                .join(format!("{}.json", rec.key.file_stem())),
            rec,
        )
    }

    pub fn read_receipt(&self, key: &SettleKey) -> std::io::Result<Option<ReceiptRecord>> {
        read_json(
            &self
                .dir
                .join("receipts")
                .join(format!("{}.json", key.file_stem())),
        )
    }

    /// 全量回执键（texas 对账扫描）。
    pub fn list_receipts(&self) -> std::io::Result<Vec<ReceiptRecord>> {
        list_json(&self.dir.join("receipts"))
    }

    // ---- dead/<key>.json（投递期死信，双源之一）----

    pub fn write_dead(&self, rec: &DeadRecord) -> std::io::Result<()> {
        atomic_write_json(
            &self
                .dir
                .join("dead")
                .join(format!("{}.json", rec.key.file_stem())),
            rec,
        )
    }

    pub fn read_dead(&self, key: &SettleKey) -> std::io::Result<Option<DeadRecord>> {
        read_json(
            &self
                .dir
                .join("dead")
                .join(format!("{}.json", key.file_stem())),
        )
    }

    /// 全量投递期死信（texas 扫描观察停发与对账；Dual 路死信 → 降级）。
    pub fn list_dead(&self) -> std::io::Result<Vec<DeadRecord>> {
        list_json(&self.dir.join("dead"))
    }

    /// 清除死信标记（poster 在 WAL 降级事件被观察到之后调用：按 Legacy 重投）。
    pub fn clear_dead(&self, key: &SettleKey) -> std::io::Result<()> {
        let _ = fs::remove_file(
            self.dir
                .join("dead")
                .join(format!("{}.json", key.file_stem())),
        );
        Ok(())
    }

    // ---- batches/<batch_key>.json（批级键域）----

    pub fn write_batch(&self, rec: &BatchRecord) -> std::io::Result<()> {
        let name = sanitize_batch_key(&rec.batch_key);
        atomic_write_json(&self.dir.join("batches").join(format!("{name}.json")), rec)
    }

    pub fn read_batch(&self, batch_key: &str) -> std::io::Result<Option<BatchRecord>> {
        let name = sanitize_batch_key(batch_key);
        read_json(&self.dir.join("batches").join(format!("{name}.json")))
    }

    pub fn list_batches(&self) -> std::io::Result<Vec<BatchRecord>> {
        list_json(&self.dir.join("batches"))
    }
}

/// 批键文件名安全化（hex 或 0x 前缀 hex → 文件名；其余字符替换）。
fn sanitize_batch_key(key: &str) -> String {
    key.trim_start_matches("0x")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> std::io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}"))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn list_json<T: serde::de::DeserializeOwned>(dir: &Path) -> std::io::Result<Vec<T>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    for p in paths {
        if let Some(v) = read_json(&p)? {
            out.push(v);
        }
    }
    Ok(out)
}

/// 原子写 JSON：同目录 `<name>.tmp-<pid>` + rename（POSIX 原子）。
pub fn atomic_write_json<T: serde::Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let body = serde_json::to_vec_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("settle-queue-sidecar-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 原子写：读侧永远看到完整 JSON；无 .tmp 残留。
    #[test]
    fn atomic_write_leaves_no_partial_files() {
        let dir = tmpdir("atomic");
        let sc = PosterSidecar::open(&dir).unwrap();
        let rec = ReceiptRecord {
            key: SettleKey::new(1, 2),
            route: SettleRoute::Legacy,
            txs: vec!["0xtx1".into(), "0xtx2".into()],
            batch_key: None,
            at: 100,
        };
        sc.write_receipt(&rec).unwrap();
        let back = sc.read_receipt(&SettleKey::new(1, 2)).unwrap().unwrap();
        assert_eq!(back, rec);
        // 目录里只有最终文件（无 tmp 残留）。
        let names: Vec<String> = fs::read_dir(dir.join("receipts"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["1-2.json".to_string()]);
        fs::remove_dir_all(&dir).ok();
    }

    /// 双源 DeadLetter 归属：构建期死信只在 WAL（不在 dead/ 目录）；
    /// 投递期死信只在 dead/<key>.json——poster 写、texas 读。
    #[test]
    fn dead_letter_dual_source_ownership() {
        let dir = tmpdir("dual-source");
        let sc = PosterSidecar::open(&dir).unwrap();

        // 投递期死信：poster 写 dead/。
        let key = SettleKey::new(4, 5);
        sc.write_dead(&DeadRecord {
            key,
            route_at_death: SettleRoute::Dual,
            reason: "dual leg retries exhausted".into(),
            attempts: 8,
            at: 9,
        })
        .unwrap();
        let deads = sc.list_dead().unwrap();
        assert_eq!(deads.len(), 1);
        assert!(deads[0].downgrade_candidate(), "Dual 死信 = 降级候选");

        // 降级后清除（poster 观察 WAL 路由变 Legacy 后调用）。
        sc.clear_dead(&key).unwrap();
        assert!(sc.list_dead().unwrap().is_empty());

        // Legacy 死信 = 终态，非降级候选。
        sc.write_dead(&DeadRecord {
            key,
            route_at_death: SettleRoute::Legacy,
            reason: "downgraded and still exhausted".into(),
            attempts: 8,
            at: 10,
        })
        .unwrap();
        assert!(!sc.list_dead().unwrap()[0].downgrade_candidate());

        // 构建期死信**不在** dead/（在 WAL——由 wal 模块测试覆盖）；此处
        // 钉板 dead/ 只承载投递期死信的归属事实。
        let receipts = sc.list_receipts().unwrap();
        assert!(receipts.is_empty(), "dead/ 与 receipts/ 键域互斥");
        fs::remove_dir_all(&dir).ok();
    }

    /// 批级键域：批记录以 batch_key（keccak_root hex）为文件键，members
    /// 引用单手键。
    #[test]
    fn batch_record_keyed_by_keccak_root() {
        let dir = tmpdir("batch-key");
        let sc = PosterSidecar::open(&dir).unwrap();
        let rec = BatchRecord {
            batch_key: "0xdeadbeef".into(),
            members: vec![SettleKey::new(1, 1), SettleKey::new(2, 3)],
            state: BatchState::Forming,
            receipt_tx: None,
            balance_root: None,
            created_at: 1,
        };
        sc.write_batch(&rec).unwrap();
        let back = sc.read_batch("0xdeadbeef").unwrap().unwrap();
        assert_eq!(back, rec);
        assert_eq!(sc.list_batches().unwrap().len(), 1);
        fs::remove_dir_all(&dir).ok();
    }

    /// poster-state 游标与在途快照往返。
    #[test]
    fn poster_state_roundtrip() {
        let dir = tmpdir("state");
        let sc = PosterSidecar::open(&dir).unwrap();
        assert!(sc.read_state().unwrap().is_none(), "初始无状态文件");
        let st = PosterStateFile {
            version: 1,
            cursor: 7,
            in_flight: vec![InFlightTask {
                key: SettleKey::new(6, 6),
                route: SettleRoute::Dual,
                phase: Some(SubmitPhase::RegisterVisible),
                txs: vec!["0xa".into()],
                attempts: 1,
                picked_at: 5,
            }],
            draining: false,
            updated_at: 8,
        };
        sc.write_state(&st).unwrap();
        assert_eq!(sc.read_state().unwrap().unwrap(), st);
        fs::remove_dir_all(&dir).ok();
    }
}
