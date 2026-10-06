//! queue WAL（`queue.jsonl`）——**texas 唯一写者**（单写者协议）。
//!
//! 形态：JSONL 追加日志，每行 `{ "seq": N, "event": … }`，seq 由写者单调
//! 分配（1 起）。poster 只经 [`scan_from`] 游标扫描尾部读取。
//!
//! texas 写入的三类事件（见 crate 文档）：
//! 1. [`WalEvent::Enqueued`]——append 入队（入队源 = prove_log 的
//!    `take_settle_input`，`texas/src/starknet/prove_log.rs:434`）；
//! 2. [`WalEvent::BuildDeadLettered`]——构建期死信（对账拒绝/构建失败）；
//! 3. [`WalEvent::Downgraded`]——Dual→Legacy 降级迁移（texas 依据 poster
//!    sidecar 的投递期死信回读触发，对齐 hooks.rs `snip36_settle_flow`
//!    「结算永不因证明阻塞/失败而丢失」的 legacy 保底回退语义）。
//!
//! poster 的拾取/在途/回执/投递期死信**不在本文件**——poster 独占 sidecar
//! （[`crate::sidecar`]）。双文件互不交叉是协议核心，单测钉板。
//!
//! 崩溃恢复：写者 append 采用「写行 + flush + sync_data」；撕裂尾行（无换行
//! 结束的半行）在 [`replay`]/[`scan_from`] 中被跳过，写者重开时
//! [`QueueWal::open`] 会截断撕裂尾行（crash-repair）。

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::state::{DeadLetterSource, TaskRecord, TaskState};
use crate::task::{SettleKey, SettleTask};

/// WAL 事件（texas 写；Enqueued 的 task 装箱——变体尺寸差悬殊）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalEvent {
    /// append 入队（幂等去重由 [`QueueState`] / [`QueueWal`] 保证）。
    Enqueued { task: Box<SettleTask> },
    /// Dual→Legacy 单向降级迁移（texas 依据 poster 死信回读触发）。
    Downgraded { key: SettleKey },
    /// 构建期死信（对账拒绝/构建失败——投递期死信由 poster 写 sidecar）。
    BuildDeadLettered { key: SettleKey, reason: String },
}

/// WAL 行（seq 由写者单调分配）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WalLine {
    seq: u64,
    event: WalEvent,
}

/// WAL 读写错误。
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json（行 {line}）: {source}")]
    Json {
        line: u64,
        #[source]
        source: serde_json::Error,
    },
    /// seq 回退/重复（写者 bug 或文件被外部编辑——fail-closed 拒绝续读）。
    #[error("WAL seq 非单调：期望 > {expect}，实得 {got}")]
    SeqRegression { expect: u64, got: u64 },
}

/// 入队去重结果错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnqueueError {
    /// 幂等去重：该单手键已在队列（未终态）——调用方应跳过（prove_log 仍可
    /// 记录事实，队列侧不重复入队）。
    #[error("duplicate settle task key {0}（单手键仅做队列去重）")]
    Duplicate(SettleKey),
    /// 该键已达投递终态（Receipted/DeadLetter）——不覆盖历史（对账事实源
    /// 是 prove_log；重结算走业务层裁决，队列不复活终态条目）。
    #[error("task key {0} already terminal in queue")]
    Terminal(SettleKey),
    #[error("WAL io: {0}")]
    Io(String),
}

/// WAL 全量重放状态（texas 启动恢复 / poster 对账视图共用）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueState {
    records: std::collections::BTreeMap<SettleKey, TaskRecord>,
    /// 入队前构建期死信（对账拒绝先于 enqueue 发生——hooks.rs 的
    /// refuse_settlement 路径）：无完整条目，只留墓碑防复活。
    build_dead: std::collections::BTreeMap<SettleKey, String>,
    last_seq: u64,
}

impl QueueState {
    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn record(&self, key: &SettleKey) -> Option<&TaskRecord> {
        self.records.get(key)
    }

    pub fn records(&self) -> impl Iterator<Item = &TaskRecord> {
        self.records.values()
    }

    /// 入队前构建期死信墓碑（对账拒绝先于 enqueue：无完整条目）。
    pub fn build_dead_reason(&self, key: &SettleKey) -> Option<&str> {
        self.build_dead.get(key).map(|s| s.as_str())
    }

    /// 非终态条目（重启对账续投的候选集）。
    pub fn open_records(&self) -> impl Iterator<Item = &TaskRecord> {
        self.records.values().filter(|r| !r.state.is_terminal())
    }

    /// 折叠一个事件（重放核心：入队去重、降级迁移、构建期死信）。
    fn fold(&mut self, event: WalEvent) -> Result<(), WalError> {
        match event {
            WalEvent::Enqueued { task } => {
                let task = *task;
                // 幂等去重：首个 Enqueued 生效，后续同键 Enqueued 忽略
                //（写者已在 append 前去重；此处是重放侧的防御性二次去重）。
                self.records
                    .entry(task.key)
                    .or_insert_with(|| TaskRecord::new(task));
            }
            WalEvent::Downgraded { key } => {
                if let Some(r) = self.records.get_mut(&key) {
                    // 重放侧降级：单向迁移；AlreadyLegacy 视为重放幂等。
                    let _ = r.downgrade_to_legacy();
                }
                // 未知键的 Downgraded（WAL 被外部裁剪）：忽略——对账由
                // prove_log 承担，队列 fail-soft。
            }
            WalEvent::BuildDeadLettered { key, reason } => {
                match self.records.get_mut(&key) {
                    Some(r) => {
                        if !r.state.is_terminal() {
                            r.state = TaskState::DeadLetter(DeadLetterSource::Build);
                            r.dead_reason = Some(reason.clone());
                        }
                    }
                    // 入队前死信：墓碑（enqueue 将拒绝——Terminal）。
                    None => {
                        self.build_dead.insert(key, reason);
                    }
                }
            }
        }
        Ok(())
    }

    /// 该键现在能否入队（幂等去重判定；入队前构建期死信墓碑 = Terminal）。
    pub fn enqueueability(&self, key: &SettleKey) -> Result<(), EnqueueError> {
        if self.build_dead.contains_key(key) {
            return Err(EnqueueError::Terminal(*key));
        }
        match self.records.get(key) {
            None => Ok(()),
            Some(r) if r.state.is_terminal() => Err(EnqueueError::Terminal(*key)),
            Some(_) => Err(EnqueueError::Duplicate(*key)),
        }
    }
}

/// 全量重放（撕裂尾行跳过；seq 非单调 fail-closed）。文件不存在 = 空队列。
pub fn replay(path: &Path) -> Result<QueueState, WalError> {
    fold_lines(path, &mut QueueState::default(), 0)
}

fn open_if_exists(path: &Path) -> Result<Option<File>, WalError> {
    match File::open(path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// poster 游标扫描：返回 seq > `cursor` 的事件（按 seq 升序）与新游标。
/// 撕裂尾行跳过（下轮重读）；seq 回退 fail-closed。
pub fn scan_from(path: &Path, cursor: u64) -> Result<(Vec<(u64, WalEvent)>, u64), WalError> {
    let Some(file) = open_if_exists(path)? else {
        return Ok((Vec::new(), cursor));
    };
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    let mut last_seq = cursor;
    let mut line_no: u64 = 0;
    // read_line 保留行尾换行——最后一行无 '\n' 即撕裂尾行（写者崩溃）。
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        if !buf.ends_with('\n') {
            // 撕裂尾行：跳过，不改游标——下轮重读。
            break;
        }
        let Some(parsed) = parse_line(&buf, line_no)? else {
            continue; // 空行容错
        };
        if parsed.seq <= cursor {
            last_seq = last_seq.max(parsed.seq);
            continue;
        }
        if parsed.seq <= last_seq && !out.is_empty() {
            return Err(WalError::SeqRegression {
                expect: last_seq,
                got: parsed.seq,
            });
        }
        last_seq = last_seq.max(parsed.seq);
        out.push((parsed.seq, parsed.event));
    }
    Ok((out, last_seq))
}

struct ParsedLine {
    seq: u64,
    event: WalEvent,
}

fn parse_line(line: &str, line_no: u64) -> Result<Option<ParsedLine>, WalError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let parsed: WalLine = serde_json::from_str(trimmed).map_err(|source| WalError::Json {
        line: line_no,
        source,
    })?;
    Ok(Some(ParsedLine {
        seq: parsed.seq,
        event: parsed.event,
    }))
}

fn fold_lines(path: &Path, state: &mut QueueState, cursor: u64) -> Result<QueueState, WalError> {
    let Some(file) = open_if_exists(path)? else {
        return Ok(std::mem::take(state));
    };
    let mut reader = BufReader::new(file);
    let mut line_no: u64 = 0;
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        line_no += 1;
        if !buf.ends_with('\n') {
            break; // 撕裂尾行（写者崩溃）——跳过，fail-closed 不折叠半行。
        }
        let Some(parsed) = parse_line(&buf, line_no)? else {
            continue;
        };
        if parsed.seq <= cursor {
            continue;
        }
        if parsed.seq <= state.last_seq {
            return Err(WalError::SeqRegression {
                expect: state.last_seq,
                got: parsed.seq,
            });
        }
        state.last_seq = parsed.seq;
        state.fold(parsed.event)?;
    }
    Ok(std::mem::take(state))
}

/// queue WAL 写者句柄（**texas 独占**；poster 永远不该持有此类型——
/// 类型即协议）。
pub struct QueueWal {
    path: PathBuf,
    file: File,
    last_seq: u64,
    /// 已在队列（未终态）的键（幂等去重索引，open 时重放构建）。
    open_keys: std::collections::HashSet<SettleKey>,
    /// 已达终态的键。
    terminal_keys: std::collections::HashSet<SettleKey>,
}

impl QueueWal {
    /// 打开（或创建）WAL。启动即重放：撕裂尾行截断修复（crash recovery）、
    /// 去重索引重建。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, WalError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // 先重放拿状态（同时定位撕裂尾行）。
        let state = replay(&path)?;
        let torn = read_has_torn_tail(&path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        if torn {
            // crash repair：截断撕裂尾行（半行 JSON 永不可信——fail-closed
            // 丢弃而非续写）。
            truncate_torn_tail(&mut file, &path)?;
        }
        let mut open_keys = std::collections::HashSet::new();
        let mut terminal_keys = std::collections::HashSet::new();
        for r in state.records() {
            if r.state.is_terminal() {
                terminal_keys.insert(r.task.key);
            } else {
                open_keys.insert(r.task.key);
            }
        }
        for key in state.build_dead.keys() {
            terminal_keys.insert(*key);
        }
        Ok(Self {
            path,
            file,
            last_seq: state.last_seq(),
            open_keys,
            terminal_keys,
        })
    }

    /// WAL 路径（观测用）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// append 入队（幂等去重：未终态重复键 [`EnqueueError::Duplicate`]，
    /// 终态键 [`EnqueueError::Terminal`]）。
    pub fn enqueue(&mut self, task: SettleTask) -> Result<u64, EnqueueError> {
        let key = task.key;
        if self.terminal_keys.contains(&key) {
            return Err(EnqueueError::Terminal(key));
        }
        if self.open_keys.contains(&key) {
            return Err(EnqueueError::Duplicate(key));
        }
        let seq = self
            .append(WalEvent::Enqueued {
                task: Box::new(task),
            })
            .map_err(|e| EnqueueError::Io(e.to_string()))?;
        self.open_keys.insert(key);
        Ok(seq)
    }

    /// 构建期死信（texas 写 WAL；投递期死信由 poster 写 sidecar——双源归属）。
    pub fn build_dead_letter(&mut self, key: SettleKey, reason: String) -> Result<u64, WalError> {
        let seq = self.append(WalEvent::BuildDeadLettered { key, reason })?;
        self.open_keys.remove(&key);
        self.terminal_keys.insert(key);
        Ok(seq)
    }

    /// Dual→Legacy 降级迁移（texas 依据 poster sidecar 死信回读触发；
    /// Legacy 键拒绝——单向迁移）。
    pub fn downgrade(&mut self, key: SettleKey) -> Result<u64, WalError> {
        let seq = self.append(WalEvent::Downgraded { key })?;
        // 键仍在队列（Enqueued 重投），open_keys 不变。
        Ok(seq)
    }

    fn append(&mut self, event: WalEvent) -> Result<u64, WalError> {
        let seq = self.last_seq + 1;
        let line = WalLine { seq, event };
        let mut buf =
            serde_json::to_string(&line).map_err(|source| WalError::Json { line: 0, source })?;
        buf.push('\n');
        self.file.write_all(buf.as_bytes())?;
        self.file.flush()?;
        self.file.sync_data()?;
        self.last_seq = seq;
        Ok(seq)
    }
}

fn read_has_torn_tail(path: &Path) -> Result<bool, WalError> {
    let Some(file) = open_if_exists(path)? else {
        return Ok(false);
    };
    // 撕裂尾行 = 最后一行缺 '\n'（read_line 保留换行，可据此判定）。
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    let mut torn = false;
    loop {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        torn = !buf.ends_with('\n');
    }
    Ok(torn)
}

fn truncate_torn_tail(file: &mut File, path: &Path) -> Result<(), WalError> {
    // 找到最后一个 '\n' 之后的位置，截断到那里。
    let meta = std::fs::metadata(path)?;
    let len = meta.len();
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; len as usize];
    use std::io::Read;
    f.read_exact(&mut buf)?;
    let Some(pos) = buf.iter().rposition(|&b| b == b'\n') else {
        // 整个文件没有完整行（首次崩溃在第一行）——清空。
        file.set_len(0)?;
        return Ok(());
    };
    file.set_len(pos as u64 + 1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{LegCalldata, SettlePayload, SettleRoute};

    fn dual_task(table: u32, hand: u32) -> SettleTask {
        SettleTask::dual(
            SettleKey::new(table, hand),
            "v2".into(),
            SettlePayload {
                register: LegCalldata {
                    selector: "0x11".into(),
                    calldata: vec!["0x1".into()],
                },
                settle: LegCalldata {
                    selector: "0x22".into(),
                    calldata: vec!["0x2".into()],
                },
                fold_statement: None,
            },
            None,
            42,
        )
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "settle-queue-test-{tag}-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 幂等去重：同键二次入队被拒；重放后写者去重索引一致。
    #[test]
    fn enqueue_dedup() {
        let dir = tmpdir("dedup");
        let wal_path = dir.join("queue.jsonl");
        let mut wal = QueueWal::open(&wal_path).unwrap();
        wal.enqueue(dual_task(1, 10)).unwrap();
        assert_eq!(
            wal.enqueue(dual_task(1, 10)),
            Err(EnqueueError::Duplicate(SettleKey::new(1, 10)))
        );
        // 不同键正常。
        wal.enqueue(dual_task(1, 11)).unwrap();

        // 重放：两条记录。
        let st = replay(&wal_path).unwrap();
        assert_eq!(st.records().count(), 2);
        assert_eq!(st.last_seq(), 2);

        // 重开（重启恢复）后去重索引仍在。
        let mut wal = QueueWal::open(&wal_path).unwrap();
        assert_eq!(
            wal.enqueue(dual_task(1, 10)),
            Err(EnqueueError::Duplicate(SettleKey::new(1, 10)))
        );
        // 终态键不复活。
        wal.build_dead_letter(SettleKey::new(1, 11), "对账拒绝".into())
            .unwrap();
        assert_eq!(
            wal.enqueue(dual_task(1, 11)),
            Err(EnqueueError::Terminal(SettleKey::new(1, 11)))
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// WAL 重放与崩溃恢复：撕裂尾行被跳过；写者重开时截断修复后可续写。
    #[test]
    fn replay_and_torn_tail_recovery() {
        let dir = tmpdir("torn");
        let wal_path = dir.join("queue.jsonl");
        {
            let mut wal = QueueWal::open(&wal_path).unwrap();
            wal.enqueue(dual_task(2, 1)).unwrap();
            wal.enqueue(dual_task(2, 2)).unwrap();
        }
        // 模拟崩溃：追加半行。
        {
            use std::io::Write;
            let mut f = OpenOptions::new().append(true).open(&wal_path).unwrap();
            f.write_all(br#"{"seq":3,"event":{"type":"enqueued","#)
                .unwrap();
        }
        // 重放：完整两行可见，撕裂行跳过。
        let st = replay(&wal_path).unwrap();
        assert_eq!(st.records().count(), 2);
        assert_eq!(st.last_seq(), 2);

        // poster 游标扫描同样跳过撕裂行且游标不推进。
        let (events, cursor) = scan_from(&wal_path, 0).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(cursor, 2);

        // 写者重开：截断撕裂尾行，续写 seq 连续。
        let mut wal = QueueWal::open(&wal_path).unwrap();
        let seq = wal.enqueue(dual_task(2, 3)).unwrap();
        assert_eq!(seq, 3);
        let st = replay(&wal_path).unwrap();
        assert_eq!(st.records().count(), 3);
        assert_eq!(st.last_seq(), 3);
        // 文件不再有撕裂尾。
        assert!(!read_has_torn_tail(&wal_path).unwrap());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 降级迁移重放：Downgraded 事件把 Dual 记录迁成 Legacy；poster 游标
    /// 扫描能看见迁移事件。
    #[test]
    fn downgrade_replay_and_scan() {
        let dir = tmpdir("downgrade");
        let wal_path = dir.join("queue.jsonl");
        let mut wal = QueueWal::open(&wal_path).unwrap();
        wal.enqueue(dual_task(3, 7)).unwrap();
        wal.downgrade(SettleKey::new(3, 7)).unwrap();
        wal.build_dead_letter(SettleKey::new(9, 9), "构建失败".into())
            .unwrap();

        let st = replay(&wal_path).unwrap();
        let r = st.record(&SettleKey::new(3, 7)).unwrap();
        assert_eq!(r.task.route, SettleRoute::Legacy);
        assert!(r.downgraded);
        // (9,9) 是入队前构建期死信：无完整条目，只有墓碑（enqueue 拒绝）。
        assert_eq!(
            st.build_dead_reason(&SettleKey::new(9, 9)),
            Some("构建失败")
        );
        assert_eq!(
            st.enqueueability(&SettleKey::new(9, 9)),
            Err(EnqueueError::Terminal(SettleKey::new(9, 9)))
        );

        // poster 扫描（增量）。
        let (events, cursor) = scan_from(&wal_path, 0).unwrap();
        assert_eq!(cursor, 3);
        assert_eq!(events.len(), 3);
        assert!(matches!(events[1].1, WalEvent::Downgraded { .. }));
        let (events2, cursor2) = scan_from(&wal_path, cursor).unwrap();
        assert!(events2.is_empty());
        assert_eq!(cursor2, cursor);
        std::fs::remove_dir_all(&dir).ok();
    }
}
