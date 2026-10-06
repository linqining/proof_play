//! 牌局记录存储（P0-2 看板数据层）。
//!
//! 抽象接口 [`HandHistoryStore`]，当前为进程内实现 [`MemoryHistoryStore`]，
//! 每桌保留最近 [`DEFAULT_CAPACITY`] 条（FIFO 淘汰）。后续换 SQLite/Postgres
//! 只需新增实现并在 [`global_store`] 替换装配点，调用方（手牌终局挂钩 +
//! HTTP 查询端点）不动。
//!
//! 记录时机：两条手牌终局路径各记一次（互斥不重复）——
//! - 摊牌：`Table::finish_showdown`（settle_hand 末尾）
//! - 弃牌终局：`Table::end_without_showdown`

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::pokergame::deck::Card;
use crate::pokergame::side_pot::SidePot;

/// 每桌保留的最大记录条数。
pub const DEFAULT_CAPACITY: usize = 100;

/// 单手牌终局记录（快照自 Table summary，序列化为 camelCase 给前端看板）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandHistoryRecord {
    /// 桌内单调递增手数（从 1 开始）。
    pub hand_seq: u64,
    /// 终局时间戳（毫秒）。
    pub hand_over_at: u64,
    /// 是否进入摊牌。
    pub went_to_showdown: bool,
    /// 底池总额（含台费前的 gross pot）。
    pub gross_pot: u64,
    /// 本手台费（fold-win 恒为 0）。
    pub rake_collected: u64,
    /// 边池层级（终局快照）。
    pub side_pots: Vec<SidePot>,
    /// 公共牌（终局面）。
    pub board: Vec<Card>,
    /// 已亮出的玩家手牌（seat → 两张底牌；仅摊牌亮牌座位）。
    pub hole_cards: std::collections::HashMap<u32, Vec<Card>>,
    /// 赢家消息（净额，与前端展示一致）。
    pub win_messages: Vec<String>,
    /// 座位快照（钱包、用户名、下注、筹码，见 `Table::clean_seats_for_history`）。
    pub seats: serde_json::Value,
    /// 手内过程快照（发牌/各街/结算，见 `Table::update_history`）。
    pub streets: Vec<serde_json::Value>,
    /// 开局时间（epoch ms；0 = 旧记录未记录，用时不可算）。
    #[serde(default)]
    pub hand_started_at: u64,
    /// 摊牌各家牌型（seat → HandRank 显示名；fold-win 手为空）。
    #[serde(default)]
    pub showdown_hand_ranks: Vec<crate::pokergame::table_summary::ShowdownHandRank>,
    /// 每家净结果（seat → 终局 stack − 期初 stack；正 = 赢）。
    /// 期初快照在 start_hand 打（投盲注前），中途入座者无基线、不记。
    /// serde 序列化为 [seat, net] 元组数组。
    #[serde(default)]
    pub nets: Vec<(u32, i64)>,
    /// 逐动作展示流水（seat/player/action/amount/street/ts/auto），
    /// 与 #18 Poseidon 审计链（action_log）并行，仅用于前端凭证展示。
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    /// 本手 id（开局分配，动作签名域 / 结算记账 / 证明留存同源）。
    /// 0 = 旧记录未记录。证明通道按 (hand_seq → hand_id → proof_ledger)
    /// 索引，结算回执注册表按 (table_id, hand_id) 索引，本字段是两边的桥。
    #[serde(default)]
    pub hand_id: u32,
}

/// 牌局记录存储抽象。实现需线程安全（在服务器异步上下文中调用）。
pub trait HandHistoryStore: Send + Sync {
    /// 追加一条终局记录（分配 hand_seq）。
    fn append(&self, table_id: u32, record: HandHistoryRecord);
    /// 按桌查询最近记录，新→旧排序；`limit` 截断。
    fn list_by_table(&self, table_id: u32, limit: usize) -> Vec<HandHistoryRecord>;

    /// 当前记录总条数（测试用）。
    #[cfg(test)]
    fn len(&self, table_id: u32) -> usize;
    /// 精确取单手记录。
    fn get(&self, table_id: u32, hand_seq: u64) -> Option<HandHistoryRecord>;

    /// 按 hand_id（证明留存 / 结算回执的键）反查 hand_seq。
    /// 默认实现线性扫描最近记录；0 = 旧记录未记录 hand_id，视为无映射。
    fn find_seq_by_hand_id(&self, table_id: u32, hand_id: u32) -> Option<u64> {
        if hand_id == 0 {
            return None;
        }
        self.list_by_table(table_id, DEFAULT_CAPACITY)
            .into_iter()
            .find(|r| r.hand_id == hand_id)
            .map(|r| r.hand_seq)
    }
}

/// 进程内实现：每桌一个 FIFO 队列，超出容量淘汰最旧记录。
pub struct MemoryHistoryStore {
    inner: Mutex<HashMap<u32, VecDeque<HandHistoryRecord>>>,
    capacity: usize,
}

impl MemoryHistoryStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// 默认容量（100 条/桌）的实例。
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl HandHistoryStore for MemoryHistoryStore {
    fn append(&self, table_id: u32, mut record: HandHistoryRecord) {
        let mut map = match self.inner.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        let queue = map.entry(table_id).or_default();
        record.hand_seq = queue.back().map(|r| r.hand_seq + 1).unwrap_or(1);
        queue.push_back(record);
        while queue.len() > self.capacity {
            queue.pop_front();
        }
    }

    fn list_by_table(&self, table_id: u32, limit: usize) -> Vec<HandHistoryRecord> {
        let map = match self.inner.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        match map.get(&table_id) {
            Some(queue) => queue.iter().rev().take(limit).cloned().collect(),
            None => Vec::new(),
        }
    }

    fn get(&self, table_id: u32, hand_seq: u64) -> Option<HandHistoryRecord> {
        let map = match self.inner.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&table_id)?
            .iter()
            .find(|r| r.hand_seq == hand_seq)
            .cloned()
    }
    #[cfg(test)]
    fn len(&self, table_id: u32) -> usize {
        let map = match self.inner.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        map.get(&table_id).map(|v| v.len()).unwrap_or(0)
    }

}

/// 进程级默认存储实例。换持久化实现时只需改这一处装配。
pub fn global_store() -> &'static dyn HandHistoryStore {
    static STORE: OnceLock<MemoryHistoryStore> = OnceLock::new();
    STORE.get_or_init(MemoryHistoryStore::with_default_capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> HandHistoryRecord {
        HandHistoryRecord {
            hand_seq: 0,
            hand_over_at: 1,
            went_to_showdown: true,
            gross_pot: 100,
            rake_collected: 5,
            side_pots: vec![],
            board: vec![],
            hole_cards: std::collections::HashMap::new(),
            win_messages: vec!["A wins $95.00".into()],
            seats: serde_json::json!({}),
            streets: vec![],
            hand_started_at: 0,
            showdown_hand_ranks: vec![],
            nets: vec![],
            actions: vec![],
            hand_id: 0,
        }
    }

    #[test]
    fn append_assigns_monotonic_seq_per_table() {
        let store = MemoryHistoryStore::with_default_capacity();
        store.append(1, record());
        store.append(1, record());
        store.append(2, record());
        assert_eq!(store.len(1), 2);
        assert_eq!(store.len(2), 1);
        let list = store.list_by_table(1, 10);
        assert_eq!(list.len(), 2);
        // 新→旧：最新的 seq 最大
        assert_eq!(list[0].hand_seq, 2);
        assert_eq!(list[1].hand_seq, 1);
        assert_eq!(store.get(1, 2).map(|r| r.hand_seq), Some(2));
        assert!(store.get(1, 3).is_none());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = MemoryHistoryStore::new(3);
        for _ in 0..5 {
            store.append(7, record());
        }
        assert_eq!(store.len(7), 3);
        let list = store.list_by_table(7, 10);
        assert_eq!(list[0].hand_seq, 5, "最旧记录被淘汰，最新为 seq 5");
        assert_eq!(list.last().map(|r| r.hand_seq), Some(3));
    }

    #[test]
    fn list_limit_truncates() {
        let store = MemoryHistoryStore::with_default_capacity();
        for _ in 0..10 {
            store.append(9, record());
        }
        assert_eq!(store.list_by_table(9, 4).len(), 4);
    }
}
