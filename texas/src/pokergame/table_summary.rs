//! 链上 Table 状态快照类型（原 sui_events.rs 中的链中性部分）。
//!
//! 这些结构体描述牌桌的元数据 / 加密状态 / 运行时状态，
//! 虽然历史上对应 Sui Move 合约的 TableSummaryV2，但本身与链无关，
//! 现由 Starknet 结算路径复用，故独立成模块。

use serde::{Deserialize, Serialize};

use crate::pokergame::side_pot::SidePot;

/// 摊牌牌型条目（seat → HandRank 显示名）。
/// 用结构体而非 (u32, String) 元组：serde 把元组序列化成 JSON 数组，
/// 前端要的是带字段名的对象。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ShowdownHandRank {
    pub seat: u32,
    pub rank: String,
}

/// 链上 Table 的元数据快照，对应 Move 合约的 TableSummaryMeta
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryMeta {
    // 元数据
    // Move 类型为 ID，BCS 序列化为 32 字节原始 address（无长度前缀）
    pub table_id: [u8; 32],
    pub name: String,
    pub max_players: u64,
    pub small_blind: u64,
    pub big_blind: u64,
    // 活跃座位信息
    pub active_count: u64,
    pub button: u64,
    // 底池
    pub pot: u64,
    pub side_pots_count: u64,
    pub community_cards_count: u64,
    // 阶段
    pub round_state: u8,
    // 下注轮信息
    pub betting_round_exists: bool,
    pub betting_round_current_bet: u64,
    pub betting_round_min_raise: u64,
    pub betting_round_big_blind: u64,
    pub betting_round_last_raiser_seat: Option<u64>,
    pub betting_round_actions_taken: u64,
    // 当前行动玩家
    pub current_turn: Option<u64>,
    // 座位快照
    pub seats_occupied: Vec<bool>,
    // Move 类型为 vector<address>，BCS 序列化为 Vec<[u8; 32]>
    pub seat_players: Vec<[u8; 32]>,
    pub seat_stacks: Vec<u64>,
    pub seat_bets: Vec<u64>,
    pub seat_total_bets: Vec<u64>,
    pub seat_folded: Vec<bool>,
    pub seat_all_in: Vec<bool>,
    pub seat_is_waiting: Vec<bool>,
}

/// 链上 Table 的加密状态快照，对应 Move 合约的 TableSummaryCryptoState
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryCryptoState {
    /// 加密牌组（每个元素为 96 bytes: c1 || c2）
    pub deck_encrypted: Vec<Vec<u8>>,
    /// 聚合公钥 (G1 compressed bytes, 48 bytes)
    pub aggregated_pk: Vec<u8>,
    /// 每个座位的玩家公钥（空座位为空 vector）
    pub seat_pks: Vec<Vec<u8>>,
    /// 待洗牌玩家 seat_index 列表
    pub shuffle_pending_players: Vec<u64>,
    /// 已完成洗牌玩家 seat_index 列表
    pub shuffle_completed_players: Vec<u64>,
    /// reconstruct 随机系数 (scalar bytes, 32 bytes)
    pub reconstruct_coefficient: Vec<u8>,
    /// 待提交 reconstruct deck 的玩家 seat_index 列表
    pub reconstruct_pending_players: Vec<u64>,
    /// 已提交 reconstruct deck 的玩家 seat_index 列表
    pub reconstruct_completed_players: Vec<u64>,
}

/// 链上 Table 的状态快照，对应 Move 合约的 TableSummaryState
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryState {
    // 洗牌状态
    pub shuffle_current_shuffler: Option<u64>,
    pub shuffle_pending_count: u64,
    pub shuffle_completed_count: u64,
    // Reveal 阶段
    pub reveal_phase: u8,
    pub reveal_assignment_count: u64,
    // Reconstruct 阶段
    pub reconstruct_phase: u8,
    // 牌组大小
    pub deck_size: u64,
    // 已发牌数量
    pub cards_dealt: u64,
    // 明文牌组（52 张 G1 compressed bytes）
    pub deck_plaintext: Vec<Vec<u8>>,
    // 超时配置
    pub shuffle_timeout_ms: u64,
    pub reveal_timeout_ms: u64,
    pub betting_timeout_ms: u64,
    pub reconstruct_timeout_ms: u64,
    pub showdown_display_ms: u64,
    pub hand_complete_wait_ms: u64,
    pub ready_wait_ms: u64,
    // 时间戳
    pub ready_at: u64,
    pub shuffle_started_at: u64,
    pub reveal_started_at: u64,
    pub betting_started_at: u64,
    pub reconstruct_started_at: u64,
    pub showdown_at: u64,
    pub hand_complete_at: u64,
    // 一致性保证
    pub epoch: u64,
}

/// 链上 Table 的扩展快照（V2），对应合约中 get_table_summary_v2 的返回值。
/// 由于合约部署原因，crypto 字段移至独立的 V2 结构体（与 Move TableSummaryV2 对齐）。
///
/// 注意：`id`/`limit`/`call_amount` 等以下扩展字段是本地运行时状态，
/// 不在链上 struct 中（链上路径走 `TableSummaryV2Chain` + `From` 转换，
/// 新增字段缺省为 Default）。**不要**把新字段加进 meta/state/crypto 三个
/// 子结构——它们参与链上 BCS 反序列化，字段数变更会导致解析失败。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryV2 {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
    pub crypto: TableSummaryCryptoState,
    /// 本地 socket table ID（区别于 meta.table_id 链上地址 [u8;32]）
    pub id: u32,
    /// 桌面限额
    pub limit: u64,
    /// 当前跟注金额
    pub call_amount: Option<u64>,
    /// 最小下注额
    pub min_bet: u64,
    /// 当前手牌是否结束
    pub hand_over: bool,
    /// 胜利消息列表
    pub win_messages: Vec<String>,
    /// 是否进入摊牌
    pub went_to_showdown: bool,
    /// 边池列表（meta.side_pots_count 仅存数量，此处存完整结构）
    pub side_pots: Vec<SidePot>,
    /// 本手已收台费（链下口径与链上 settle 一致；新一手发牌时清零）
    pub rake_collected: u64,
    /// 历史操作记录
    pub history: Vec<serde_json::Value>,
    /// 本手开局时间（epoch ms；start_hand 设置，终局记录用）
    #[serde(default)]
    pub hand_started_at: u64,
    /// 摊牌各家牌型（determine_winner 时填充，新一手开局清零）。
    /// 供 ClientTable / 牌史看板下发。
    #[serde(default)]
    pub showdown_hand_ranks: Vec<ShowdownHandRank>,
    /// 本手逐动作展示流水（record_action 追加；start_hand 清零）。
    /// 与 #18 的 action_log（Poseidon 审计链）并行——这里只做展示，
    /// 不参与任何摘要/证明。
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
}

/// 链上 BCS 反序列化专用结构体，仅包含 Move 合约 `get_table_summary_v2` 返回的字段。
/// `TableSummaryV2` 中的 `id`/`limit`/`call_amount` 等字段是本地运行时状态，
/// 不在链上 struct 中，直接用 `TableSummaryV2` 做 BCS 反序列化会失败。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TableSummaryV2Chain {
    pub meta: TableSummaryMeta,
    pub state: TableSummaryState,
    pub crypto: TableSummaryCryptoState,
}

impl From<TableSummaryV2Chain> for TableSummaryV2 {
    fn from(chain: TableSummaryV2Chain) -> Self {
        TableSummaryV2 {
            meta: chain.meta,
            state: chain.state,
            crypto: chain.crypto,
            ..Default::default()
        }
    }
}
