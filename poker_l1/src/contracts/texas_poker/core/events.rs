//! Texas Poker 事件定义（本模块为事件的权威定义）。
//!
//! 所有事件统一为 `TexasPokerEvent` 枚举，Borsh 序列化后由预编译合约
//! 通过 `emit_event` 写入事件日志（链下索引）。
//!
//! 事件分类：
//! 1. 牌桌生命周期：TableCreated / PlayerJoined / PlayerLeft / LeaveRequested
//! 2. 手牌生命周期：HandStarted / BlindsPosted / AntePosted / BettingRoundStarted /
//!    CurrentTurnChanged / RoundAdvanced / PotCollected / CommunityCardRevealed /
//!    ShowdownHoleCardsRevealed / WinnerAwarded / RakeCollected / HandSettled /
//!    HandEndedWithoutShowdown / HandReset / SettlementPlanCommitted
//! 3. 下注操作：PlayerFolded / PlayerChecked / PlayerBet / PlayerCalled / PlayerRaised /
//!    PlayerAllIn / TimeBankConsumed
//! 4. 洗牌协议：ShuffleVerified / ShuffleTurn / ShuffleComplete / ShuffleTimeout
//! 5. 揭示协议：RevealPhase / RevealTokenSubmitted / RevealPhaseComplete / RevealTimeout
//! 6. 重构协议：ReconstructInitiated / ReconstructDeckSubmitted / ReconstructComplete /
//!    ReconstructTimeout
//! 7. 玩家管理：PlayerKicked / PlayerRefund / AddonRequested / AddonCredited / RebuyProcessed
//! 8. 配置与牌组重建：DeckRebuilt / RunItTwiceTriggered

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::object_model::ObjectID;

use super::types::SeatMask;

// ========== 退款类型常量 ==========
//
// 退款/重置/弃牌原因常量的唯一定义在 `core/constants.rs`。
// 此处 re-export 维持 `events::X` 导入路径（state_machine / src/airs 消费者仍在用）。

pub use super::constants::{
    FOLD_REASON_AUTO_TIMEOUT, FOLD_REASON_FORCE_ADMIN, FOLD_REASON_MANUAL, REFUND_TYPE_BET_ONLY,
    REFUND_TYPE_STACK_ONLY, RESET_REASON_LAST_PLAYER_STANDING, RESET_REASON_RECONSTRUCT_FAIL,
    RESET_REASON_STATE_INCONSISTENT, RESET_REASON_TIMEOUT,
};

/// Canonical source of a player removal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum KickCause {
    /// A protocol deadline expired.
    Timeout = 0,
    /// The table administrator explicitly removed the player.
    Admin = 1,
    /// Reconstruction did not complete before its deadline.
    ReconstructTimeout = 2,
}

// ========== 牌组重建原因常量 ==========

/// 洗牌超时后降级重建明文牌组。
pub const DECK_REBUILT_REASON_SHUFFLE_TIMEOUT: u8 = 0;
/// 重构协议完成后重建规范牌组。
pub const DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE: u8 = 1;

// ========== 触发动作常量（PlayerAllIn）==========

/// all-in 由跟注触发（筹码不足以完整跟注，剩余全部推入）。
pub const TRIGGER_ACTION_CALL_ALL_IN: u8 = 0;
/// all-in 由加注触发（主动把剩余筹码全部推入）。
pub const TRIGGER_ACTION_RAISE_ALL_IN: u8 = 1;

// ========== pot_type 常量（WinnerAwarded）==========

/// 主池。
pub const POT_TYPE_MAIN: u8 = 0;
/// 边池。
pub const POT_TYPE_SIDE: u8 = 1;

/// Texas Poker 事件枚举（所有变体均为纯数据，Borsh 序列化友好）。
///
/// 统一为单一 enum，便于在 `dispatch` 阶段收集 `Vec<TexasPokerEvent>` 后批量 emit。
/// 变体声明顺序即 Borsh 判别式顺序，新增变体只能追加在末尾，不可插入或删除中间变体。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TexasPokerEvent {
    // ========== 1. 牌桌生命周期 ==========
    /// 牌桌创建成功（`create_table` 完成时发出，本组事件中的第一个）。
    ///
    /// v34 起不再携带展示名承诺：名字非共识，由非共识 metadata 对象承载。
    TableCreated {
        /// 牌桌对象 ID。
        table_id: ObjectID,
    },
    /// 玩家入座（`join_table` 成功时发出；买入从 chip_pool 锁定到座位 stack）。
    PlayerJoined {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 分配到的座位索引（0 起）。
        seat_index: u8,
        /// 玩家地址。
        player: Address,
        /// 本次买入金额（chip）。
        buy_in: u64,
        /// 是否标记为等待位（等待下一手才开始参与，不进入本局）。
        is_waiting: bool,
        /// 入座后桌上活跃座位数（occupied 且非 waiting）。
        active_count_after: u64,
    },
    /// 玩家离开牌桌（`leave_table` 生效、座位清空并退款后发出）。
    PlayerLeft {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 被清空的座位索引。
        seat_index: u8,
        /// 离场玩家地址。
        player: Address,
    },
    /// 玩家显式设置「本手结束后离场」意图。
    ///
    /// 由 `set_leave_after_hand` 方法在标志实际变化时发出。
    /// 实际离场（退款 + 座位清空）在下一手 `reset_for_next_hand` 时触发，
    /// 届时另发 `PlayerRefund` + `PlayerLeft`。
    LeaveRequested {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 发起预约的座位索引。
        seat_index: u8,
        /// 发起预约的玩家地址。
        player: Address,
        /// 显式目标值（true=已预约下局离场，false=取消预约）。
        want_leave: bool,
    },

    // ========== 2. 手牌生命周期 ==========
    /// 一手开始（`start_hand` 完成洗牌准备、确定按钮位与盲注后发出）。
    HandStarted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 本手按钮位（庄家）座位索引。
        button: u8,
        /// 小盲金额（chip）。
        small_blind: u64,
        /// 大盲金额（chip）。
        big_blind: u64,
        /// 参与本手的座位位掩码（bit i = 座位 i；定宽）。
        participants: SeatMask,
    },
    /// 盲注（含 ante）投注完成、即将进入 preflop 下注轮时发出。
    BlindsPosted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 小盲座位索引。
        sb_seat: u8,
        /// 大盲座位索引。
        bb_seat: u8,
        /// 小盲实投金额（chip，受 stack 限制可能小于名义值）。
        sb_amount: u64,
        /// 大盲实投金额（chip）。
        bb_amount: u64,
        /// preflop 首个行动座位（UTG）。
        first_to_act: u8,
    },
    /// 一条街的下注轮开始（发完公共牌 / preflop 盲注后就绪时发出）。
    BettingRoundStarted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 当前街道（见 constants 模块的 `ROUND_*` 常量）。
        round_state: u8,
        /// 本轮起始最高下注（chip；preflop=大盲，postflop=0）。
        current_bet: u64,
        /// 本轮最小加注增量（chip，初始 = 大盲）。
        min_raise: u64,
        /// 本轮首个行动座位。
        first_to_act: u8,
        /// 本轮开始前底池金额（chip，不含本轮尚未收集的下注）。
        pot_before: u64,
    },
    /// 街道推进（本轮下注收齐、即将揭示下一张公共牌时发出）。
    RoundAdvanced {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 推进前街道。
        from_round: u8,
        /// 推进后街道。
        to_round: u8,
        /// 推进时底池金额（chip）。
        pot: u64,
        /// 推进后已揭示的公共牌张数。
        community_cards_count: u64,
    },
    /// 本轮下注收集进底池（`collect_bets` 在街道切换前发出）。
    PotCollected {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 收集发生的街道。
        round_state: u8,
        /// 收集后底池金额（chip）。
        pot_after: u64,
        /// 本轮有下注被收集的座位位掩码（bit i = 座位 i）。
        collected_from_seats: SeatMask,
    },
    /// 结算时向单一赢家/平分者 award（settle 按池层逐个发出）。
    WinnerAwarded {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 获奖座位索引。
        seat_index: u8,
        /// 获奖玩家地址。
        player: Address,
        /// 获奖金额（chip）。
        amount: u64,
        /// 0=main_pot, 1=side_pot
        pot_type: u8,
        /// 最佳牌型（None=无摊牌直接获胜）
        hand_rank: Option<u8>,
    },
    /// 一手结算完成（settle 汇总发出，随后进入摊牌展示或直接重置）。
    HandSettled {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 本手最终底池（chip，已含全部收集）。
        pot: u64,
        /// 获奖座位位掩码（含平分者；bit i = 座位 i）。
        winners: SeatMask,
    },
    /// 无摊牌结束（其余玩家全部弃牌，唯一剩余玩家直接赢得底池）。
    HandEndedWithoutShowdown {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 获胜座位索引。
        winner_seat: u8,
        /// 获胜玩家地址。
        winner_player: Address,
        /// 获胜金额（chip，即本手底池）。
        pot: u64,
    },
    /// 本手被重置（异常路径：超时/踢人/重构失败等，见 RESET_REASON_* 常量）。
    HandReset {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 重置原因（见 `RESET_REASON_*` 常量）。
        reason: u8,
        /// 重置发生时的街道。
        round_state: u8,
    },

    // ========== 3. 下注操作 ==========
    /// 玩家弃牌（主动或超时/管理员触发）。
    PlayerFolded {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 弃牌座位索引。
        seat_index: u8,
        /// 0=manual, 1=auto_timeout, 2=force_admin
        reason: u8,
        /// 弃牌发生时的街道。
        round_state: u8,
    },
    /// 玩家过牌（无需补齐下注时）。
    PlayerChecked {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 过牌座位索引。
        seat_index: u8,
        /// 过牌发生时的街道。
        round_state: u8,
    },
    /// 玩家跟注（补齐到当前最高下注；all-in 时金额可能不足）。
    PlayerCalled {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 跟注座位索引。
        seat_index: u8,
        /// 实际补入的跟注金额（chip，all-in 时 < chips_to_call）。
        call_delta: u64,
        /// 跟注发生时的街道。
        round_state: u8,
    },
    /// 玩家加注（把本轮下注抬高到新总额）。
    PlayerRaised {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 加注座位索引。
        seat_index: u8,
        /// 相对原最高下注的增量（chip）。
        raise_delta: u64,
        /// 加注后该座位本轮累计下注（chip）。
        total_bet: u64,
        /// 加注发生时的街道。
        round_state: u8,
    },
    /// 玩家全下（筹码全部推入）。
    PlayerAllIn {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 全下座位索引。
        seat_index: u8,
        /// 0=call_all_in, 1=raise_all_in
        trigger_action: u8,
        /// 全下推入的金额（chip）。
        amount: u64,
        /// 全下发生时的街道。
        round_state: u8,
    },

    // ========== 4. 洗牌协议 ==========
    /// 某玩家的洗牌贡献通过 ZK 验证（`submit_shuffle_v2` 成功后发出）。
    ShuffleVerified {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 提交洗牌的座位索引。
        seat_index: u8,
        /// 提交洗牌的玩家地址。
        player: Address,
    },
    /// 轮转到下一位洗牌者（前一位验证通过后由状态机发出）。
    ShuffleTurn {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 新轮到的洗牌座位索引。
        seat_index: u8,
        /// 尚未完成洗牌的贡献者数量。
        pending_count: u64,
        /// 已完成洗牌的贡献者数量。
        completed_count: u64,
    },
    /// 全员洗牌完成（聚合密钥就绪、加密牌组可发牌时发出）。
    ShuffleComplete {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 完成时的洗牌阶段（见 `SHUFFLE_PHASE_*` 常量）。
        phase: u8,
        /// 参与本手洗牌的玩家数。
        participant_count: u64,
        /// 洗牌后加密牌组的张数。
        deck_size: u64,
    },
    /// 洗牌超时（某贡献者在截止前未提交，触发降级或踢人）。
    ShuffleTimeout {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 超时的座位索引。
        seat_index: u8,
        /// 超时发生的洗牌阶段。
        phase: u8,
        /// 本轮洗牌开始时刻（Unix 毫秒）。
        started_at: u64,
        /// 配置的超时阈值（毫秒）。
        timeout_ms: u64,
    },

    // ========== 5. 揭示协议 ==========
    /// 揭示阶段切换（进入 flop/turn/river/showdown 或重发流程时发出）。
    RevealPhase {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 新进入的揭示阶段（见 `REVEAL_PHASE_*` 常量）。
        phase: u8,
    },
    /// 某座位提交了一张牌的揭示令牌（部分解密贡献）。
    RevealTokenSubmitted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 提交令牌的座位索引。
        seat_index: u8,
        /// 目标牌在牌组中的索引。
        card_index: u8,
        /// 提交时的揭示阶段。
        phase: u8,
    },
    /// 一个揭示阶段完成（该阶段所有令牌集齐、牌面可解密时发出）。
    RevealPhaseComplete {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 完成的揭示阶段。
        phase: u8,
    },
    /// 揭示超时（有座位未在截止前提交令牌）。
    RevealTimeout {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 超时的揭示阶段。
        phase: u8,
        /// 未按时提交令牌的座位位掩码（bit i = 座位 i）。
        pending_players: SeatMask,
    },
    /// 公共牌揭示（flop/turn/river 阶段牌面解密完成时发出）。
    CommunityCardRevealed {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 揭示发生的阶段（flop/turn/river）。
        phase: u8,
        /// 本次揭示的牌索引（按发牌顺序，`card_count` 之后补 0）。
        /// 定宽 6 = RIT flop 双跑 3+3，对齐
        /// `MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS`。
        card_indices: [u8; 6],
        /// 对应牌的点数（2-14，与 card_indices 同序）。
        card_ranks: [u8; 6],
        /// 对应牌的花色（编码 0-3，见 card 模块花色常量，与 card_indices 同序）。
        card_suits: [u8; 6],
        /// 有效牌数（1..=6）。
        card_count: u8,
    },
    /// 摊牌时某玩家亮出手牌（showdown 解密完成时逐座位发出）。
    ShowdownHoleCardsRevealed {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 亮牌座位索引。
        seat_index: u8,
        /// 亮牌玩家地址。
        player: Address,
        /// 手牌的牌索引（固定 2 张，发牌顺序）。
        card_indices: [u8; 2],
        /// 手牌点数（2-14，与 card_indices 同序）。
        card_ranks: [u8; 2],
        /// 手牌花色（0-3，与 card_indices 同序）。
        card_suits: [u8; 2],
    },

    // ========== 6. 重构协议 ==========
    /// 牌组重构启动（玩家离场致密钥份额缺失时，转由剩余玩家重构牌组明文）。
    ReconstructInitiated {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 需提交重构份额的座位位掩码（bit i = 座位 i）。
        expected_players: SeatMask,
        /// 重构启动时的街道。
        round_state: u8,
    },
    /// 某座位提交了重构份额（`submit_reconstruct_deck` 验证通过后发出）。
    ReconstructDeckSubmitted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 提交份额的座位索引。
        seat_index: u8,
    },
    /// 重构完成（所有份额集齐、牌组明文恢复，随后重建规范牌组）。
    ReconstructComplete {
        /// 牌桌对象 ID。
        table_id: ObjectID,
    },
    /// 重构超时（有座位未在截止前提交份额）。
    ReconstructTimeout {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 未按时提交份额的座位位掩码（bit i = 座位 i）。
        pending_players: SeatMask,
    },

    // ========== 7. 玩家管理 ==========
    /// 玩家被踢出（超时/管理员/重构超时，随后附退款与离场事件）。
    PlayerKicked {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 被踢座位索引。
        seat_index: u8,
        /// 被踢玩家地址。
        player: Address,
        /// 踢出原因（见 [`KickCause`]）。
        reason: KickCause,
    },
    /// 向离场/被踢玩家退款（座位资产退回 chip_pool 时发出）。
    PlayerRefund {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 退款座位索引。
        seat_index: u8,
        /// 退款玩家地址。
        player: Address,
        /// 退款金额（chip）。
        amount: u64,
        /// 退款类型（见 `REFUND_TYPE_*` 常量）。
        refund_type: u8,
    },

    // ========== 8. 配置与牌组重建 ==========
    /// 牌组重建（超时降级或重构完成后以明文规范牌组替换原牌组）。
    DeckRebuilt {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 重建原因（见 `DECK_REBUILT_REASON_*` 常量）。
        reason: u8,
        /// 重建后牌组张数。
        deck_size: u64,
    },
    /// 行动权变更（advance_turn 每次切换当前行动座位时发出）。
    CurrentTurnChanged {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 变更前行动座位（None=轮空/无行动者）。
        old_turn: Option<u8>,
        /// 变更后行动座位（None=本手行动阶段结束）。
        new_turn: Option<u8>,
        /// 变更发生时的街道。
        round_state: u8,
    },

    // ========== 9. Addon / Rebuy ==========
    /// 玩家发起 addon（下一手生效）。
    AddonRequested {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 发起 addon 的座位索引。
        seat_index: u8,
        /// 发起 addon 的玩家地址。
        player: Address,
        /// 请求加购的金额（chip）。
        amount: u64,
        /// 请求后该座位累计的待生效 addon 总额（chip）。
        pending_after: u64,
    },
    /// addon 在 `reset_for_next_hand` 合并到 stack 时触发。
    AddonCredited {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 收到 addon 的座位索引。
        seat_index: u8,
        /// 收到 addon 的玩家地址。
        player: Address,
        /// 本次入账金额（chip）。
        amount: u64,
        /// 入账后座位 stack 余额（chip）。
        stack_after: u64,
    },
    /// 玩家 rebuy（立即生效，仅 MTT 早期/特殊规则）。
    RebuyProcessed {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// rebuy 的座位索引。
        seat_index: u8,
        /// rebuy 的玩家地址。
        player: Address,
        /// 本次 rebuy 金额（chip）。
        amount: u64,
        /// 入账后座位 stack 余额（chip）。
        stack_after: u64,
    },

    // ========== 10. Bet 动作 ==========
    /// 玩家主动下注（postflop 第一个下注者）。
    PlayerBet {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 下注座位索引。
        seat_index: u8,
        /// 下注金额（chip）。
        amount: u64,
        /// 下注发生时的街道。
        round_state: u8,
    },

    // ========== 11. Time Bank ==========
    /// 玩家 Time Bank 被消耗（超时续命）。
    TimeBankConsumed {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 消耗 Time Bank 的座位索引。
        seat_index: u8,
        /// 本次消耗量（毫秒）。
        consumed_ms: u64,
        /// 消耗后剩余额度（毫秒）。
        remaining_ms: u64,
    },

    // ========== 12. Ante ==========
    /// Ante 被投注（start_hand 时）。
    AntePosted {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 投 ante 的座位索引。
        seat_index: u8,
        /// ante 金额（chip）。
        amount: u64,
        /// ante 模式（见 `ANTE_MODE_*` 常量）。
        ante_mode: u8,
    },

    // ========== 13. Rake ==========
    /// Rake 被抽水（settle 时）。
    RakeCollected {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 抽水前底池（chip）。
        pot_before: u64,
        /// 抽走的 rake 金额（chip，归 treasury）。
        rake_amount: u64,
        /// 抽水后底池（chip）。
        pot_after: u64,
        /// rake 模式（见 `RAKE_MODE_*` 常量）。
        rake_mode: u8,
    },

    // ========== 14. Run It Twice ==========
    /// Run It Twice 被触发（all-in 后）。
    RunItTwiceTriggered {
        /// 牌桌对象 ID。
        table_id: ObjectID,
        /// 第一副牌局的后续公共牌张数。
        board1_cards: u8, // 牌数
        /// 第二副牌局的后续公共牌张数。
        board2_cards: u8,
    },

    // ========== 15. Canonical settlement plan ==========
    /// The state machine derived and atomically applied a canonical settlement plan.
    ///
    /// The digest commits to every pot layer, runout amount, eligible/winner mask, hand rank,
    /// per-seat award, rake allocation, and odd-chip decision.
    SettlementPlanCommitted {
        /// Settled table.
        table_id: ObjectID,
        /// Domain-separated digest of the canonical Borsh settlement plan v2.
        plan_digest: [u8; 32],
        /// Number of independent runouts (`1` or `2`).
        runout_count: u8,
        /// Total wager amount before rake.
        gross_pot: u64,
        /// Total rake removed from table custody.
        rake: u64,
        /// Total amount awarded to seats.
        total_awards: u64,
    },

    // ========== 16. Hole-card redeal ==========
    /// A hole card was re-dealt (dead-slot recovery): the holder replaced a card whose
    /// decryption yields a non-canonical plaintext with the next unconsumed deck card, and a
    /// [`crate::contracts::texas_poker::constants::REVEAL_PHASE_REDEAL`] token window opened
    /// with betting suspended. Emitted before the redeal token collection starts.
    HoleCardRedealt {
        /// Redealing table.
        table_id: ObjectID,
        /// Holder seat index.
        seat_index: u8,
        /// Replaced hole-card slot (0/1).
        card_slot: u8,
        /// Deck index of the replacement card (the previous `cards_dealt` cursor position).
        new_card_index: u8,
        /// Betting street the redeal suspends.
        round_state: u8,
    },
}

/// 将事件追加到事件日志（链下索引友好）。
///
/// 仅追加，不返回值。
/// 调用方在 `dispatch` 中收集所有事件后，由 Precompile::call 批量 emit。
pub fn emit_event(events: &mut Vec<TexasPokerEvent>, evt: TexasPokerEvent) {
    events.push(evt);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_table_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    #[test]
    fn test_event_borsh_roundtrip_table_created() {
        let evt = TexasPokerEvent::TableCreated {
            table_id: dummy_table_id(),
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_player_joined() {
        let evt = TexasPokerEvent::PlayerJoined {
            table_id: dummy_table_id(),
            seat_index: 3,
            player: [0xAB; 20],
            buy_in: 1_000_000,
            is_waiting: false,
            active_count_after: 4,
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_hand_started() {
        let evt = TexasPokerEvent::HandStarted {
            table_id: dummy_table_id(),
            button: 0,
            small_blind: 50,
            big_blind: 100,
            participants: 0b1111,
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_community_card_revealed() {
        let evt = TexasPokerEvent::CommunityCardRevealed {
            table_id: dummy_table_id(),
            phase: 3, // flop
            card_indices: [0, 1, 2, 0, 0, 0],
            card_ranks: [14, 13, 7, 0, 0, 0], // A, K, 7
            card_suits: [0, 1, 2, 0, 0, 0],   // club, diamond, heart
            card_count: 3,
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_current_turn_changed() {
        let evt = TexasPokerEvent::CurrentTurnChanged {
            table_id: dummy_table_id(),
            old_turn: Some(0),
            new_turn: Some(1),
            round_state: 2, // preflop
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_current_turn_changed_none() {
        let evt = TexasPokerEvent::CurrentTurnChanged {
            table_id: dummy_table_id(),
            old_turn: Some(2),
            new_turn: None,
            round_state: 6, // showdown
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_emit_event_appends() {
        let mut events: Vec<TexasPokerEvent> = vec![];
        emit_event(
            &mut events,
            TexasPokerEvent::TableCreated {
                table_id: dummy_table_id(),
            },
        );
        emit_event(
            &mut events,
            TexasPokerEvent::PlayerJoined {
                table_id: dummy_table_id(),
                seat_index: 0,
                player: [0; 20],
                buy_in: 1000,
                is_waiting: false,
                active_count_after: 1,
            },
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], TexasPokerEvent::TableCreated { .. }));
        assert!(matches!(events[1], TexasPokerEvent::PlayerJoined { .. }));
    }

    #[test]
    fn test_constants_values() {
        // 验证原因/类型常量的数值（链下索引按这些数值解码事件字段）
        assert_eq!(REFUND_TYPE_STACK_ONLY, 0);
        assert_eq!(REFUND_TYPE_BET_ONLY, 2);

        assert_eq!(KickCause::Timeout as u8, 0);
        assert_eq!(KickCause::Admin as u8, 1);
        assert_eq!(KickCause::ReconstructTimeout as u8, 2);

        assert_eq!(RESET_REASON_TIMEOUT, 0);
        assert_eq!(RESET_REASON_RECONSTRUCT_FAIL, 2);
        assert_eq!(RESET_REASON_LAST_PLAYER_STANDING, 3);
        assert_eq!(RESET_REASON_STATE_INCONSISTENT, 4);

        assert_eq!(FOLD_REASON_MANUAL, 0);
        assert_eq!(FOLD_REASON_AUTO_TIMEOUT, 1);
        assert_eq!(FOLD_REASON_FORCE_ADMIN, 2);

        assert_eq!(DECK_REBUILT_REASON_SHUFFLE_TIMEOUT, 0);
        assert_eq!(DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE, 1);

        assert_eq!(TRIGGER_ACTION_CALL_ALL_IN, 0);
        assert_eq!(TRIGGER_ACTION_RAISE_ALL_IN, 1);

        assert_eq!(POT_TYPE_MAIN, 0);
        assert_eq!(POT_TYPE_SIDE, 1);
    }

    #[test]
    fn test_all_variants_borsh_serializable() {
        // 烟雾测试：枚举每个分支的 Borsh 序列化至少不 panic。
        // 覆盖所有 45 个变体，确保 derive(Serialize, Deserialize) 正确。
        let table_id = dummy_table_id();
        let samples: Vec<TexasPokerEvent> = vec![
            TexasPokerEvent::TableCreated { table_id },
            TexasPokerEvent::PlayerJoined {
                table_id,
                seat_index: 0,
                player: [0; 20],
                buy_in: 0,
                is_waiting: false,
                active_count_after: 0,
            },
            TexasPokerEvent::PlayerLeft {
                table_id,
                seat_index: 0,
                player: [0; 20],
            },
            TexasPokerEvent::LeaveRequested {
                table_id,
                seat_index: 0,
                player: [0; 20],
                want_leave: true,
            },
            TexasPokerEvent::HandStarted {
                table_id,
                button: 0,
                small_blind: 0,
                big_blind: 0,
                participants: 0,
            },
            TexasPokerEvent::BlindsPosted {
                table_id,
                sb_seat: 0,
                bb_seat: 1,
                sb_amount: 0,
                bb_amount: 0,
                first_to_act: 0,
            },
            TexasPokerEvent::BettingRoundStarted {
                table_id,
                round_state: 0,
                current_bet: 0,
                min_raise: 0,
                first_to_act: 0,
                pot_before: 0,
            },
            TexasPokerEvent::RoundAdvanced {
                table_id,
                from_round: 0,
                to_round: 0,
                pot: 0,
                community_cards_count: 0,
            },
            TexasPokerEvent::PotCollected {
                table_id,
                round_state: 0,
                pot_after: 0,
                collected_from_seats: 0,
            },
            TexasPokerEvent::WinnerAwarded {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                pot_type: 0,
                hand_rank: None,
            },
            TexasPokerEvent::HandSettled {
                table_id,
                pot: 0,
                winners: 0,
            },
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id,
                winner_seat: 0,
                winner_player: [0; 20],
                pot: 0,
            },
            TexasPokerEvent::HandReset {
                table_id,
                reason: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerFolded {
                table_id,
                seat_index: 0,
                reason: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerChecked {
                table_id,
                seat_index: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerCalled {
                table_id,
                seat_index: 0,
                call_delta: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerRaised {
                table_id,
                seat_index: 0,
                raise_delta: 0,
                total_bet: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerAllIn {
                table_id,
                seat_index: 0,
                trigger_action: 0,
                amount: 0,
                round_state: 0,
            },
            TexasPokerEvent::ShuffleVerified {
                table_id,
                seat_index: 0,
                player: [0; 20],
            },
            TexasPokerEvent::ShuffleTurn {
                table_id,
                seat_index: 0,
                pending_count: 0,
                completed_count: 0,
            },
            TexasPokerEvent::ShuffleComplete {
                table_id,
                phase: 0,
                participant_count: 0,
                deck_size: 0,
            },
            TexasPokerEvent::ShuffleTimeout {
                table_id,
                seat_index: 0,
                phase: 0,
                started_at: 0,
                timeout_ms: 0,
            },
            TexasPokerEvent::RevealPhase { table_id, phase: 0 },
            TexasPokerEvent::RevealTokenSubmitted {
                table_id,
                seat_index: 0,
                card_index: 0,
                phase: 0,
            },
            TexasPokerEvent::RevealPhaseComplete { table_id, phase: 0 },
            TexasPokerEvent::RevealTimeout {
                table_id,
                phase: 0,
                pending_players: 0,
            },
            TexasPokerEvent::CommunityCardRevealed {
                table_id,
                phase: 0,
                card_indices: [0; 6],
                card_ranks: [0; 6],
                card_suits: [0; 6],
                card_count: 0,
            },
            TexasPokerEvent::ShowdownHoleCardsRevealed {
                table_id,
                seat_index: 0,
                player: [0; 20],
                card_indices: [0; 2],
                card_ranks: [0; 2],
                card_suits: [0; 2],
            },
            TexasPokerEvent::ReconstructInitiated {
                table_id,
                expected_players: 0,
                round_state: 0,
            },
            TexasPokerEvent::ReconstructDeckSubmitted {
                table_id,
                seat_index: 0,
            },
            TexasPokerEvent::ReconstructComplete { table_id },
            TexasPokerEvent::ReconstructTimeout {
                table_id,
                pending_players: 0,
            },
            TexasPokerEvent::PlayerKicked {
                table_id,
                seat_index: 0,
                player: [0; 20],
                reason: KickCause::Timeout,
            },
            TexasPokerEvent::PlayerRefund {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                refund_type: 0,
            },
            TexasPokerEvent::DeckRebuilt {
                table_id,
                reason: 0,
                deck_size: 0,
            },
            TexasPokerEvent::CurrentTurnChanged {
                table_id,
                old_turn: None,
                new_turn: None,
                round_state: 0,
            },
            TexasPokerEvent::AddonRequested {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                pending_after: 0,
            },
            TexasPokerEvent::AddonCredited {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                stack_after: 0,
            },
            TexasPokerEvent::RebuyProcessed {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                stack_after: 0,
            },
            TexasPokerEvent::PlayerBet {
                table_id,
                seat_index: 0,
                amount: 0,
                round_state: 0,
            },
            TexasPokerEvent::TimeBankConsumed {
                table_id,
                seat_index: 0,
                consumed_ms: 0,
                remaining_ms: 0,
            },
            TexasPokerEvent::AntePosted {
                table_id,
                seat_index: 0,
                amount: 0,
                ante_mode: 0,
            },
            TexasPokerEvent::RakeCollected {
                table_id,
                pot_before: 0,
                rake_amount: 0,
                pot_after: 0,
                rake_mode: 0,
            },
            TexasPokerEvent::RunItTwiceTriggered {
                table_id,
                board1_cards: 0,
                board2_cards: 0,
            },
            TexasPokerEvent::SettlementPlanCommitted {
                table_id,
                plan_digest: [0; 32],
                runout_count: 1,
                gross_pot: 0,
                rake: 0,
                total_awards: 0,
            },
        ];

        for evt in &samples {
            let bytes = borsh::to_vec(evt).expect("Borsh serialize 失败");
            let _recovered: TexasPokerEvent =
                borsh::from_slice(&bytes).expect("Borsh deserialize 失败");
        }
        // 验证样本数量（45 个变体；从未发出的 redeal 协议事件与
        // 无发射点的 TimeoutConfigUpdated 已删除）
        assert_eq!(samples.len(), 45, "事件变体数应为 45");
    }
}
