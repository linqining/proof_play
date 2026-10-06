//! Texas Poker 合约状态常量（移植自 `texas_poker_move/sources/table_constants.move`）。
//!
//! 所有常量值与 Move 端逐字节一致，确保状态机语义不变。

// ===== 玩家与牌组 =====

/// 最少开局玩家数。
pub const MIN_PLAYERS_TO_START: u8 = 2;

/// 最多玩家数。
pub const MAX_PLAYERS: u8 = 9;

/// 每个玩家手牌数（德州扑克固定 2 张）。
pub const CARDS_PER_PLAYER: u8 = 2;

// ===== Round 状态（round_state 字段）=====

/// 等待开始。
pub const ROUND_WAITING: u8 = 0;
/// 翻牌前。
pub const ROUND_PREFLOP: u8 = 2;
/// 翻牌（3 张公共牌）。
pub const ROUND_FLOP: u8 = 3;
/// 转牌（第 4 张公共牌）。
pub const ROUND_TURN: u8 = 4;
/// 河牌（第 5 张公共牌）。
pub const ROUND_RIVER: u8 = 5;
/// 摊牌。
pub const ROUND_SHOWDOWN: u8 = 6;

// ===== Shuffle Phase（shuffle_state.phase 字段）=====

/// 未在洗牌阶段（默认）。
pub const SHUFFLE_PHASE_NONE: u8 = 0;
/// 玩家离场致密钥不全，正在重构牌组。
pub const SHUFFLE_PHASE_RECONSTRUCT: u8 = 2;
/// 洗牌完成、即将进入翻牌前下注。
pub const SHUFFLE_PHASE_BEFORE_PREFLOP: u8 = 3;

// ===== Legacy reveal phase ABI（由 RevealPurpose + HandPhase.street 唯一投影）=====

/// 未在揭示阶段。
pub const REVEAL_PHASE_NONE: u8 = 0;
/// 翻牌前揭示（发底牌对应的令牌收集）。
pub const REVEAL_PHASE_PREFLOP: u8 = 1;
/// 换牌揭示（redeal：死槽底牌替换后的令牌重收集；与游戏层
/// `RevealPhase::RedealReveal` 的数值 ABI 对齐）。
pub const REVEAL_PHASE_REDEAL: u8 = 2;
/// 翻牌（flop 3 张公共牌）揭示。
pub const REVEAL_PHASE_FLOP: u8 = 3;
/// 转牌（turn 第 4 张公共牌）揭示。
pub const REVEAL_PHASE_TURN: u8 = 4;
/// 河牌（river 第 5 张公共牌）揭示。
pub const REVEAL_PHASE_RIVER: u8 = 5;
/// 摊牌（亮出全部剩余玩家底牌）。
pub const REVEAL_PHASE_SHOWDOWN: u8 = 6;

// ===== Reconstruct Phase（reconstruct_state.phase 字段）=====

/// 未在重构阶段（默认）。
pub const RECONSTRUCT_PHASE_NONE: u8 = 0;
/// 正在收集玩家的重构份额。
pub const RECONSTRUCT_PHASE_COLLECTING: u8 = 1;

// ===== 下注动作位掩码（betting.rs 用）=====

/// 弃牌动作位（永远可用）。
pub const ACTION_FOLD: u8 = 1;
/// 过牌动作位（无需补齐下注时可用）。
pub const ACTION_CHECK: u8 = 2;
/// 跟注动作位（需补齐下注且还有筹码时可用）。
pub const ACTION_CALL: u8 = 4;
/// 加注动作位（筹码超过跟注额时可用）。
pub const ACTION_RAISE: u8 = 8;

// ===== 退款类型 =====

/// 仅退座位剩余 stack（未参与本手下注）。
pub const REFUND_TYPE_STACK_ONLY: u8 = 0;
/// 仅退本手已下注（stack 已为 0）。
pub const REFUND_TYPE_BET_ONLY: u8 = 2;

// ===== 踢人原因 =====

/// 协议某阶段超时被踢。
pub const KICK_REASON_TIMEOUT: super::events::KickCause = super::events::KickCause::Timeout;
/// 管理员显式踢出。
pub const KICK_REASON_ADMIN: super::events::KickCause = super::events::KickCause::Admin;
/// 重构超时被踢。
pub const KICK_REASON_RECONSTRUCT_TIMEOUT: super::events::KickCause =
    super::events::KickCause::ReconstructTimeout;

// ===== 重置原因 =====

/// 协议超时触发重置。
pub const RESET_REASON_TIMEOUT: u8 = 0;
/// 牌组重构验证失败触发重置。
pub const RESET_REASON_RECONSTRUCT_FAIL: u8 = 2;
/// 仅剩一名玩家触发重置。
pub const RESET_REASON_LAST_PLAYER_STANDING: u8 = 3;
/// 状态一致性校验失败触发重置。
pub const RESET_REASON_STATE_INCONSISTENT: u8 = 4;

// ===== 弃牌原因 =====

/// 玩家主动弃牌。
pub const FOLD_REASON_MANUAL: u8 = 0;
/// 行动超时自动弃牌。
pub const FOLD_REASON_AUTO_TIMEOUT: u8 = 1;
/// 管理员强制弃牌。
pub const FOLD_REASON_FORCE_ADMIN: u8 = 2;

// 牌组重建原因（DECK_REBUILT_REASON_*）唯一权威在 core/events.rs；
// 此处旧的同值别名 DECK_REBUILD_REASON_* 已删除（零引用）。

// ===== 金额与超时 =====

// 以下默认超时是 `types::TimeoutConfig::default` 的唯一权威来源
// （default 逐字段引用这些常量，消除两处硬编码的分叉）。
// 数值以 Rust 状态机现行为准：shuffle/reveal/reconstruct = 10s，betting = 30s。

/// 默认洗牌超时（毫秒）。
pub const DEFAULT_SHUFFLE_TIMEOUT_MS: u32 = 10_000;
/// 默认揭示超时（毫秒）。
pub const DEFAULT_REVEAL_TIMEOUT_MS: u32 = 10_000;
/// 默认行动超时（毫秒）。
pub const DEFAULT_BETTING_TIMEOUT_MS: u32 = 30_000;
/// 默认重构超时（毫秒）。
pub const DEFAULT_RECONSTRUCT_TIMEOUT_MS: u32 = 10_000;
/// 默认摊牌展示时长（毫秒）。
pub const DEFAULT_SHOWDOWN_DISPLAY_MS: u32 = 3_000;
/// 默认一手结束后到下一手的等待时长（毫秒，Move 对齐；Rust 端暂无对应字段）。
pub const DEFAULT_HAND_COMPLETE_WAIT_MS: u64 = 5_000;
/// 默认开局前等待玩家就绪的时长（毫秒，Move 对齐；Rust 端暂无对应字段）。
pub const DEFAULT_READY_WAIT_MS: u64 = 5_000;

/// 边池总下注上限（防溢出）。
pub const MAX_TOTAL_BET: u64 = 1_000_000_000_000_000_000;

// ===== Ante 模式（start_hand 投盲注时使用）=====

/// 无 ante（默认）。
pub const ANTE_MODE_NONE: u8 = 0;
/// 普通 ante（每个玩家投 ante_amount）。
pub const ANTE_MODE_NORMAL: u8 = 1;
/// Big Blind Ante（BBA，仅大盲位投 ante_amount，简化投注）。
pub const ANTE_MODE_BBA: u8 = 2;

// ===== Time Bank（玩家思考时间银行）=====

/// 默认 Time Bank 初始额度（毫秒，30 秒）。
pub const DEFAULT_TIME_BANK_MS: u32 = 30_000;

/// Time Bank 每手补充额度（毫秒，每手开始时 +10 秒，最多到初始额度）。
pub const TIME_BANK_REFILL_PER_HAND_MS: u32 = 10_000;

// ===== Rake 模式（settle 时抽水）=====

/// 无 rake。
pub const RAKE_MODE_NONE: u8 = 0;
/// 按比例抽水（pot * rake_bps / 10000，受 rake_cap 上限）。
pub const RAKE_MODE_PERCENTAGE: u8 = 1;

/// 默认 rake 比例（500 = 5%）。
pub const DEFAULT_RAKE_BPS: u16 = 500;

/// 默认 rake 上限（按 BB 倍数，通常 1-3 BB；此处用绝对值）。
pub const DEFAULT_RAKE_CAP: u64 = 1_000;

// ===== Run It Twice 模式（all-in 后发两次）=====

/// 不发两次（默认）。
pub const RIT_MODE_DISABLED: u8 = 0;
/// Run It Twice（all-in 后发两次 turn+river，降低方差）。
pub const RIT_MODE_TWICE: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_state_constants() {
        assert_eq!(ROUND_WAITING, 0);
        assert_eq!(ROUND_PREFLOP, 2);
        assert_eq!(ROUND_FLOP, 3);
        assert_eq!(ROUND_TURN, 4);
        assert_eq!(ROUND_RIVER, 5);
        assert_eq!(ROUND_SHOWDOWN, 6);
    }

    #[test]
    fn test_shuffle_phase_constants() {
        assert_eq!(SHUFFLE_PHASE_NONE, 0);
        assert_eq!(SHUFFLE_PHASE_BEFORE_PREFLOP, 3);
    }

    #[test]
    fn test_player_limits() {
        assert_eq!(MIN_PLAYERS_TO_START, 2);
        assert_eq!(MAX_PLAYERS, 9);
        assert_eq!(CARDS_PER_PLAYER, 2);
    }
}
