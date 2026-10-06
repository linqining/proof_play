//! 证明任务共享类型 — poker_l1 与 poker_texas_air 的数据契约边界。
//!
//! ## 角色
//!
//! 本模块只定义 [`MethodInput`]——一个不依赖任何业务类型（TexasPokerTable 等）
//! 的纯枚举，作为 `poker_l1`（合约层，产出证明任务）与 `poker_texas_air`
//! （Orchestrator，消费证明任务）之间的 borsh 二进制兼容契约。
//!
//! ## 为何放 vm-common
//!
//! - `poker_l1` 不能依赖 `poker_texas_air`（依赖方向是 air → l1）
//! - `MethodInput` 两边都需要（poker_l1 填充，poker_texas_air 消费），且必须
//!   borsh 布局完全一致，故下沉到共享层
//! - `vm-common` 已被两端依赖，且不依赖任何业务类型，是天然的共享层
//!
//! ## borsh 兼容性
//!
//! `poker_l1` 的 `ProveTask` 与 `poker_texas_air` 的 `ProveTask` 是同名镜像
//! 定义，字段类型对齐（TexasPokerTable / TexasPokerEvent 都是 poker_l1 类型，两端可见同一类型）；
//! `method_kind` 在 poker_l1 用 `u8`，在 poker_texas_air 用 `MethodKind`
//! （`#[borsh(use_discriminant=true)]` + `#[repr(u8)]`），borsh 单字节布局一致。

use borsh::{BorshDeserialize, BorshSerialize};

/// 方法业务输入的枚举封装（与具体业务类型解耦）。
///
/// 每个 variant 对应一组方法参数。borsh 布局在 poker_l1 与 poker_texas_air
/// 两侧完全一致，是 return_value 字节流的核心契约。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub enum MethodInput {
    /// 仅含 seat_index 的非密码学方法（fold/check/call/force_fold/
    /// leave_table）。
    SeatOnly {
        /// 座位索引。
        seat_index: u8,
    },
    /// `raise`（seat_index + total_bet）。
    Raise {
        /// 座位索引。
        seat_index: u8,
        /// 加注后本轮总下注额。
        total_bet: u64,
    },
    /// `bet`（seat_index + amount 增量）。
    Bet {
        /// 座位索引。
        seat_index: u8,
        /// 下注增量。
        amount: u64,
    },
    /// `addon` / `rebuy`（seat_index + amount）。
    Funds {
        /// 座位索引。
        seat_index: u8,
        /// 金额。
        amount: u64,
    },
    /// Canonical administrator `kick_player` target.
    Kick {
        /// 座位索引。
        seat_index: u8,
    },
    /// `join_table`（player + buy_in）。
    Join {
        /// 玩家地址。
        player: [u8; 20],
        /// 买入金额。
        buy_in: u64,
    },
    /// `create_table`（max_players + small_blind + big_blind + rit_mode）。
    ///
    /// v34 起不携带 `name`：展示名非共识，不进 prove task。
    CreateTable {
        /// 最大玩家数。
        max_players: u8,
        /// 小盲注。
        small_blind: u64,
        /// 大盲注。
        big_blind: u64,
        /// Run It Twice 桌面策略（poker_l1 `RIT_MODE_*` 常量；缺省 DISABLED）。
        rit_mode: u8,
    },
    /// `submit_shuffle_v2` 的窄派生输入。
    SubmitShuffleV2 {
        /// 提交洗牌的座位索引。
        seat_index: u8,
    },
    /// `submit_player_reveal_tokens` 的窄派生输入。
    SubmitPlayerRevealTokens {
        /// 提交 reveal token 的座位索引。
        seat_index: u8,
    },
    /// `submit_reconstruct_deck` 的窄派生输入。
    SubmitReconstructDeck {
        /// 提交重构牌组的座位索引。
        seat_index: u8,
    },
    /// `set_leave_after_hand`（显式设置下一手前离场标记）。
    SetLeaveAfterHand {
        /// 玩家座位索引。
        seat_index: u8,
        /// 是否在本手结束后离场。
        want_leave: bool,
    },
    /// `fold_with_proof` 的窄派生输入。
    FoldWithProof {
        /// fold 玩家座位索引。
        seat_index: u8,
    },
    /// `redeal_hole_card` 的窄派生输入（持有者换掉解密失败的底牌）。
    RedealHoleCard {
        /// 持有者座位索引。
        seat_index: u8,
        /// 被换的底牌槽位（0/1）。
        card_slot: u8,
    },
    /// 无业务参数的方法（start_hand / advance_deadline）。
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_input_borsh_roundtrip() {
        let inputs = vec![
            MethodInput::SeatOnly { seat_index: 3 },
            MethodInput::Raise {
                seat_index: 1,
                total_bet: 500,
            },
            MethodInput::Bet {
                seat_index: 2,
                amount: 100,
            },
            MethodInput::Funds {
                seat_index: 0,
                amount: 1000,
            },
            MethodInput::Kick { seat_index: 4 },
            MethodInput::Join {
                player: [0xAB; 20],
                buy_in: 2000,
            },
            MethodInput::CreateTable {
                max_players: 6,
                small_blind: 50,
                big_blind: 100,
                rit_mode: 1,
            },
            MethodInput::SubmitShuffleV2 { seat_index: 2 },
            MethodInput::SubmitPlayerRevealTokens { seat_index: 3 },
            MethodInput::SubmitReconstructDeck { seat_index: 4 },
            MethodInput::SetLeaveAfterHand {
                seat_index: 5,
                want_leave: true,
            },
            MethodInput::FoldWithProof { seat_index: 0 },
            MethodInput::Empty,
        ];
        for input in &inputs {
            let bytes = borsh::to_vec(input).unwrap();
            let recovered: MethodInput = borsh::from_slice(&bytes).unwrap();
            assert_eq!(input, &recovered, "roundtrip 失败: {input:?}");
        }
    }
}
