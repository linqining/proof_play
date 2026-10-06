//! 当前 method AIR 的枚举与 selector 计算。
//!
//! 保留与 [`poker_l1::contracts::texas_poker::dispatch`] 一致的稳定 discriminant 空间，
//! 当前包含 19 个 active selector；5/10/15/16 已退休且不重排。
//!
//! # 分类
//!
//! - **A 档（生命周期，5 个）**：表台创建/入座/离座/开局/超时
//! - **B 档（玩家动作，8 个）**：8 个启用 AIR
//! - **B+ 档（资金动作，2 个）**：addon（下一手生效）/rebuy（立即生效）
//! - **C 档（密码学协议，4 个）**：4 个启用 AIR

use borsh::{BorshDeserialize, BorshSerialize};

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// 直接转发 [`poker_l1::contracts::texas_poker::runtime::dispatch::compute_method_selector`]，
/// 保证与 L1 dispatch 的 selector 空间单一来源。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    poker_l1::contracts::texas_poker::runtime::dispatch::compute_method_selector(method_name)
}

/// 当前方法种类的枚举。
///
/// 每个 variant 都对应 `poker_l1` 的公开 dispatch selector。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum MethodKind {
    // ===== A 档：表台生命周期（5 个）=====
    /// `create_table` — 创建新桌台。
    CreateTable = 0,
    /// `join_table` — 简单入座（不参与本局，等下一局）。
    JoinTable = 1,
    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    LeaveTable = 2,
    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    StartHand = 3,
    /// `advance_deadline` — 超时驱动（permissionless）。
    AdvanceDeadline = 4,
    // ===== B 档：玩家动作 =====
    /// `fold` — 玩家主动 fold。
    Fold = 6,
    /// `check` — 玩家过牌。
    Check = 7,
    /// `call` — 玩家跟注。
    Call = 8,
    /// `raise` — 玩家加注。
    Raise = 9,
    /// `force_fold` — 管理员强制 fold 玩家。
    ForceFold = 11,
    /// `kick_player_v2` — 踢出玩家（管理员操作，原因固定为 Admin）。
    KickPlayer = 12,

    // ===== B+ 档：资金动作（2 个）=====
    /// `addon` — 玩家追加筹码（下一手生效，不影响当前 pot）。
    Addon = 13,
    /// `rebuy` — 玩家重购（立即生效，MTT 早期用）。
    Rebuy = 14,

    // ===== C 档：Mental Poker 协议（4 个）=====
    /// `submit_shuffle_v2` — 玩家提交洗牌结果（V2）。
    SubmitShuffleV2 = 17,
    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    SubmitPlayerRevealTokens = 18,
    /// `submit_reconstruct_deck` — 提交重构牌组。
    SubmitReconstructDeck = 19,

    // ===== B 档扩展：bet 动作（1 个）=====
    /// `bet` — 玩家主动下注（postflop 第一个下注者，语义等同 raise 但更清晰）。
    Bet = 20,
    /// `set_leave_after_hand` — 显式设置下一手前离场标记。
    SetLeaveAfterHand = 21,
    /// `fold_with_proof` — 局中 fold 并剥离自己的加密层。
    FoldWithProof = 22,
    /// `redeal_hole_card` — 持有者换掉解密失败的底牌（死槽恢复，C 档语义：
    /// 改变 deck 发牌游标与手牌账本，必须进证明轨迹）。
    RedealHoleCard = 23,
}

impl MethodKind {
    /// 当前方法总数。
    pub const COUNT: usize = 20;

    /// Whether the repository ships an enabled production AIR for this selector.
    ///
    /// All 19 retained MethodKind variants currently have an enabled production AIR.
    #[must_use]
    pub const fn is_production_air_enabled(self) -> bool {
        true
    }

    /// 返回方法名字符串（snake_case，与 Move 端 entry function 名一一对应）。
    #[must_use]
    pub const fn method_name(self) -> &'static str {
        match self {
            Self::CreateTable => "create_table",
            Self::JoinTable => "join_table",
            Self::LeaveTable => "leave_table",
            Self::StartHand => "start_hand",
            Self::AdvanceDeadline => "advance_deadline",
            Self::Fold => "fold",
            Self::Check => "check",
            Self::Call => "call",
            Self::Raise => "raise",
            Self::ForceFold => "force_fold",
            Self::KickPlayer => "kick_player_v2",
            Self::Addon => "addon",
            Self::Rebuy => "rebuy",
            Self::SubmitShuffleV2 => "submit_shuffle_v2",
            Self::SubmitPlayerRevealTokens => "submit_player_reveal_tokens",
            Self::SubmitReconstructDeck => "submit_reconstruct_deck",
            Self::Bet => "bet",
            Self::SetLeaveAfterHand => "set_leave_after_hand",
            Self::FoldWithProof => "fold_with_proof",
            Self::RedealHoleCard => "redeal_hole_card",
        }
    }

    /// 返回方法选择器（blake2b_256(method_name)[0..32]）。
    #[must_use]
    pub fn selector(self) -> [u8; METHOD_SELECTOR_LEN] {
        compute_method_selector(self.method_name())
    }

    /// 返回方法所属档位。
    #[must_use]
    pub const fn tier(self) -> MethodTier {
        match self {
            Self::CreateTable
            | Self::JoinTable
            | Self::LeaveTable
            | Self::StartHand
            | Self::AdvanceDeadline => MethodTier::Lifecycle,
            Self::Fold
            | Self::Check
            | Self::Call
            | Self::Raise
            | Self::ForceFold
            | Self::KickPlayer
            | Self::Bet
            | Self::SetLeaveAfterHand => MethodTier::Action,
            Self::Addon | Self::Rebuy => MethodTier::Funds,
            Self::SubmitShuffleV2
            | Self::SubmitPlayerRevealTokens
            | Self::SubmitReconstructDeck
            | Self::FoldWithProof
            | Self::RedealHoleCard => MethodTier::Crypto,
        }
    }

    /// 从 u8 还原 MethodKind。
    ///
    /// # Errors
    ///
    /// 未注册或已退休的 discriminant 返回 `None`。
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::CreateTable),
            1 => Some(Self::JoinTable),
            2 => Some(Self::LeaveTable),
            3 => Some(Self::StartHand),
            4 => Some(Self::AdvanceDeadline),
            5 => None,
            6 => Some(Self::Fold),
            7 => Some(Self::Check),
            8 => Some(Self::Call),
            9 => Some(Self::Raise),
            10 => None,
            11 => Some(Self::ForceFold),
            12 => Some(Self::KickPlayer),
            13 => Some(Self::Addon),
            14 => Some(Self::Rebuy),
            15 | 16 => None,
            17 => Some(Self::SubmitShuffleV2),
            18 => Some(Self::SubmitPlayerRevealTokens),
            19 => Some(Self::SubmitReconstructDeck),
            20 => Some(Self::Bet),
            21 => Some(Self::SetLeaveAfterHand),
            22 => Some(Self::FoldWithProof),
            23 => Some(Self::RedealHoleCard),
            _ => None,
        }
    }

    /// 返回所有当前方法（用于迭代）。
    #[must_use]
    pub const fn all() -> [Self; Self::COUNT] {
        [
            Self::CreateTable,
            Self::JoinTable,
            Self::LeaveTable,
            Self::StartHand,
            Self::AdvanceDeadline,
            Self::Fold,
            Self::Check,
            Self::Call,
            Self::Raise,
            Self::ForceFold,
            Self::KickPlayer,
            Self::Addon,
            Self::Rebuy,
            Self::SubmitShuffleV2,
            Self::SubmitPlayerRevealTokens,
            Self::SubmitReconstructDeck,
            Self::Bet,
            Self::SetLeaveAfterHand,
            Self::FoldWithProof,
            Self::RedealHoleCard,
        ]
    }
}

/// 方法所属档位（用于实施阶段控制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodTier {
    /// A 档：表台生命周期（5 个，阶段 1-2 实现）。
    Lifecycle,
    /// B 档：玩家动作（8 个，全部启用 AIR）。
    Action,
    /// B+ 档：资金动作（2 个：addon/rebuy）。
    Funds,
    /// C 档：Mental Poker 协议（4 个，全部启用 AIR）。
    Crypto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_count() {
        assert_eq!(MethodKind::COUNT, 20);
        assert_eq!(MethodKind::all().len(), 20);
    }

    #[test]
    fn test_method_name_roundtrip() {
        for kind in MethodKind::all() {
            let name = kind.method_name();
            let selector = kind.selector();
            // selector 长度 = 32
            assert_eq!(selector.len(), METHOD_SELECTOR_LEN);
            // 不同方法的 selector 应不同
            for other in MethodKind::all() {
                if other != kind {
                    assert_ne!(selector, other.selector(), "selector 碰撞: {name}");
                }
            }
        }
    }

    #[test]
    fn test_from_u8_roundtrip() {
        for kind in MethodKind::all() {
            let v = kind as u8;
            assert_eq!(MethodKind::from_u8(v), Some(kind));
        }
        assert_eq!(MethodKind::from_u8(21), Some(MethodKind::SetLeaveAfterHand));
        assert_eq!(MethodKind::from_u8(22), Some(MethodKind::FoldWithProof));
        for retired in [5, 10, 15, 16] {
            assert_eq!(MethodKind::from_u8(retired), None);
        }
        assert_eq!(MethodKind::from_u8(23), Some(MethodKind::RedealHoleCard));
        assert_eq!(MethodKind::from_u8(24), None);
        assert_eq!(MethodKind::from_u8(255), None);
    }

    #[test]
    fn test_tier_classification() {
        assert_eq!(MethodKind::CreateTable.tier(), MethodTier::Lifecycle);
        assert_eq!(MethodKind::Raise.tier(), MethodTier::Action);
        assert_eq!(MethodKind::SubmitShuffleV2.tier(), MethodTier::Crypto);
        assert!(MethodKind::Bet.is_production_air_enabled());
        assert!(MethodKind::SetLeaveAfterHand.is_production_air_enabled());
        assert!(MethodKind::FoldWithProof.is_production_air_enabled());
    }

    #[test]
    fn test_selector_matches_l1_dispatch() {
        // 非循环自证：期望值是 blake2b-256("create_table")[0..32] 的硬编码摘要，
        // 断言转发到 poker_l1 dispatch 后 selector 空间仍未漂移。
        let expected = [
            0xac, 0x94, 0xb9, 0x7b, 0x9e, 0xcd, 0x10, 0xd3, 0x7c, 0x4c, 0x5d, 0xb0, 0xfb, 0xb8,
            0x9d, 0x9a, 0xf5, 0xcd, 0xb4, 0xed, 0x25, 0x42, 0x34, 0xe3, 0x1b, 0x1a, 0x8e, 0xda,
            0xf5, 0xec, 0x84, 0x75,
        ];
        assert_eq!(MethodKind::CreateTable.selector(), expected);
        // 全部 19 个 kind：selector 必须与 poker_l1 dispatch 函数逐字节一致。
        for kind in MethodKind::all() {
            assert_eq!(
                kind.selector(),
                poker_l1::contracts::texas_poker::runtime::dispatch::compute_method_selector(
                    kind.method_name()
                ),
                "selector 漂移: {}",
                kind.method_name()
            );
        }
    }
}
