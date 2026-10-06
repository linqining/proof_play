//! Texas Poker 合约 active dispatch 路由。
//!
//! 严格对齐 `texas_poker_move/sources/table.move` 的 public entry function 清单：
//! - 表台生命周期：create_table / join_table / leave_table / start_hand / advance_deadline
//! - 玩家动作：fold / check / call / raise / bet / force_fold / kick_player_v2
//! - 离场预约：set_leave_after_hand（显式幂等设置，任意时刻可调用）
//! - Mental Poker 协议：fold_with_proof / submit_shuffle_v2 /
//!   submit_player_reveal_tokens / submit_reconstruct_deck
//!
//! # Selector 计算
//!
//! `blake2b_256(method_name)[0..32]`，与 `contracts/dispatch.rs` 保持一致。
//!
//! # Args 编码
//!
//! 每个 method 对应一个 `*Args` 结构体，使用 **borsh** 序列化（B.4 迁移后）。
//! 密码学字段（pk/ciphertexts/proofs）为 typed `poker_protocol` 类型，
//! 消除 dispatch 子函数中手动 `ser::deserialize_*` 调用。
//!
//! # Events 处理
//!
//! state_machine 函数通过 `events: &mut Vec<TexasPokerEvent>` 收集事件；
//! dispatch 层把它们 borsh 进 `DispatchResult.return_value`
//! （`build_dispatch_output`），由 host 侧（`TableRuntime::collect_into`）
//! 解码消费——事件不落日志即丢弃，出栈即结构化。

use super::utils::{BlsScalar, G1Projective};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ElGamalCiphertext};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind};
use poker_protocol::zk_shuffle::reconstruction::{ReconstructProof, ReconstructionStatement};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;

use super::constants::{FOLD_REASON_FORCE_ADMIN, KICK_REASON_ADMIN};
use super::events::TexasPokerEvent;
use super::state_machine;
#[cfg(test)]
use super::types::SeatStatus;
use super::types::TexasPokerTable;
use crate::Address;
use crate::ChainId;
use crate::contracts::dispatch::{DispatchContext, DispatchResult};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// 与 `contracts::dispatch::compute_method_selector` 算法一致，
/// 但独立定义以避免循环依赖（texas_poker 不应被父 dispatch 模块引用）。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    let mut h = Blake2bVar::new(METHOD_SELECTOR_LEN).expect("32 <= 64");
    h.update(method_name.as_bytes());
    let mut out = [0u8; METHOD_SELECTOR_LEN];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// Selector hash helpers for active consensus calls.
///
/// 所有方法名使用 snake_case，与 Move 端 entry function 名一一对应。
pub mod selectors {
    use super::compute_method_selector;

    /// `create_table` — 创建新桌台。
    pub fn create_table() -> [u8; 32] {
        compute_method_selector("create_table")
    }

    /// `join_table` — 简单入座（不参与本局，等下一局）。
    pub fn join_table() -> [u8; 32] {
        compute_method_selector("join_table")
    }

    /// `leave_table` — 简单离座（仅在 WAITING 状态）。
    pub fn leave_table() -> [u8; 32] {
        compute_method_selector("leave_table")
    }

    /// `start_hand` — 开始新一局（投盲注 + 进入 shuffle 阶段）。
    pub fn start_hand() -> [u8; 32] {
        compute_method_selector("start_hand")
    }

    /// `advance_deadline` — canonical permissionless timeout entry.
    pub fn advance_deadline() -> [u8; 32] {
        compute_method_selector("advance_deadline")
    }

    /// `force_fold` — 管理员强制 fold 玩家。
    pub fn force_fold() -> [u8; 32] {
        compute_method_selector("force_fold")
    }

    /// `kick_player_v2` — canonical administrator removal with an implicit `Admin` cause.
    ///
    /// The historical selector allowed the caller to choose timeout/reconstruct event causes.
    /// Current consensus calls carry only the target seat and always use the `Admin` cause.
    pub fn kick_player_v2() -> [u8; 32] {
        compute_method_selector("kick_player_v2")
    }

    /// `submit_shuffle_v2` — 玩家提交洗牌结果（第二手及以后）。
    pub fn submit_shuffle_v2() -> [u8; 32] {
        compute_method_selector("submit_shuffle_v2")
    }

    /// `submit_player_reveal_tokens` — 提交揭牌令牌。
    pub fn submit_player_reveal_tokens() -> [u8; 32] {
        compute_method_selector("submit_player_reveal_tokens")
    }

    /// `submit_reconstruct_deck` — 提交重构牌组。
    pub fn submit_reconstruct_deck() -> [u8; 32] {
        compute_method_selector("submit_reconstruct_deck")
    }

    /// `redeal_hole_card` — 持有者换掉解密失败的底牌（死槽恢复）。
    ///
    /// 仅牌主可调用；仅在下注轮可用。将 deck 游标位（`cards_dealt`）的新牌
    /// 换入指定槽位并挂起下注轮、开启 `REVEAL_PHASE_REDEAL` 令牌窗口。
    pub fn redeal_hole_card() -> [u8; 32] {
        compute_method_selector("redeal_hole_card")
    }

    /// `fold` — 玩家主动 fold。
    pub fn fold() -> [u8; 32] {
        compute_method_selector("fold")
    }

    /// `check` — 玩家过牌。
    pub fn check() -> [u8; 32] {
        compute_method_selector("check")
    }

    /// `call` — 玩家跟注。
    pub fn call() -> [u8; 32] {
        compute_method_selector("call")
    }

    /// `raise` — 玩家加注。
    pub fn raise() -> [u8; 32] {
        compute_method_selector("raise")
    }

    /// `bet` — 玩家主动下注（postflop 第一个下注者，语义等同于 raise 但更清晰）。
    pub fn bet() -> [u8; 32] {
        compute_method_selector("bet")
    }

    /// `addon` — 玩家追加筹码（下一手生效）。
    pub fn addon() -> [u8; 32] {
        compute_method_selector("addon")
    }

    /// `rebuy` — 玩家重购（立即生效，MTT 早期用）。
    pub fn rebuy() -> [u8; 32] {
        compute_method_selector("rebuy")
    }

    /// `set_leave_after_hand` — 显式设置玩家是否在本手结束后离场。
    ///
    /// 在线扑克 "sit out next hand / stand up next hand" 模式：玩家可在任意
    /// round_state 调用设置 `seat.want_leave` 标志，下一手 `reset_for_next_hand`
    /// 时强制踢出并退款。解决 `leave_table` 仅 WAITING 可用、creator/自动推进可能
    /// 立即 start_hand 导致玩家来不及离场的问题。
    ///
    /// 该方法使用独立 MethodKind discriminant 21 产生 ProveTask；重复设置同一值是
    /// canonical no-op，不产生事件、call_seq 或 proof task。
    pub fn set_leave_after_hand() -> [u8; 32] {
        compute_method_selector("set_leave_after_hand")
    }

    /// `fold_with_proof` — 玩家 fold 并提交 fold proof（剥离加密层 + 退出后续 reveal）。
    ///
    /// 在下注轮调用，玩家 fold 时通过
    /// DLEqProof（LeaveKind）剥离自己的加密层（remove pk from aggregated_pk +
    /// remask deck），并从所有 reveal pending 列表中移除——后续解牌不需要该玩家
    /// 参加。区别于普通 fold：普通 fold 玩家仍需为后续公共牌提交 reveal token
    /// （或被超时踢出）；fold_with_proof 让玩家立即从协议中「物理退出」。
    ///
    /// 该方法使用稳定的独立 MethodKind discriminant 22 产生 ProveTask，并保留
    /// 完整原始 proof 参数，供证明消费侧重验复合状态转换。
    pub fn fold_with_proof() -> [u8; 32] {
        compute_method_selector("fold_with_proof")
    }

    /// Return every selector accepted by the current consensus source surface.
    #[must_use]
    pub fn all() -> Vec<[u8; 32]> {
        vec![
            create_table(),
            join_table(),
            leave_table(),
            start_hand(),
            advance_deadline(),
            force_fold(),
            kick_player_v2(),
            submit_shuffle_v2(),
            submit_player_reveal_tokens(),
            submit_reconstruct_deck(),
            redeal_hole_card(),
            fold(),
            check(),
            call(),
            raise(),
            bet(),
            addon(),
            rebuy(),
            set_leave_after_hand(),
            fold_with_proof(),
        ]
    }
}

/// Stable canonical command tag shared by source dispatch and heterogeneous method batches.
///
/// Legacy selectors are only wire-level aliases. Once decoded, all routing and proof metadata
/// use this enum so selector order or spelling cannot silently change the method discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum CanonicalCommand {
    CreateTable = 0,
    JoinTable = 1,
    LeaveTable = 2,
    StartHand = 3,
    AdvanceDeadline = 4,
    Fold = 6,
    Check = 7,
    Call = 8,
    Raise = 9,
    ForceFold = 11,
    KickPlayer = 12,
    Addon = 13,
    Rebuy = 14,
    SubmitShuffleV2 = 17,
    SubmitPlayerRevealTokens = 18,
    SubmitReconstructDeck = 19,
    Bet = 20,
    SetLeaveAfterHand = 21,
    FoldWithProof = 22,
    RedealHoleCard = 23,
}

/// Narrow top-level tag used by heterogeneous method batches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CanonicalCommandFamily {
    /// Table creation and immutable initialization.
    Create = 0,
    /// Seat membership and leave-policy changes.
    Seat = 1,
    /// Checked chip custody updates.
    Funds = 2,
    /// Ordinary betting actions.
    Action = 3,
    /// Mental Poker proof-bearing operations.
    Crypto = 4,
    /// Hand start and permissionless deadline consumption.
    Lifecycle = 5,
}

/// Two-level method-batch discriminator. Wire selectors never enter the proof row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalBatchTag {
    /// Broad command family selecting the tagged method constraints.
    pub family: CanonicalCommandFamily,
    /// Family-local canonical operation tag.
    pub subtag: u8,
}

impl CanonicalCommand {
    /// Stable human-readable command name used by canonical payload diagnostics.
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
            Self::KickPlayer => "kick_player",
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

    /// Recover a stable command tag from its persisted discriminant.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::CreateTable,
            1 => Self::JoinTable,
            2 => Self::LeaveTable,
            3 => Self::StartHand,
            4 => Self::AdvanceDeadline,
            5 => return None,
            6 => Self::Fold,
            7 => Self::Check,
            8 => Self::Call,
            9 => Self::Raise,
            10 => return None,
            11 => Self::ForceFold,
            12 => Self::KickPlayer,
            13 => Self::Addon,
            14 => Self::Rebuy,
            15 | 16 => return None,
            17 => Self::SubmitShuffleV2,
            18 => Self::SubmitPlayerRevealTokens,
            19 => Self::SubmitReconstructDeck,
            20 => Self::Bet,
            21 => Self::SetLeaveAfterHand,
            22 => Self::FoldWithProof,
            23 => Self::RedealHoleCard,
            _ => return None,
        })
    }

    /// Canonical replay selector deterministically derived from the command tag.
    #[must_use]
    pub fn selector(self) -> [u8; 32] {
        match self {
            Self::CreateTable => selectors::create_table(),
            Self::JoinTable => selectors::join_table(),
            Self::LeaveTable => selectors::leave_table(),
            Self::StartHand => selectors::start_hand(),
            Self::AdvanceDeadline => selectors::advance_deadline(),
            Self::Fold => selectors::fold(),
            Self::Check => selectors::check(),
            Self::Call => selectors::call(),
            Self::Raise => selectors::raise(),
            Self::ForceFold => selectors::force_fold(),
            Self::KickPlayer => selectors::kick_player_v2(),
            Self::Addon => selectors::addon(),
            Self::Rebuy => selectors::rebuy(),
            Self::SubmitShuffleV2 => selectors::submit_shuffle_v2(),
            Self::SubmitPlayerRevealTokens => selectors::submit_player_reveal_tokens(),
            Self::SubmitReconstructDeck => selectors::submit_reconstruct_deck(),
            Self::Bet => selectors::bet(),
            Self::SetLeaveAfterHand => selectors::set_leave_after_hand(),
            Self::FoldWithProof => selectors::fold_with_proof(),
            Self::RedealHoleCard => selectors::redeal_hole_card(),
        }
    }

    /// Decode a legacy method selector into its stable command tag.
    #[must_use]
    pub fn from_selector(selector: &[u8; 32]) -> Option<Self> {
        Some(if selector == &selectors::create_table() {
            Self::CreateTable
        } else if selector == &selectors::join_table() {
            Self::JoinTable
        } else if selector == &selectors::leave_table() {
            Self::LeaveTable
        } else if selector == &selectors::start_hand() {
            Self::StartHand
        } else if selector == &selectors::advance_deadline() {
            Self::AdvanceDeadline
        } else if selector == &selectors::fold() {
            Self::Fold
        } else if selector == &selectors::check() {
            Self::Check
        } else if selector == &selectors::call() {
            Self::Call
        } else if selector == &selectors::raise() {
            Self::Raise
        } else if selector == &selectors::force_fold() {
            Self::ForceFold
        } else if selector == &selectors::kick_player_v2() {
            Self::KickPlayer
        } else if selector == &selectors::addon() {
            Self::Addon
        } else if selector == &selectors::rebuy() {
            Self::Rebuy
        } else if selector == &selectors::submit_shuffle_v2() {
            Self::SubmitShuffleV2
        } else if selector == &selectors::submit_player_reveal_tokens() {
            Self::SubmitPlayerRevealTokens
        } else if selector == &selectors::submit_reconstruct_deck() {
            Self::SubmitReconstructDeck
        } else if selector == &selectors::bet() {
            Self::Bet
        } else if selector == &selectors::set_leave_after_hand() {
            Self::SetLeaveAfterHand
        } else if selector == &selectors::fold_with_proof() {
            Self::FoldWithProof
        } else if selector == &selectors::redeal_hole_card() {
            Self::RedealHoleCard
        } else {
            return None;
        })
    }

    /// Decode a selector admitted by the current proof/archive trust boundary.
    ///
    /// Historical production data is intentionally unsupported, so retired selectors fail closed
    /// here exactly as they do at the fresh precompile boundary.
    #[must_use]
    pub fn from_archive_selector(selector: &[u8; 32]) -> Option<Self> {
        Self::from_selector(selector)
    }

    /// Stable method-batch tag.
    #[must_use]
    pub const fn method_tag(self) -> u8 {
        self as u8
    }

    /// Collapse compatibility selectors onto the narrow command family/subtag used by batching.
    #[must_use]
    pub const fn batch_tag(self) -> CanonicalBatchTag {
        use CanonicalCommandFamily::{Action, Create, Crypto, Funds, Lifecycle, Seat};
        let (family, subtag) = match self {
            Self::CreateTable => (Create, 0),
            Self::JoinTable => (Seat, 0),
            Self::LeaveTable => (Seat, 1),
            Self::SetLeaveAfterHand => (Seat, 2),
            Self::KickPlayer => (Seat, 3),
            Self::Addon => (Funds, 0),
            Self::Rebuy => (Funds, 1),
            Self::Fold | Self::ForceFold => (Action, 0),
            Self::Check | Self::Call => (Action, 1),
            Self::Raise | Self::Bet => (Action, 2),
            Self::SubmitShuffleV2 => (Crypto, 2),
            Self::SubmitPlayerRevealTokens => (Crypto, 3),
            Self::SubmitReconstructDeck => (Crypto, 4),
            Self::FoldWithProof => (Crypto, 5),
            Self::RedealHoleCard => (Crypto, 6),
            Self::StartHand => (Lifecycle, 0),
            Self::AdvanceDeadline => (Lifecycle, 1),
        };
        CanonicalBatchTag { family, subtag }
    }
}

// ========== Args 结构体（borsh 序列化 + typed 密码学字段） ==========

/// `create_table` 参数。
///
/// v34 起不再携带 `name`：展示名非共识，由非共识 metadata 对象承载。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct CreateTableArgs {
    /// 最大玩家数（2..=9）。
    pub max_players: u8,
    /// 小盲注金额。
    pub small_blind: u64,
    /// 大盲注金额。
    pub big_blind: u64,
    /// Run It Twice 桌面策略（`RIT_MODE_DISABLED` / `RIT_MODE_TWICE`）。
    ///
    /// 严格 4 字段编码：载荷必须精确携带本字段，旧编码与尾随
    /// 垃圾字节一律反序列化失败（fail-closed）；缺省语义即不开启
    /// （`RIT_MODE_DISABLED`），非协议值由 core::apply_create_table 拒绝。
    pub rit_mode: u8,
}

/// `fold_with_proof` 参数（局中 fold + 剥离加密层）。
///
/// 在下注轮调用，完成局中弃牌 + 退出后续 reveal 协议。proof 使用 `LeaveKind`。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct FoldWithProofArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// fold 时的牌组输出（typed ElGamalCiphertext 列表，剥离玩家加密层后的新牌组）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// fold proof（typed DLEqProof<LeaveKind>，与 leave proof 同型）。
    pub fold_proof: DLEqProof<DefaultCurve, LeaveKind>,
}

/// `join_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct JoinTableArgs {
    /// 玩家地址。
    pub player: Address,
    /// 买入金额。
    pub buy_in: u64,
    /// 玩家 ElGamal 公钥（G1 点，使用 ECPoint newtype 以支持 Borsh）。
    pub pk: ECPoint,
    /// 会话交易公钥（P1-2 会话委托）：Stark Schnorr 32B 压缩点（tagged）。
    /// 与链上 vault 登记（`set_session_tx_pk[_for]`）的一致性由游戏服务端
    /// 在 join 接受点核验；入座后成为本座 VM 层交易签名的验证锚。
    pub tx_pk: crate::signature::TaggedPubkey,
    /// 80-byte Schnorr proof that the caller knows the scalar behind `pk`.
    pub pk_ownership_proof: Vec<u8>,
}

impl JoinTableArgs {
    /// Build canonical join args from a Mental-Poker secret key and fresh Schnorr nonce.
    pub fn with_key(
        player: Address,
        buy_in: u64,
        secret_key: BlsScalar,
        nonce: BlsScalar,
    ) -> PokerL1Result<Self> {
        let pk = super::utils::g1_generator() * secret_key;
        Ok(Self {
            player,
            buy_in,
            pk: ECPoint(pk),
            tx_pk: crate::signature::TaggedPubkey {
                tag: crate::signature::encode_tag(
                    crate::signature::SignatureScheme::Stark,
                    crate::signature::CURRENT_VERSION,
                ),
                raw: vec![0u8; 32],
            },
            pk_ownership_proof: super::utils::create_pk_ownership_proof(&secret_key, &nonce)?,
        })
    }

    /// 显式携带会话交易公钥（生产 join 路径——`with_key` 的 tx_pk 是未登记
    /// 哨兵，真实 join 必须由服务端核验后填充本方法设置的真钥）。
    #[must_use]
    pub fn with_tx_pk(mut self, tx_pk: crate::signature::TaggedPubkey) -> Self {
        self.tx_pk = tx_pk;
        self
    }
}

/// `leave_table` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct LeaveTableArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `auto_fold` / `force_fold` / `fold` / `check` / `call` 参数（仅 seat_index）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SeatIndexArgs {
    /// 座位索引。
    pub seat_index: u8,
}

/// `set_leave_after_hand` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SetLeaveAfterHandArgs {
    /// 座位索引；dispatch 会将其绑定到 authenticated caller。
    pub seat_index: u8,
    /// 是否在当前手结束后的 reset 边界离场。
    pub want_leave: bool,
}

/// `submit_shuffle_v2` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitShuffleV2Args {
    /// 座位索引。
    pub seat_index: u8,
    /// shuffle 输出牌组（typed ElGamalCiphertext 列表）。
    pub output_cards: Vec<ElGamalCiphertext>,
    /// Versioned shuffle proof；生产验证仅接受 Bayer--Groth V2。
    pub shuffle_proof: ShuffleProof,
}

/// `submit_player_reveal_tokens` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitRevealTokensArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 揭牌令牌列表（typed ECPoint，Borsh 兼容的 G1 点包装）。令牌按认证前态中该
    /// seat 的全部 pending assignment 的 canonical 顺序排列；调用方不再重复提交索引。
    pub reveal_tokens: Vec<ECPoint>,
    /// 揭牌 proof 列表（typed RevealTokenProof，与 reveal_tokens 一一对应）。
    pub proofs: Vec<RevealTokenProof<DefaultCurve>>,
}

/// `redeal_hole_card` 参数（持有者换掉解密失败的底牌）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RedealHoleCardArgs {
    /// 持有者座位索引（dispatch 校验 caller 即该座玩家）。
    pub seat_index: u8,
    /// 被换的底牌槽位（0/1）。
    pub card_slot: u8,
}

/// `submit_reconstruct_deck` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct SubmitReconstructDeckArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// Complete V3 public statement. The hidden readable-to-canonical mapping
    /// is not serialized in this value.
    pub statement: ReconstructionStatement<DefaultCurve>,
    /// Reconstruction V3 proof for the exact statement above.
    pub proof: ReconstructProof<DefaultCurve>,
}

/// `raise` 参数。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RaiseArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 加注后该玩家本轮总下注额（不是加注增量）。
    pub total_bet: u64,
}

/// `bet` 参数（postflop 主动下注，amount 是下注增量，不是总下注）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BetArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 下注金额（增量，必须 > 0）。
    pub amount: u64,
}

/// `addon` 参数（追加筹码，下一手生效）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct AddonArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 追加金额（必须 > 0）。
    pub amount: u64,
}

/// `rebuy` 参数（重购，立即生效）。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RebuyArgs {
    /// 座位索引。
    pub seat_index: u8,
    /// 重购金额（必须 > 0）。
    pub amount: u64,
}

/// Canonical proof-task payload for `join_table`.
///
/// The authenticated caller is the only possible player, so the legacy `player` field is not
/// persisted a second time. Public-key ownership material remains part of the command because it
/// is independently verified and cannot be derived from state.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalJoinTableArgs {
    buy_in: u64,
    pk: ECPoint,
    tx_pk: crate::signature::TaggedPubkey,
    pk_ownership_proof: Vec<u8>,
}

/// Canonical actor-less payload for `set_leave_after_hand`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalSetLeaveAfterHandArgs {
    want_leave: bool,
}

/// Canonical actor-less payload for `fold_with_proof`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalFoldWithProofArgs {
    output_cards: Vec<ElGamalCiphertext>,
    fold_proof: DLEqProof<DefaultCurve, LeaveKind>,
}

/// Canonical actor-less payload for `submit_shuffle_v2`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalSubmitShuffleV2Args {
    output_cards: Vec<ElGamalCiphertext>,
    shuffle_proof: ShuffleProof,
}

/// Canonical actor-less payload for `submit_player_reveal_tokens`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalSubmitRevealTokensArgs {
    reveal_tokens: Vec<ECPoint>,
    proofs: Vec<RevealTokenProof<DefaultCurve>>,
}

/// Canonical actor-less payload for `submit_reconstruct_deck`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalSubmitReconstructDeckArgs {
    statement: ReconstructionStatement<DefaultCurve>,
    proof: ReconstructProof<DefaultCurve>,
}

/// Canonical actor-less payload for `redeal_hole_card`：持有者由认证 caller 派生，
/// 载荷只保留被换的槽位。
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalRedealHoleCardArgs {
    card_slot: u8,
}

/// Canonical actor-less payload for `raise`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalRaiseArgs {
    total_bet: u64,
}

/// Canonical actor-less payload shared by `bet`, `addon`, and `rebuy`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct CanonicalAmountArgs {
    amount: u64,
}

// ========== Dispatch 路由入口 ==========

/// Dispatch 路由入口。
///
/// 将 ContractCall 路由到对应的 Texas Poker 合约方法。
///
/// 参数：
/// - `context`：执行上下文（调用者、block 信息等）
/// - `table`：可变的 `TexasPokerTable` 引用（状态变更目标）
/// - `selector`：方法选择器（32 字节）
/// - `args`：调用参数（BCS 编码）
///
/// 返回：`DispatchResult` 包含状态变更信息。
///
/// 失败时返回 `PokerL1Error::UnknownContractMethod`（未知方法）或各业务方法的具体错误。
pub fn dispatch(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    // Post-commit Prover：执行前捕获 pre_table 快照（用于构造证明任务）。
    // clone 成本可接受（TexasPokerTable ~KB 级，且 prove_task 是异步消费的离线数据）。
    let pre_table = table.clone();
    let mut events: Vec<TexasPokerEvent> = Vec::new();
    let command =
        CanonicalCommand::from_selector(selector).ok_or(PokerL1Error::UnknownContractMethod {
            selector: *selector,
        })?;
    let result = match command {
        CanonicalCommand::CreateTable => dispatch_create_table(context, table, args, &mut events),
        CanonicalCommand::JoinTable => dispatch_join_table(context, table, args, &mut events),
        CanonicalCommand::LeaveTable => dispatch_leave_table(context, table, args, &mut events),
        CanonicalCommand::StartHand => dispatch_start_hand(context, table, args, &mut events),
        CanonicalCommand::AdvanceDeadline => {
            dispatch_advance_deadline(context, table, args, &mut events)
        }
        CanonicalCommand::ForceFold => dispatch_force_fold(context, table, args, &mut events),
        CanonicalCommand::KickPlayer => dispatch_kick_player(context, table, args, &mut events),
        CanonicalCommand::SubmitShuffleV2 => {
            dispatch_submit_shuffle_v2(context, table, args, &mut events)
        }
        CanonicalCommand::SubmitPlayerRevealTokens => {
            dispatch_submit_player_reveal_tokens(context, table, args, &mut events)
        }
        CanonicalCommand::SubmitReconstructDeck => {
            dispatch_submit_reconstruct_deck(context, table, args, &mut events)
        }
        CanonicalCommand::RedealHoleCard => {
            dispatch_redeal_hole_card(context, table, args, &mut events)
        }
        CanonicalCommand::Fold => dispatch_fold(context, table, args, &mut events),
        CanonicalCommand::Check => dispatch_check(context, table, args, &mut events),
        CanonicalCommand::Call => dispatch_call(context, table, args, &mut events),
        CanonicalCommand::Raise => dispatch_raise(context, table, args, &mut events),
        CanonicalCommand::Bet => dispatch_bet(context, table, args, &mut events),
        CanonicalCommand::Addon => dispatch_addon(context, table, args, &mut events),
        CanonicalCommand::Rebuy => dispatch_rebuy(context, table, args, &mut events),
        CanonicalCommand::SetLeaveAfterHand => {
            dispatch_set_leave_after_hand(context, table, args, &mut events)
        }
        CanonicalCommand::FoldWithProof => {
            dispatch_fold_with_proof(context, table, args, &mut events)
        }
    };
    if let Err(error) = result {
        *table = pre_table.clone();
        return Err(error);
    }
    state_machine::normalize_until_blocked(table, context.block_timestamp, &mut events)?;

    // Action transitions intentionally disarm the previous actor's deadline while
    // changing the turn.  The persisted tagged-union phase must never cross the
    // codec boundary with an unarmed active deadline, so re-arm the newly active
    // betting actor from the authenticated consensus timestamp before serializing
    // the dispatch output.
    if matches!(
        table.hand_phase,
        super::types::HandPhase::Betting { deadline_ms: 0, .. }
    ) {
        if let Err(error) = table.arm_betting_deadline(context.block_timestamp) {
            *table = pre_table.clone();
            return Err(error);
        }
    }

    // 证明任务元数据只在成功且真正改变状态的 dispatch 上推进。
    // 使用 pre_table 作为计数基准，防止 create_table 覆写结构时把序号重置为 0。
    let state_changed = *table != pre_table;
    if state_changed {
        let next_call_seq = pre_table
            .call_seq
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Serialization("texas_poker call_seq overflow".into()))?;
        let hand_started = events
            .iter()
            .any(|event| matches!(event, TexasPokerEvent::HandStarted { .. }));
        let next_hand_id = if hand_started {
            pre_table
                .hand_id
                .checked_add(1)
                .ok_or_else(|| PokerL1Error::Serialization("texas_poker hand_id overflow".into()))?
        } else {
            pre_table.hand_id
        };
        table.call_seq = next_call_seq;
        table.hand_id = next_hand_id;
    }
    log_events(&events);

    // Post-commit Prover：构造证明任务（pre/post table + method 元数据）。
    // return_value = borsh(DispatchOutput { events, prove_task })，
    // Orchestrator 从链层取回后反序列化生成 proof。
    let return_value = build_dispatch_output(context, &events, selector, args, pre_table, table)?;

    Ok(DispatchResult {
        created_objects: vec![],
        modified_objects: vec![table.id],
        return_value,
    })
}

/// 签名交易消息域（P0-2 缺口修复：caller 签名绑定接线）。
pub const TX_SIGNING_DOMAIN: &[u8] = b"zchain.tx.v1";

/// 构造签名交易消息哈希：绑定链 ID、表对象、caller、方法与载荷、nonce。
///
/// nonce 绑定进签名消息 = 每条签名只能用于特定序列槽（配合 runtime 层的
/// applied-nonce 集合实现防重放）。客户端与 runtime 必须使用同一公式。
pub fn tx_message_hash(
    chain_id: ChainId,
    table_id: &ObjectID,
    caller: &Address,
    selector: &[u8; 32],
    args: &[u8],
    nonce: u64,
) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256 initialized");
    Update::update(&mut hasher, TX_SIGNING_DOMAIN);
    Update::update(&mut hasher, &chain_id.to_be_bytes());
    Update::update(&mut hasher, table_id.to_bytes().as_slice());
    Update::update(&mut hasher, caller.as_slice());
    Update::update(&mut hasher, selector);
    Update::update(&mut hasher, args);
    Update::update(&mut hasher, &nonce.to_be_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("32-byte blake2b output");
    out
}

/// 构造 `DispatchOutput` 并序列化为 return_value 字节。
///
/// 根据 selector 推导 method_kind discriminant + 构造 MethodInput，
/// 封装为 `DispatchOutput { events, prove_task }`。
/// 没有状态变化（例如 no-op advance_deadline）时仅返回 events；所有已注册 selector
/// 一旦改变状态都必须产生 task。未知 selector 返回错误，不能静默丢 task。
fn build_dispatch_output(
    context: &DispatchContext,
    events: &[TexasPokerEvent],
    selector: &[u8; 32],
    args: &[u8],
    pre_table: TexasPokerTable,
    post_table: &TexasPokerTable,
) -> PokerL1Result<Vec<u8>> {
    use super::prove_task::{DispatchOutput, ProveTask};

    if pre_table == *post_table {
        let out = DispatchOutput::events_only(events.to_vec());
        return borsh::to_vec(&out)
            .map_err(|e| PokerL1Error::Serialization(format!("dispatch output borsh: {e}")));
    }

    let (kind, canonical_args) = canonical_command_parts(selector, args)?;
    let table_id = post_table.id.creation_nonce;
    let hand_id = post_table.hand_id;
    let call_seq = post_table.call_seq;
    let task = ProveTask::new(
        kind,
        context.clone(),
        canonical_args,
        pre_table,
        post_table.clone(),
        table_id,
        hand_id,
        call_seq,
    );
    let out = DispatchOutput::with_task(events.to_vec(), task);
    borsh::to_vec(&out)
        .map_err(|e| PokerL1Error::Serialization(format!("dispatch output borsh: {e}")))
}

/// 根据 selector + args 构造 `(method_kind_discriminant, MethodInput)`。
///
/// method_kind discriminant 与 `poker_texas_air::MethodKind` 对齐
/// （`#[repr(u8)]` + `use_discriminant=true`）。
///
/// 四个 active 密码学方法先按各自真实 Args 类型完整解码，再把原始 borsh 字节写入
/// 专用 MethodInput variant。这样证明端能重新验证完整 proof，而不是只拿 seat_index。
fn build_method_input(
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<(u8, super::prove_task::MethodInput)> {
    use super::prove_task::MethodInput;
    // method_kind discriminant（与 poker_texas_air::MethodKind 对齐）
    const K_CREATE_TABLE: u8 = CanonicalCommand::CreateTable as u8;
    const K_JOIN_TABLE: u8 = CanonicalCommand::JoinTable as u8;
    const K_LEAVE_TABLE: u8 = CanonicalCommand::LeaveTable as u8;
    const K_START_HAND: u8 = CanonicalCommand::StartHand as u8;
    const K_ADVANCE_DEADLINE: u8 = CanonicalCommand::AdvanceDeadline as u8;
    const K_FOLD: u8 = CanonicalCommand::Fold as u8;
    const K_CHECK: u8 = CanonicalCommand::Check as u8;
    const K_CALL: u8 = CanonicalCommand::Call as u8;
    const K_RAISE: u8 = CanonicalCommand::Raise as u8;
    const K_FORCE_FOLD: u8 = CanonicalCommand::ForceFold as u8;
    const K_KICK: u8 = CanonicalCommand::KickPlayer as u8;
    const K_ADDON: u8 = CanonicalCommand::Addon as u8;
    const K_REBUY: u8 = CanonicalCommand::Rebuy as u8;
    const K_SUBMIT_SHUFFLE: u8 = CanonicalCommand::SubmitShuffleV2 as u8;
    const K_SUBMIT_REVEAL: u8 = CanonicalCommand::SubmitPlayerRevealTokens as u8;
    const K_SUBMIT_RECONSTRUCT: u8 = CanonicalCommand::SubmitReconstructDeck as u8;
    const K_BET: u8 = CanonicalCommand::Bet as u8;
    const K_SET_LEAVE_AFTER_HAND: u8 = CanonicalCommand::SetLeaveAfterHand as u8;
    const K_FOLD_WITH_PROOF: u8 = CanonicalCommand::FoldWithProof as u8;
    const K_REDEAL_HOLE_CARD: u8 = CanonicalCommand::RedealHoleCard as u8;

    if selector == &selectors::create_table() {
        let a: CreateTableArgs = decode_args(args, "create_table prove task")?;
        return Ok((
            K_CREATE_TABLE,
            MethodInput::CreateTable {
                max_players: a.max_players,
                small_blind: a.small_blind,
                big_blind: a.big_blind,
                rit_mode: a.rit_mode,
            },
        ));
    }
    if selector == &selectors::join_table() {
        let a: JoinTableArgs = decode_args(args, "join_table prove task")?;
        return Ok((
            K_JOIN_TABLE,
            MethodInput::Join {
                player: a.player,
                buy_in: a.buy_in,
            },
        ));
    }
    if selector == &selectors::leave_table() {
        let a: LeaveTableArgs = decode_args(args, "leave_table prove task")?;
        return Ok((
            K_LEAVE_TABLE,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::start_hand() {
        return Ok((K_START_HAND, MethodInput::Empty));
    }
    if selector == &selectors::advance_deadline() {
        if !args.is_empty() {
            return Err(PokerL1Error::Serialization(
                "advance_deadline does not accept arguments".into(),
            ));
        }
        return Ok((K_ADVANCE_DEADLINE, MethodInput::Empty));
    }
    if selector == &selectors::force_fold() {
        let a: SeatIndexArgs = decode_args(args, "force_fold prove task")?;
        return Ok((
            K_FORCE_FOLD,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::kick_player_v2() {
        let a: SeatIndexArgs = decode_args(args, "kick_player_v2 prove task")?;
        return Ok((
            K_KICK,
            MethodInput::Kick {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::submit_shuffle_v2() {
        let a: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2 prove task")?;
        return Ok((
            K_SUBMIT_SHUFFLE,
            MethodInput::SubmitShuffleV2 {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::submit_player_reveal_tokens() {
        let a: SubmitRevealTokensArgs =
            decode_args(args, "submit_player_reveal_tokens prove task")?;
        return Ok((
            K_SUBMIT_REVEAL,
            MethodInput::SubmitPlayerRevealTokens {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::submit_reconstruct_deck() {
        let a: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck prove task")?;
        return Ok((
            K_SUBMIT_RECONSTRUCT,
            MethodInput::SubmitReconstructDeck {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::fold() {
        let a: SeatIndexArgs = decode_args(args, "fold prove task")?;
        return Ok((
            K_FOLD,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::check() {
        let a: SeatIndexArgs = decode_args(args, "check prove task")?;
        return Ok((
            K_CHECK,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::call() {
        let a: SeatIndexArgs = decode_args(args, "call prove task")?;
        return Ok((
            K_CALL,
            MethodInput::SeatOnly {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::raise() {
        let a: RaiseArgs = decode_args(args, "raise prove task")?;
        return Ok((
            K_RAISE,
            MethodInput::Raise {
                seat_index: a.seat_index,
                total_bet: a.total_bet,
            },
        ));
    }
    if selector == &selectors::bet() {
        let a: BetArgs = decode_args(args, "bet prove task")?;
        return Ok((
            K_BET,
            MethodInput::Bet {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::addon() {
        let a: AddonArgs = decode_args(args, "addon prove task")?;
        return Ok((
            K_ADDON,
            MethodInput::Funds {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::rebuy() {
        let a: RebuyArgs = decode_args(args, "rebuy prove task")?;
        return Ok((
            K_REBUY,
            MethodInput::Funds {
                seat_index: a.seat_index,
                amount: a.amount,
            },
        ));
    }
    if selector == &selectors::set_leave_after_hand() {
        let a: SetLeaveAfterHandArgs = decode_args(args, "set_leave_after_hand prove task")?;
        return Ok((
            K_SET_LEAVE_AFTER_HAND,
            MethodInput::SetLeaveAfterHand {
                seat_index: a.seat_index,
                want_leave: a.want_leave,
            },
        ));
    }
    if selector == &selectors::fold_with_proof() {
        let a: FoldWithProofArgs = decode_args(args, "fold_with_proof prove task")?;
        return Ok((
            K_FOLD_WITH_PROOF,
            MethodInput::FoldWithProof {
                seat_index: a.seat_index,
            },
        ));
    }
    if selector == &selectors::redeal_hole_card() {
        let a: RedealHoleCardArgs = decode_args(args, "redeal_hole_card prove task")?;
        return Ok((
            K_REDEAL_HOLE_CARD,
            MethodInput::RedealHoleCard {
                seat_index: a.seat_index,
                card_slot: a.card_slot,
            },
        ));
    }

    Err(PokerL1Error::UnknownContractMethod {
        selector: *selector,
    })
}

/// Derive a context-free typed view for commands whose payload still carries every input.
///
/// Actor-less commands deliberately fail here and must use [`derive_authenticated_method_input`].
/// This separation prevents callers from inventing a placeholder actor when authenticated context
/// and canonical pre-state are required.
pub fn derive_method_input(
    method_tag: u8,
    canonical_args: &[u8],
) -> PokerL1Result<super::prove_task::MethodInput> {
    let command = CanonicalCommand::from_u8(method_tag).ok_or_else(|| {
        PokerL1Error::Serialization(format!("unknown canonical Texas command tag {method_tag}"))
    })?;
    if matches!(
        command,
        CanonicalCommand::JoinTable
            | CanonicalCommand::LeaveTable
            | CanonicalCommand::Fold
            | CanonicalCommand::Check
            | CanonicalCommand::Call
            | CanonicalCommand::Raise
            | CanonicalCommand::Bet
            | CanonicalCommand::Addon
            | CanonicalCommand::Rebuy
            | CanonicalCommand::SetLeaveAfterHand
    ) {
        return Err(PokerL1Error::Serialization(format!(
            "{} canonical input requires authenticated context and pre-state",
            command.method_name()
        )));
    }
    let (derived_tag, input) = build_method_input(&command.selector(), canonical_args)?;
    if derived_tag != method_tag {
        return Err(PokerL1Error::Serialization(format!(
            "canonical Texas command tag mismatch: stored={method_tag}, decoded={derived_tag}"
        )));
    }
    Ok(input)
}

/// Derive the proof-facing command view from authenticated context and canonical pre-state.
///
/// Canonical payloads physically omit redundant `player`/`seat_index` fields and derive them from
/// the signed caller or canonical current actor. The returned
/// [`MethodInput`](super::prove_task::MethodInput) never takes a self-directed actor identity from
/// unauthenticated payload data.
pub fn derive_authenticated_method_input(
    method_tag: u8,
    canonical_args: &[u8],
    context: &DispatchContext,
    pre_table: &TexasPokerTable,
) -> PokerL1Result<super::prove_task::MethodInput> {
    use super::prove_task::MethodInput;

    let command = CanonicalCommand::from_u8(method_tag).ok_or_else(|| {
        PokerL1Error::Serialization(format!("unknown canonical Texas command tag {method_tag}"))
    })?;
    let caller_seat = |method: &str| authenticated_caller_seat(context, pre_table, method);

    let input = match command {
        CanonicalCommand::JoinTable => {
            let args: CanonicalJoinTableArgs =
                decode_args(canonical_args, "canonical join_table payload")?;
            MethodInput::Join {
                player: context.caller,
                buy_in: args.buy_in,
            }
        }
        CanonicalCommand::LeaveTable
        | CanonicalCommand::Fold
        | CanonicalCommand::Check
        | CanonicalCommand::Call => {
            require_empty_canonical_payload(canonical_args, command.method_name())?;
            MethodInput::SeatOnly {
                seat_index: caller_seat(command.method_name())?,
            }
        }
        CanonicalCommand::Raise => {
            let args: CanonicalRaiseArgs = decode_args(canonical_args, "canonical raise payload")?;
            MethodInput::Raise {
                seat_index: caller_seat("raise")?,
                total_bet: args.total_bet,
            }
        }
        CanonicalCommand::Bet => {
            let args: CanonicalAmountArgs = decode_args(canonical_args, "canonical bet payload")?;
            MethodInput::Bet {
                seat_index: caller_seat("bet")?,
                amount: args.amount,
            }
        }
        CanonicalCommand::Addon | CanonicalCommand::Rebuy => {
            let args: CanonicalAmountArgs = decode_args(canonical_args, "canonical funds payload")?;
            MethodInput::Funds {
                seat_index: caller_seat(command.method_name())?,
                amount: args.amount,
            }
        }
        CanonicalCommand::SetLeaveAfterHand => {
            let args: CanonicalSetLeaveAfterHandArgs =
                decode_args(canonical_args, "canonical set_leave_after_hand payload")?;
            MethodInput::SetLeaveAfterHand {
                seat_index: caller_seat("set_leave_after_hand")?,
                want_leave: args.want_leave,
            }
        }
        CanonicalCommand::KickPlayer => {
            let args: SeatIndexArgs = decode_args(canonical_args, "canonical kick_player payload")?;
            MethodInput::Kick {
                seat_index: args.seat_index,
            }
        }
        CanonicalCommand::FoldWithProof => {
            let _: CanonicalFoldWithProofArgs =
                decode_args(canonical_args, "canonical fold_with_proof payload")?;
            MethodInput::FoldWithProof {
                seat_index: caller_seat("fold_with_proof")?,
            }
        }
        CanonicalCommand::SubmitShuffleV2 => {
            let _: CanonicalSubmitShuffleV2Args =
                decode_args(canonical_args, "canonical submit_shuffle_v2 payload")?;
            MethodInput::SubmitShuffleV2 {
                seat_index: caller_seat("submit_shuffle_v2")?,
            }
        }
        CanonicalCommand::SubmitPlayerRevealTokens => {
            let _: CanonicalSubmitRevealTokensArgs = decode_args(
                canonical_args,
                "canonical submit_player_reveal_tokens payload",
            )?;
            MethodInput::SubmitPlayerRevealTokens {
                seat_index: caller_seat("submit_player_reveal_tokens")?,
            }
        }
        CanonicalCommand::SubmitReconstructDeck => {
            let _: CanonicalSubmitReconstructDeckArgs =
                decode_args(canonical_args, "canonical submit_reconstruct_deck payload")?;
            MethodInput::SubmitReconstructDeck {
                seat_index: caller_seat("submit_reconstruct_deck")?,
            }
        }
        CanonicalCommand::RedealHoleCard => {
            let args: CanonicalRedealHoleCardArgs =
                decode_args(canonical_args, "canonical redeal_hole_card payload")?;
            MethodInput::RedealHoleCard {
                seat_index: caller_seat("redeal_hole_card")?,
                card_slot: args.card_slot,
            }
        }
        _ => derive_method_input(method_tag, canonical_args)?,
    };

    Ok(input)
}

/// Normalize one legacy ABI call into the unique persisted tagged-command representation.
///
/// The returned tag is the stable `CanonicalCommand` discriminant. Ordinary player commands omit
/// actor fields, amount commands retain only their amount, and deadline advancement has an empty
/// payload because time comes from `DispatchContext`. Proof-bearing crypto payloads retain
/// their complete statements and proofs while omitting authenticated actor fields. Unknown
/// selectors and malformed arguments fail closed.
pub fn canonical_command_parts(selector: &[u8; 32], args: &[u8]) -> PokerL1Result<(u8, Vec<u8>)> {
    let command =
        CanonicalCommand::from_selector(selector).ok_or(PokerL1Error::UnknownContractMethod {
            selector: *selector,
        })?;
    let (derived_tag, _) = build_method_input(selector, args)?;
    if derived_tag != command as u8 {
        return Err(PokerL1Error::Serialization(format!(
            "Texas command selector/tag mismatch: selector={selector:?}, derived={derived_tag}, expected={}",
            command as u8
        )));
    }
    let canonical_args = match command {
        CanonicalCommand::AdvanceDeadline => Vec::new(),
        CanonicalCommand::JoinTable => {
            let input: JoinTableArgs = decode_args(args, "join_table canonical payload")?;
            borsh::to_vec(&CanonicalJoinTableArgs {
                buy_in: input.buy_in,
                pk: input.pk,
                tx_pk: input.tx_pk,
                pk_ownership_proof: input.pk_ownership_proof,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("join_table canonical payload: {error}"))
            })?
        }
        CanonicalCommand::FoldWithProof => {
            let input: FoldWithProofArgs = decode_args(args, "fold_with_proof canonical payload")?;
            borsh::to_vec(&CanonicalFoldWithProofArgs {
                output_cards: input.output_cards,
                fold_proof: input.fold_proof,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("fold_with_proof canonical payload: {error}"))
            })?
        }
        CanonicalCommand::SubmitShuffleV2 => {
            let input: SubmitShuffleV2Args =
                decode_args(args, "submit_shuffle_v2 canonical payload")?;
            borsh::to_vec(&CanonicalSubmitShuffleV2Args {
                output_cards: input.output_cards,
                shuffle_proof: input.shuffle_proof,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("submit_shuffle_v2 canonical payload: {error}"))
            })?
        }
        CanonicalCommand::SubmitPlayerRevealTokens => {
            let input: SubmitRevealTokensArgs =
                decode_args(args, "submit_player_reveal_tokens canonical payload")?;
            borsh::to_vec(&CanonicalSubmitRevealTokensArgs {
                reveal_tokens: input.reveal_tokens,
                proofs: input.proofs,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "submit_player_reveal_tokens canonical payload: {error}"
                ))
            })?
        }
        CanonicalCommand::SubmitReconstructDeck => {
            let input: SubmitReconstructDeckArgs =
                decode_args(args, "submit_reconstruct_deck canonical payload")?;
            borsh::to_vec(&CanonicalSubmitReconstructDeckArgs {
                statement: input.statement,
                proof: input.proof,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "submit_reconstruct_deck canonical payload: {error}"
                ))
            })?
        }
        CanonicalCommand::RedealHoleCard => {
            let input: RedealHoleCardArgs =
                decode_args(args, "redeal_hole_card canonical payload")?;
            borsh::to_vec(&CanonicalRedealHoleCardArgs {
                card_slot: input.card_slot,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("redeal_hole_card canonical payload: {error}"))
            })?
        }
        CanonicalCommand::LeaveTable
        | CanonicalCommand::Fold
        | CanonicalCommand::Check
        | CanonicalCommand::Call => {
            let _: SeatIndexArgs = decode_args(args, "actor-only canonical payload")?;
            Vec::new()
        }
        CanonicalCommand::SetLeaveAfterHand => {
            let input: SetLeaveAfterHandArgs =
                decode_args(args, "set_leave_after_hand canonical payload")?;
            borsh::to_vec(&CanonicalSetLeaveAfterHandArgs {
                want_leave: input.want_leave,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "set_leave_after_hand canonical payload: {error}"
                ))
            })?
        }
        CanonicalCommand::Raise => {
            let input: RaiseArgs = decode_args(args, "raise canonical payload")?;
            borsh::to_vec(&CanonicalRaiseArgs {
                total_bet: input.total_bet,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("raise canonical payload: {error}"))
            })?
        }
        CanonicalCommand::Bet => {
            let input: BetArgs = decode_args(args, "bet canonical payload")?;
            borsh::to_vec(&CanonicalAmountArgs {
                amount: input.amount,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("bet canonical payload: {error}"))
            })?
        }
        CanonicalCommand::Addon => {
            let input: AddonArgs = decode_args(args, "addon canonical payload")?;
            borsh::to_vec(&CanonicalAmountArgs {
                amount: input.amount,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("addon canonical payload: {error}"))
            })?
        }
        CanonicalCommand::Rebuy => {
            let input: RebuyArgs = decode_args(args, "rebuy canonical payload")?;
            borsh::to_vec(&CanonicalAmountArgs {
                amount: input.amount,
            })
            .map_err(|error| {
                PokerL1Error::Serialization(format!("rebuy canonical payload: {error}"))
            })?
        }
        CanonicalCommand::KickPlayer => {
            let seat_index =
                decode_args::<SeatIndexArgs>(args, "kick_player_v2 canonical payload")?.seat_index;
            borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|error| {
                PokerL1Error::Serialization(format!("kick_player_v2 canonical payload: {error}"))
            })?
        }
        _ => args.to_vec(),
    };
    Ok((derived_tag, canonical_args))
}

/// Reconstruct the active execution ABI from an authenticated actor-less command payload.
///
/// Proof tasks and method batches persist only canonical payloads. Native dispatch remains the
/// single business replay engine, so verifier code uses this function to rehydrate the boundary
/// ABI without accepting an actor identity from prover-controlled bytes.
pub fn replay_dispatch_args(
    method_tag: u8,
    canonical_args: &[u8],
    context: &DispatchContext,
    pre_table: &TexasPokerTable,
) -> PokerL1Result<Vec<u8>> {
    use super::prove_task::MethodInput;

    let command = CanonicalCommand::from_u8(method_tag).ok_or_else(|| {
        PokerL1Error::Serialization(format!("unknown canonical Texas command tag {method_tag}"))
    })?;
    let input = derive_authenticated_method_input(method_tag, canonical_args, context, pre_table)?;
    let replay_args = match (command, input) {
        (CanonicalCommand::JoinTable, MethodInput::Join { player, buy_in }) => {
            let canonical: CanonicalJoinTableArgs =
                decode_args(canonical_args, "canonical join_table replay payload")?;
            borsh::to_vec(&JoinTableArgs {
                player,
                buy_in,
                pk: canonical.pk,
                tx_pk: canonical.tx_pk,
                pk_ownership_proof: canonical.pk_ownership_proof,
            })
        }
        (CanonicalCommand::KickPlayer, MethodInput::Kick { seat_index }) => {
            borsh::to_vec(&SeatIndexArgs { seat_index })
        }
        (CanonicalCommand::FoldWithProof, MethodInput::FoldWithProof { seat_index }) => {
            let canonical: CanonicalFoldWithProofArgs =
                decode_args(canonical_args, "canonical fold_with_proof replay payload")?;
            borsh::to_vec(&FoldWithProofArgs {
                seat_index,
                output_cards: canonical.output_cards,
                fold_proof: canonical.fold_proof,
            })
        }
        (CanonicalCommand::SubmitShuffleV2, MethodInput::SubmitShuffleV2 { seat_index }) => {
            let canonical: CanonicalSubmitShuffleV2Args =
                decode_args(canonical_args, "canonical submit_shuffle_v2 replay payload")?;
            borsh::to_vec(&SubmitShuffleV2Args {
                seat_index,
                output_cards: canonical.output_cards,
                shuffle_proof: canonical.shuffle_proof,
            })
        }
        (
            CanonicalCommand::SubmitPlayerRevealTokens,
            MethodInput::SubmitPlayerRevealTokens { seat_index },
        ) => {
            let canonical: CanonicalSubmitRevealTokensArgs = decode_args(
                canonical_args,
                "canonical submit_player_reveal_tokens replay payload",
            )?;
            borsh::to_vec(&SubmitRevealTokensArgs {
                seat_index,
                reveal_tokens: canonical.reveal_tokens,
                proofs: canonical.proofs,
            })
        }
        (
            CanonicalCommand::SubmitReconstructDeck,
            MethodInput::SubmitReconstructDeck { seat_index },
        ) => {
            let canonical: CanonicalSubmitReconstructDeckArgs = decode_args(
                canonical_args,
                "canonical submit_reconstruct_deck replay payload",
            )?;
            borsh::to_vec(&SubmitReconstructDeckArgs {
                seat_index,
                statement: canonical.statement,
                proof: canonical.proof,
            })
        }
        (
            CanonicalCommand::LeaveTable
            | CanonicalCommand::Fold
            | CanonicalCommand::Check
            | CanonicalCommand::Call,
            MethodInput::SeatOnly { seat_index },
        ) => borsh::to_vec(&SeatIndexArgs { seat_index }),
        (
            CanonicalCommand::Raise,
            MethodInput::Raise {
                seat_index,
                total_bet,
            },
        ) => borsh::to_vec(&RaiseArgs {
            seat_index,
            total_bet,
        }),
        (CanonicalCommand::Bet, MethodInput::Bet { seat_index, amount }) => {
            borsh::to_vec(&BetArgs { seat_index, amount })
        }
        (CanonicalCommand::Addon, MethodInput::Funds { seat_index, amount }) => {
            borsh::to_vec(&AddonArgs { seat_index, amount })
        }
        (CanonicalCommand::Rebuy, MethodInput::Funds { seat_index, amount }) => {
            borsh::to_vec(&RebuyArgs { seat_index, amount })
        }
        (
            CanonicalCommand::SetLeaveAfterHand,
            MethodInput::SetLeaveAfterHand {
                seat_index,
                want_leave,
            },
        ) => borsh::to_vec(&SetLeaveAfterHandArgs {
            seat_index,
            want_leave,
        }),
        (
            CanonicalCommand::RedealHoleCard,
            MethodInput::RedealHoleCard {
                seat_index,
                card_slot,
            },
        ) => borsh::to_vec(&RedealHoleCardArgs {
            seat_index,
            card_slot,
        }),
        _ => return Ok(canonical_args.to_vec()),
    }
    .map_err(|error| {
        PokerL1Error::Serialization(format!(
            "{} replay payload borsh: {error}",
            command.method_name()
        ))
    })?;
    Ok(replay_args)
}

fn require_empty_canonical_payload(payload: &[u8], method: &str) -> PokerL1Result<()> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(PokerL1Error::Serialization(format!(
            "{method} canonical payload must be empty"
        )))
    }
}

/// 将 events 列表以 debug 级别记录到 tracing。
fn log_events(events: &[TexasPokerEvent]) {
    if events.is_empty() {
        return;
    }
    tracing::debug!("texas_poker dispatch emitted {} events", events.len());
}

/// borsh 反序列化辅助。
fn decode_args<T: BorshDeserialize>(args: &[u8], method: &str) -> PokerL1Result<T> {
    borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("{method} args borsh: {e}")))
}

// ========== P0-2 权限校验辅助 ==========
//
// TexasPokerTable 此前在 dispatch 层与 precompile 层都没有任何调用方权限校验
// （routing 层的 validate_game_turn_tx 只覆盖 GameStatus，未覆盖 TexasPokerTable）。
// 这意味着任意地址都能对任意座位执行 fold/raise/kick/rebuy 等方法。
//
// 本模块在 dispatch 层补齐 caller 权限校验：
// - 动作类（fold/check/call/raise/bet/auto_fold/addon/rebuy/leave_table）：
//   caller == seats[seat_index].player
// - 管理类（kick_player/force_fold/reset_for_next_hand）：
//   caller == table.creator（create_table 时记录）
// - 协议类（submit_*/fold_with_proof）：
//   caller == seats[seat_index].player（与动作类一致）
//
// 选择 dispatch 层（而非 routing 层）的原因：caller 校验可被 poker_texas_air
// 电路直接约束，与同步电路目标契合；且合约自包含，不引入跨对象同步负担。

/// Resolve the authenticated caller to its unique occupied seat.
///
/// Legacy wire payloads still carry `seat_index`; that value is only a compatibility assertion.
/// The returned seat is derived from the signed [`DispatchContext`] and canonical pre-state, so
/// state-machine execution never trusts a caller-selected actor index.
fn resolve_caller_seat(
    context: &DispatchContext,
    table: &TexasPokerTable,
    claimed_seat_index: u8,
    method: &str,
) -> PokerL1Result<u8> {
    if claimed_seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: seat_index {claimed_seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if !table.padding_seats_are_vacant() {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: non-canonical seat layout: padding beyond max_players={} is occupied",
            table.max_players
        )));
    }

    let resolved = authenticated_caller_seat(context, table, method)?;
    if claimed_seat_index != resolved {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: legacy seat_index {claimed_seat_index} does not match authenticated caller seat {resolved}"
        )));
    }
    Ok(resolved)
}

fn authenticated_caller_seat(
    context: &DispatchContext,
    table: &TexasPokerTable,
    method: &str,
) -> PokerL1Result<u8> {
    if !table.padding_seats_are_vacant() {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: non-canonical seat layout: padding beyond max_players={} is occupied",
            table.max_players
        )));
    }
    let mut resolved = None;
    for (seat_index, seat) in table.seats.iter().enumerate() {
        if seat.is_occupied() && seat.player() == context.caller {
            let seat_index = u8::try_from(seat_index).map_err(|_| {
                PokerL1Error::Serialization(format!(
                    "{method}: caller seat index does not fit canonical u8"
                ))
            })?;
            if let Some(previous) = resolved {
                return Err(PokerL1Error::Serialization(format!(
                    "{method}: caller {:?} occupies multiple seats ({previous}, {seat_index})",
                    context.caller
                )));
            }
            resolved = Some(seat_index);
        }
    }

    resolved.ok_or_else(|| {
        PokerL1Error::Serialization(format!(
            "{method}: caller {:?} does not occupy a seat",
            context.caller
        ))
    })
}

/// 校验 caller 是桌台创建者（管理类方法）。
fn require_caller_is_creator(
    context: &DispatchContext,
    table: &TexasPokerTable,
    method: &str,
) -> PokerL1Result<()> {
    if table.creator != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "{method}: caller {:?} is not table creator",
            context.caller
        )));
    }
    Ok(())
}

// ========== dispatch_* 子函数 ==========

/// `create_table` — 初始化桌台（覆写默认空桌台）。
fn dispatch_create_table(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    _events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: CreateTableArgs = decode_args(args, "create_table")?;
    // 语义校验 + creator 登记在 core::apply_create_table（2026-09-09 下沉）。
    state_machine::apply_create_table(
        table,
        context.caller,
        input.max_players,
        input.small_blind,
        input.big_blind,
        input.rit_mode,
    )
}

/// `fold_with_proof` — 带 proof 的局中 fold（剥离加密层 + 退出后续 reveal）。
///
/// 权限：`caller == seat.player()`（与普通 fold 一致）。
/// 仅在下注轮可用（`is_betting_round`）。
///
/// 调用 `state_machine::apply_fold_with_proof`：验证 DLEqProof（LeaveKind）→
/// 从 aggregated_pk 移除玩家 pk → remask encrypted deck → scrub 所有 reveal
/// pending → 标记 folded → 推进轮次。
fn dispatch_fold_with_proof(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: FoldWithProofArgs = decode_args(args, "fold_with_proof")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "fold_with_proof")?;
    state_machine::apply_fold_with_proof(
        table,
        seat_index,
        input.output_cards,
        input.fold_proof,
        events,
    )
}

/// `join_table` — 简单入座（不参与本局，标记 is_waiting=true）。
///
/// 仅在 WAITING 状态允许；占第一个空座位；玩家不能已在桌台。
fn dispatch_join_table(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: JoinTableArgs = decode_args(args, "join_table")?;
    // 入座方法：校验 caller == input.player（座位尚空，无法用 seat.player() 校验）
    // ——认证留在 runtime；其余语义在 core::apply_join_table（2026-09-09 下沉）。
    if input.player != context.caller {
        return Err(PokerL1Error::Serialization(format!(
            "join_table: caller {:?} != player {:?}",
            context.caller, input.player
        )));
    }
    state_machine::apply_join_table(
        table,
        input.player,
        input.buy_in,
        *input.pk,
        input.tx_pk,
        &input.pk_ownership_proof,
        events,
    )
}

/// `leave_table` — 简单离座（仅 WAITING 状态）。
fn dispatch_leave_table(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: LeaveTableArgs = decode_args(args, "leave_table")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "leave_table")?;
    // 语义（WAITING 校验 / 退款 / 腾座 / 事件）在 core::apply_leave_table
    // （2026-09-09 下沉）；caller 座位解析（认证）留在 runtime。
    state_machine::apply_leave_table(table, seat_index, events)
}

/// `start_hand` — 开始新一局。
///
/// 权限：仅 creator 可发起对局（管理员动作）。
fn dispatch_start_hand(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !args.is_empty() {
        return Err(PokerL1Error::Serialization(
            "start_hand does not accept arguments".into(),
        ));
    }
    require_caller_is_creator(context, table, "start_hand")?;
    state_machine::start_hand(table, events)
}

/// `advance_deadline` — 超时驱动。
fn dispatch_advance_deadline(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !args.is_empty() {
        return Err(PokerL1Error::Serialization(
            "advance_deadline does not accept arguments".into(),
        ));
    }
    // 时间只来自已认证的共识上下文；payload 不再保留第二份时间事实。
    state_machine::advance_deadline(table, context.block_timestamp, events).map(|_| ())
}

/// `force_fold` — 管理员强制 fold。
fn dispatch_force_fold(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "force_fold")?;
    require_caller_is_creator(context, table, "force_fold")?;
    state_machine::apply_fold_internal(table, input.seat_index, FOLD_REASON_FORCE_ADMIN, events)
}

/// Kick one player through the canonical administrator path.
fn dispatch_kick_player(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "kick_player_v2")?;
    // P0-2 权限校验：仅 creator 可执行管理类操作。
    if context.caller != table.creator {
        return Err(PokerL1Error::Serialization(format!(
            "kick_player_v2: caller {:?} is not table creator",
            context.caller
        )));
    }
    state_machine::kick_player_internal(table, input.seat_index, KICK_REASON_ADMIN, events)?;
    Ok(())
}

/// `submit_shuffle_v2` — 提交洗牌结果。
fn dispatch_submit_shuffle_v2(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitShuffleV2Args = decode_args(args, "submit_shuffle_v2")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "submit_shuffle_v2")?;
    state_machine::apply_submit_shuffle_v2(
        table,
        seat_index,
        input.output_cards,
        input.shuffle_proof,
        events,
    )
}

/// `submit_player_reveal_tokens` — 提交揭牌令牌。
fn dispatch_submit_player_reveal_tokens(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitRevealTokensArgs = decode_args(args, "submit_player_reveal_tokens")?;
    let seat_index = resolve_caller_seat(
        context,
        table,
        input.seat_index,
        "submit_player_reveal_tokens",
    )?;
    // ECPoint → G1Projective（state_machine 接口使用裸 G1Projective）
    let reveal_tokens: Vec<G1Projective> = input.reveal_tokens.into_iter().map(|t| *t).collect();
    state_machine::apply_submit_player_reveal_tokens(
        table,
        seat_index,
        reveal_tokens,
        input.proofs,
        context.block_timestamp,
        events,
    )
}

/// `submit_reconstruct_deck` — 提交重构牌组。
fn dispatch_submit_reconstruct_deck(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SubmitReconstructDeckArgs = decode_args(args, "submit_reconstruct_deck")?;
    let seat_index =
        resolve_caller_seat(context, table, input.seat_index, "submit_reconstruct_deck")?;
    state_machine::apply_submit_reconstruct_deck(
        table,
        seat_index,
        input.statement,
        input.proof,
        events,
    )
}

/// `redeal_hole_card` — 持有者换掉解密失败的底牌（死槽恢复）。
fn dispatch_redeal_hole_card(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RedealHoleCardArgs = decode_args(args, "redeal_hole_card")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "redeal_hole_card")?;
    state_machine::apply_redeal_hole_card(
        table,
        seat_index,
        input.card_slot,
        context.block_timestamp,
        events,
    )
}

/// `fold` — 玩家主动 fold。
fn dispatch_fold(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "fold")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "fold")?;
    state_machine::apply_fold(table, seat_index, events)
}

/// `check` — 玩家过牌。
fn dispatch_check(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "check")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "check")?;
    state_machine::apply_check(table, seat_index, events)
}

/// `call` — 玩家跟注。
fn dispatch_call(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SeatIndexArgs = decode_args(args, "call")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "call")?;
    state_machine::apply_call(table, seat_index, events)
}

/// `raise` — 玩家加注。
fn dispatch_raise(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RaiseArgs = decode_args(args, "raise")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "raise")?;
    state_machine::apply_raise(table, seat_index, input.total_bet, events)
}

/// `bet` — 玩家主动下注（postflop 第一个下注者）。
///
/// 调用 `state_machine::apply_bet`：内部复用 `apply_raise(total_bet = seat.bet() + amount)`。
fn dispatch_bet(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: BetArgs = decode_args(args, "bet")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "bet")?;
    state_machine::apply_bet(table, seat_index, input.amount, events)
}

/// `addon` — 玩家追加筹码（下一手生效）。
///
/// 调用 `state_machine::apply_addon`：累加 `pending_addon`，不动 `stack`。
/// 在下一手 `reset_for_next_hand` 第一阶段合并到 `stack`。
///
/// 资金来源由 Texas Poker precompile 统一校验：executor 传入 NativeCoin
/// UTXO，precompile 按 selector→amount 规则（join_table/addon/rebuy 解码 borsh
/// 载荷取 buy_in/amount）消费 amount、生成确定性 change，
/// 并校验 `chip_pool` 的 TableVault 转移与实际到账一致。
fn dispatch_addon(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: AddonArgs = decode_args(args, "addon")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "addon")?;
    state_machine::apply_addon(table, seat_index, input.amount, events)
}

/// `rebuy` — 玩家重购（立即生效）。
///
/// 调用 `state_machine::apply_rebuy`：直接改 `stack`（影响下一动作可用筹码）。
///
/// 资金来源与 `addon` 一样由 Texas Poker precompile 消费 NativeCoin UTXO；
/// rebuy 金额立即进入 `stack` 和完整 TableVault `chip_pool`；pending addon
/// 总额由 seat ledger 唯一派生，不再保存独立汇总。
fn dispatch_rebuy(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: RebuyArgs = decode_args(args, "rebuy")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "rebuy")?;
    state_machine::apply_rebuy(table, seat_index, input.amount, events)
}

/// `set_leave_after_hand` — 显式、幂等地设置本手结束后的离场意图。
///
/// 权限：`caller == seat.player()`（与 leave_table / addon 一致）。
/// 允许在任意 round_state 调用（玩家可在对局进行中预约离场）。
///
/// 实际离场（座位清空 + 退款）在下一手 `reset_for_next_hand` 内强制执行；
/// 只有实际改变标志时才产生 MethodKind=21 的 ProveTask；重复设置同值为 no-op。
fn dispatch_set_leave_after_hand(
    context: &DispatchContext,
    table: &mut TexasPokerTable,
    args: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let input: SetLeaveAfterHandArgs = decode_args(args, "set_leave_after_hand")?;
    let seat_index = resolve_caller_seat(context, table, input.seat_index, "set_leave_after_hand")?;
    state_machine::apply_set_leave_after_hand(table, seat_index, input.want_leave, events)?;
    Ok(())
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::texas_poker::constants::RIT_MODE_DISABLED;
    use crate::contracts::texas_poker::utils::{g1_generator, g1_identity};
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;

    /// `tx_message_hash` 已知答案向量（KAT）：签名域是 poker_l1 ↔
    /// client-wasm（WasmTxSession）↔ texas e2e 的三方契约，任何一处
    /// 改动（域分隔串/字段顺序/宽度）都必须同时改三端——本向量把漂移
    /// 变成编译期可见的测试失败。期望值由当前实现生成后钉死；
    /// 若你有意更改签名域，请重新生成并同步 client-wasm/texas。
    #[test]
    fn tx_message_hash_known_answer_vector() {
        let table_id = ObjectID::new([0x5A; 20], 77);
        let hash = tx_message_hash(
            377,
            &table_id,
            &[0xC0; 20],
            &[0x42; 32],
            &[0x11, 0x22, 0x33, 0x44],
            9,
        );
        let pinned: [u8; 32] = [
            0xdc, 0xb6, 0xda, 0x3b, 0x0f, 0x64, 0xd7, 0xc1, 0x06, 0x25, 0x7b, 0x6c, 0x52, 0xcf,
            0x42, 0x1b, 0x43, 0xf3, 0x9f, 0xec, 0x0a, 0x4c, 0x42, 0x38, 0xc8, 0xa6, 0xb8, 0x76,
            0xb3, 0xb1, 0x88, 0x26,
        ];
        assert_eq!(
            hash, pinned,
            "tx signature domain drifted — sync poker_l1/client-wasm/texas"
        );
    }

    fn make_table() -> TexasPokerTable {
        // creator 设为 [0xAA;20]，与 make_context().caller 一致，
        // 使需要 creator 权限的测试（kick/start_hand/reset）天然通过。
        TexasPokerTable::new(ObjectID::new([0xFF; 20], 0), [0xAA; 20], 6, 50, 100)
    }

    fn make_context() -> DispatchContext {
        DispatchContext {
            caller: [0xAA; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    /// 构造指定 caller 的 context（用于多玩家权限校验测试）。
    fn make_context_as(caller: Address) -> DispatchContext {
        let mut ctx = make_context();
        ctx.caller = caller;
        ctx
    }

    fn join_args(player: Address, buy_in: u64, secret: u64) -> JoinTableArgs {
        JoinTableArgs::with_key(
            player,
            buy_in,
            super::super::utils::scalar_from_u64(secret),
            super::super::utils::scalar_from_u64(secret + 10_000),
        )
        .unwrap()
        .with_tx_pk(registered_tx_pk_fixture())
    }

    /// 测试用"已登记"会话交易公钥（base_g 压缩点，非恒等元）。
    fn registered_tx_pk_fixture() -> crate::signature::TaggedPubkey {
        use poker_protocol::crypto::curve::CurvePoint;
        crate::signature::TaggedPubkey {
            tag: crate::signature::encode_tag(
                crate::signature::SignatureScheme::Stark,
                crate::signature::CURRENT_VERSION,
            ),
            raw: poker_protocol::crypto::types::base_g()
                .compress()
                .as_ref()
                .to_vec(),
        }
    }

    fn decode_output(result: &DispatchResult) -> super::super::prove_task::DispatchOutput {
        borsh::from_slice(&result.return_value).expect("dispatch output 应是有效 borsh")
    }

    #[test]
    fn selector_deterministic() {
        let h1 = selectors::create_table();
        let h2 = compute_method_selector("create_table");
        assert_eq!(h1, h2);
    }

    #[test]
    fn all_selectors_unique() {
        let sels = selectors::all();
        assert_eq!(sels.len(), 20, "registry must expose only active selectors");
        for i in 0..sels.len() {
            for j in (i + 1)..sels.len() {
                assert_ne!(sels[i], sels[j], "selector[{i}] == selector[{j}] 不应相等");
            }
        }
    }

    #[test]
    fn canonical_command_tags_cover_all_selectors() {
        let mut tags = std::collections::BTreeSet::new();
        for selector in selectors::all() {
            let command = CanonicalCommand::from_selector(&selector).expect("known selector");
            tags.insert(command.method_tag());
        }
        assert_eq!(selectors::all().len(), 20);
        assert_eq!(tags.len(), 20);
        for retired_tag in [5, 10, 15, 16] {
            assert!(CanonicalCommand::from_u8(retired_tag).is_none());
            assert!(!tags.contains(&retired_tag));
        }
        assert_eq!(
            CanonicalCommand::from_selector(&selectors::advance_deadline()),
            Some(CanonicalCommand::AdvanceDeadline)
        );
        assert_eq!(
            CanonicalCommand::from_selector(&selectors::kick_player_v2()),
            Some(CanonicalCommand::KickPlayer)
        );
        assert!(CanonicalCommand::from_selector(&compute_method_selector("kick_player")).is_none());
        assert!(
            CanonicalCommand::from_selector(&compute_method_selector("join_and_shuffle")).is_none()
        );
        assert!(
            CanonicalCommand::from_selector(&compute_method_selector("leave_with_proof")).is_none()
        );
        assert!(CanonicalCommand::from_selector(&compute_method_selector("auto_fold")).is_none());
        assert!(
            CanonicalCommand::from_selector(&compute_method_selector("reset_for_next_hand"))
                .is_none()
        );
        assert!(CanonicalCommand::from_selector(&[0xFF; 32]).is_none());
    }

    #[test]
    fn archive_decoder_rejects_every_retired_selector() {
        for selector in [
            compute_method_selector("join_and_shuffle"),
            compute_method_selector("leave_with_proof"),
            compute_method_selector("auto_fold"),
            compute_method_selector("kick_player"),
            compute_method_selector("reset_for_next_hand"),
        ] {
            assert!(CanonicalCommand::from_archive_selector(&selector).is_none());
        }
    }

    #[test]
    fn source_dispatch_rejects_every_retired_selector_before_mutation() {
        let context = make_context();
        for selector in [
            compute_method_selector("join_and_shuffle"),
            compute_method_selector("leave_with_proof"),
            compute_method_selector("auto_fold"),
            compute_method_selector("kick_player"),
            compute_method_selector("reset_for_next_hand"),
        ] {
            let mut table = make_table();
            let before = table.clone();
            let error = dispatch(&context, &mut table, &selector, &[])
                .expect_err("retired selector must fail at the source boundary");
            assert!(matches!(error, PokerL1Error::UnknownContractMethod { .. }));
            assert_eq!(table, before);
            assert!(canonical_command_parts(&selector, &[]).is_err());
            assert!(build_method_input(&selector, &[]).is_err());
        }
    }

    #[test]
    fn kick_player_v2_canonical_payload_contains_only_the_target_seat() {
        let args = borsh::to_vec(&SeatIndexArgs { seat_index: 3 }).unwrap();
        let (tag, canonical) =
            canonical_command_parts(&selectors::kick_player_v2(), &args).unwrap();
        assert_eq!(tag, CanonicalCommand::KickPlayer as u8);
        let canonical: SeatIndexArgs = borsh::from_slice(&canonical).unwrap();
        assert_eq!(canonical.seat_index, 3);
        let retired_selector = compute_method_selector("kick_player");
        assert!(canonical_command_parts(&retired_selector, &args).is_err());
        assert!(build_method_input(&retired_selector, &args).is_err());
    }

    #[test]
    fn batch_tags_collapse_compatibility_selectors() {
        assert_eq!(
            CanonicalCommand::Check.batch_tag(),
            CanonicalCommand::Call.batch_tag()
        );
        assert_eq!(
            CanonicalCommand::Raise.batch_tag(),
            CanonicalCommand::Bet.batch_tag()
        );
        assert_eq!(
            CanonicalCommand::Fold.batch_tag(),
            CanonicalCommand::ForceFold.batch_tag()
        );
        assert_eq!(
            CanonicalCommand::AdvanceDeadline.batch_tag().family,
            CanonicalCommandFamily::Lifecycle
        );
        assert_ne!(
            CanonicalCommand::Addon.batch_tag(),
            CanonicalCommand::Rebuy.batch_tag()
        );
        assert_ne!(
            CanonicalCommand::Fold.batch_tag(),
            CanonicalCommand::FoldWithProof.batch_tag()
        );
    }

    #[test]
    fn dispatch_unknown_method_returns_error() {
        let ctx = make_context();
        let mut table = make_table();
        let unknown = [0xFE; 32];
        let result = dispatch(&ctx, &mut table, &unknown, &[]);
        assert!(matches!(
            result,
            Err(PokerL1Error::UnknownContractMethod { .. })
        ));
    }

    #[test]
    fn zero_argument_admin_methods_reject_trailing_bytes_atomically() {
        let context = make_context();
        for (name, selector) in [("start_hand", selectors::start_hand())] {
            let mut table = make_table();
            let before = table.clone();
            let error = dispatch(&context, &mut table, &selector, &[0x01])
                .expect_err("zero-argument admin method must reject trailing bytes");
            assert!(error.to_string().contains("does not accept arguments"));
            assert_eq!(table, before, "{name} argument rejection must be atomic");
        }
    }

    #[test]
    fn dispatch_create_table_initializes() {
        let ctx = make_context();
        let mut table = make_table();
        // 把 table 改成非初始状态，验证 create_table 会覆写
        table.pot = 999;

        let args = CreateTableArgs {
            max_players: 9,
            small_blind: 25,
            big_blind: 50,
            rit_mode: RIT_MODE_DISABLED,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes).unwrap();

        assert_eq!(table.max_players, 9);
        assert_eq!(table.small_blind, 25);
        assert_eq!(table.big_blind, 50);
        assert_eq!(
            table.rules.rit_mode, RIT_MODE_DISABLED,
            "create_table 不开启 RIT 时必须落为 DISABLED"
        );
        assert_eq!(table.pot, 0, "create_table 应覆写为初始状态");
        assert!(!result.modified_objects.is_empty());
    }

    #[test]
    fn dispatch_create_table_rejects_invalid_max_players() {
        let ctx = make_context();
        let mut table = make_table();
        let args = CreateTableArgs {
            max_players: 10, // 越界
            small_blind: 25,
            big_blind: 50,
            rit_mode: RIT_MODE_DISABLED,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn dispatch_create_table_enables_rit_twice() {
        use crate::contracts::texas_poker::constants::RIT_MODE_TWICE;
        let ctx = make_context();
        let mut table = make_table();
        let args = CreateTableArgs {
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
            rit_mode: RIT_MODE_TWICE,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes).unwrap();
        assert_eq!(
            table.rules.rit_mode, RIT_MODE_TWICE,
            "显式传入 RIT_MODE_TWICE 的建桌必须落为桌面 RIT 策略"
        );
    }

    #[test]
    fn dispatch_create_table_rejects_unknown_rit_mode_atomically() {
        let ctx = make_context();
        let mut table = make_table();
        table.pot = 999; // 失败标记：拒绝后桌台必须原样保留
        let args = CreateTableArgs {
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
            rit_mode: 3, // 非协议常量
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
        assert!(result.is_err());
        assert_eq!(table.pot, 999, "rit_mode 校验失败不得覆写桌台");
    }

    #[test]
    fn create_table_args_reject_legacy_payload_fail_closed() {
        // 严格编码：v34 前的旧载荷（5 字段：name String + 3 规则字段 +
        // rit_mode）必须反序列化失败——新 schema 无 String 字段，legacy 字节
        // 无法精确对齐，尾随垃圾按 borsh 纪律 fail-closed。
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&6u32.to_le_bytes()); // String len
        legacy.extend_from_slice(b"legacy"); // name bytes
        legacy.push(9); // max_players
        legacy.extend_from_slice(&25u64.to_le_bytes()); // small_blind
        legacy.extend_from_slice(&50u64.to_le_bytes()); // big_blind
        legacy.push(RIT_MODE_DISABLED);
        assert!(borsh::from_slice::<CreateTableArgs>(&legacy).is_err());

        // 走完整 dispatch 也必须被拒，且不覆写桌台。
        let ctx = make_context();
        let mut table = make_table();
        table.pot = 999; // 失败标记：拒绝后桌台必须原样保留
        dispatch(&ctx, &mut table, &selectors::create_table(), &legacy).unwrap_err();
        assert_eq!(table.pot, 999);

        // 新 4 字段编码正常解码；rit_mode=DISABLED 建桌成功且不开启 RIT。
        let mut strict = Vec::new();
        strict.push(9); // max_players
        strict.extend_from_slice(&25u64.to_le_bytes()); // small_blind
        strict.extend_from_slice(&50u64.to_le_bytes()); // big_blind
        strict.push(RIT_MODE_DISABLED);
        let decoded: CreateTableArgs = borsh::from_slice(&strict).unwrap();
        assert_eq!(decoded.rit_mode, RIT_MODE_DISABLED);
        dispatch(&ctx, &mut table, &selectors::create_table(), &strict).unwrap();
        assert_eq!(table.max_players, 9);
        assert_eq!(table.rules.rit_mode, RIT_MODE_DISABLED);

        // 尾随垃圾（超出 4 字段）仍按 borsh 尾随纪律拒绝。
        let mut trailing = strict.clone();
        trailing.extend_from_slice(&[0, 7]);
        assert!(borsh::from_slice::<CreateTableArgs>(&trailing).is_err());
    }

    #[test]
    fn dispatch_join_table_then_leave_table() {
        let mut table = make_table();
        // P0-2：join_table 校验 caller == player，故 player 须用自己的 context 调用。
        let player_addr: Address = [0x11; 20];
        let ctx_p1 = make_context_as(player_addr);
        // WAITING 状态允许 join_table
        let join_args = join_args(player_addr, 1000, 1);
        let join_bytes = borsh::to_vec(&join_args).unwrap();
        dispatch(&ctx_p1, &mut table, &selectors::join_table(), &join_bytes).unwrap();
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].stack(), 1000);

        // leave_table（seat 0 的玩家本人调用）
        let leave_args = LeaveTableArgs { seat_index: 0 };
        let leave_bytes = borsh::to_vec(&leave_args).unwrap();
        dispatch(&ctx_p1, &mut table, &selectors::leave_table(), &leave_bytes).unwrap();
        assert_eq!(table.occupied_count(), 0);
    }

    #[test]
    fn join_table_allows_sub_big_blind_buy_in() {
        // 买入下限只在游戏层入座接受点（SIT_DOWN_V2）校验；VM join_table
        // 不设下限——镜像每手开局对本手参与者重放 join_table，其中含续座
        // 玩家：split-pot 等常规路径留下的不足大盲筹码（95 < 100）必须能
        // 继续参与，否则镜像 bootstrap 拒载、整手 unprovable、牌桌开局
        // 死循环（2026-09-16）。托管恒等式不放松：stack = buy_in、
        // chip_pool 精确增加 buy_in。
        let player: Address = [0x33; 20];
        let ctx = make_context_as(player);
        let mut table = make_table(); // big_blind = 100
        let buy_in = 95u64;
        let pool_before = table.chip_pool;
        let join_bytes = borsh::to_vec(&join_args(player, buy_in, 3)).unwrap();
        dispatch(&ctx, &mut table, &selectors::join_table(), &join_bytes).unwrap();
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].stack(), buy_in);
        assert_eq!(table.chip_pool, pool_before + buy_in);
    }

    #[test]
    fn join_table_rejects_identity_key_and_invalid_ownership_proof_atomically() {
        let player = [0x11; 20];
        let context = make_context_as(player);

        let mut identity_table = make_table();
        let identity_before = identity_table.clone();
        let identity_args = JoinTableArgs {
            player,
            buy_in: 1_000,
            pk: ECPoint(g1_identity()),
            tx_pk: registered_tx_pk_fixture(),
            pk_ownership_proof: vec![0; 80],
        };
        let identity_error = dispatch(
            &context,
            &mut identity_table,
            &selectors::join_table(),
            &borsh::to_vec(&identity_args).unwrap(),
        )
        .expect_err("identity Mental Poker key must be rejected");
        assert!(identity_error.to_string().contains("cannot be identity"));
        assert_eq!(identity_table, identity_before);

        let mut proof_table = make_table();
        let proof_before = proof_table.clone();
        let mut invalid_proof_args = join_args(player, 1_000, 7);
        invalid_proof_args.pk_ownership_proof[0] ^= 1;
        let proof_error = dispatch(
            &context,
            &mut proof_table,
            &selectors::join_table(),
            &borsh::to_vec(&invalid_proof_args).unwrap(),
        )
        .expect_err("invalid Mental Poker key ownership proof must be rejected");
        assert!(proof_error.to_string().contains("ownership proof"));
        assert_eq!(proof_table, proof_before);
    }

    #[test]
    fn dispatch_leave_table_rejects_pool_underflow_without_mutation() {
        let player: Address = [0x11; 20];
        let context = make_context_as(player);
        let mut table = make_table();
        table.seats[0].fixture_set_player(player);
        table.seats[0].set_stack(10).unwrap();
        table.seats[0].set_pending_addon(5).unwrap();
        table.chip_pool = 9;
        let before = table.clone();
        let mut events = vec![];
        let args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();

        let error = dispatch_leave_table(&context, &mut table, &args, &mut events).unwrap_err();

        assert!(error.to_string().contains("chip_pool underflow"));
        assert_eq!(table, before, "failed refund must be atomic");
        assert!(events.is_empty());
    }

    /// 端到端：active fresh-deck lifecycle through both player shuffles.
    ///
    /// 验证 retired `join_and_shuffle` 的完整替代链通过 dispatch 路由串联：
    /// 1. `create_table` 覆写桌台为初始 WAITING 状态
    /// 2. `join_table` 让 2 名玩家入座（pk 必须不同，避免 is_pk_registered 冲突）
    /// 3. `start_hand` 投盲注 + 设置加密牌组 + 进入 shuffle 阶段
    /// 4. `submit_shuffle_v2` 由每名 contributor 对本手 fresh deck 各执行一次
    /// 5. `reset_for_next_hand` 清理状态回到 WAITING（模拟一局结束后的重置）
    #[test]
    fn e2e_full_hand_lifecycle_create_join_start_reset() {
        // P0-2：create_table/start_hand/reset 需 creator 权限；join 需 player 本人。
        let ctx_creator = make_context(); // caller = [0xAA;20] = make_table 的 creator
        let mut table = make_table();

        // ========== Step 1: create_table ==========
        let create_args = CreateTableArgs {
            max_players: 2,
            small_blind: 10,
            big_blind: 20,
            rit_mode: RIT_MODE_DISABLED,
        };
        let create_bytes = borsh::to_vec(&create_args).unwrap();
        dispatch(
            &ctx_creator,
            &mut table,
            &selectors::create_table(),
            &create_bytes,
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 1);

        // 验证 WAITING 状态 + 参数已设置
        assert_eq!(table.max_players, 2);
        assert_eq!(table.small_blind, 10);
        assert_eq!(table.big_blind, 20);
        assert_eq!(table.round_state(), super::super::constants::ROUND_WAITING);
        assert_eq!(table.occupied_count(), 0);
        assert_eq!(table.pot, 0);

        // ========== Step 2a: join_table player 1 ==========
        let p1: Address = [0x11; 20];
        let join1 = join_args(p1, 1000, 1);
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join1).unwrap(),
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 2);
        assert_eq!(table.occupied_count(), 1);
        assert_eq!(table.seats[0].player(), [0x11; 20]);
        assert_eq!(table.seats[0].stack(), 1000);

        // ========== Step 2b: join_table player 2（pk 必须不同）==========
        let p2: Address = [0x22; 20];
        let join2 = join_args(p2, 2000, 2);
        dispatch(
            &make_context_as(p2),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join2).unwrap(),
        )
        .unwrap();
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 3);
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.seats[1].player(), [0x22; 20]);
        assert_eq!(table.seats[1].stack(), 2000);

        // ========== Step 3: start_hand（creator 发起）==========
        dispatch(&ctx_creator, &mut table, &selectors::start_hand(), &[]).unwrap();
        assert_eq!(table.hand_id, 1, "HandStarted 后 hand_id 应递增");
        assert_eq!(table.call_seq, 4);

        // 验证：进入 SHUFFLE 阶段，加密牌组已初始化（52 张）。
        //
        // 注意：start_hand 不会立即改变 round_state（仍为 ROUND_WAITING），
        // 因为 round_state 仅在下注阶段开始时切换到 ROUND_PREFLOP。
        // 对局已开始的标志是 shuffle_state.phase == SHUFFLE_PHASE_BEFORE_PREFLOP
        // 且 deck_state.encrypted 已填充 52 张加密牌。
        assert_eq!(
            table.shuffle_phase(),
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP,
            "start_hand 后应进入 shuffle BEFORE_PREFLOP 阶段"
        );
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "start_hand 应设置 52 张加密牌"
        );

        // ========== Step 4: submit_shuffle_v2 ×2 ==========
        // Unit tests compile with the explicit test-only native verifier bypass, but still execute
        // the exact active state transition, contributor ordering, deck replacement and task path.
        for (seat_index, player) in [(0, p1), (1, p2)] {
            assert_eq!(table.shuffle_state().derived_current_shuffler(), seat_index);
            let shuffle_args = SubmitShuffleV2Args {
                seat_index,
                output_cards: table.deck_state.encrypted.to_vec(),
                shuffle_proof: empty_shuffle_proof(),
            };
            let result = dispatch(
                &make_context_as(player),
                &mut table,
                &selectors::submit_shuffle_v2(),
                &borsh::to_vec(&shuffle_args).unwrap(),
            )
            .unwrap();
            let task = decode_output(&result)
                .prove_task
                .expect("active shuffle transition must produce a proof task");
            assert_eq!(task.method_kind, CanonicalCommand::SubmitShuffleV2 as u8);
        }
        assert_eq!(table.call_seq, 6);
        assert_ne!(
            table.shuffle_phase(),
            super::super::constants::SHUFFLE_PHASE_BEFORE_PREFLOP,
            "all contributors completing their active shuffle must advance the hand"
        );

        // ========== Step 5: settlement 内部 reset_for_next_hand ==========
        let mut reset_events = Vec::new();
        state_machine::reset_for_next_hand(&mut table, &mut reset_events).unwrap();
        assert_eq!(table.hand_id, 1, "局内后续调用不应改变 hand_id");
        assert_eq!(table.call_seq, 6, "内部 normalization 不创建外部调用序号");

        // 验证：回到 WAITING 状态，所有对局状态清理
        assert_eq!(table.round_state(), super::super::constants::ROUND_WAITING);
        assert_eq!(table.pot, 0, "reset 后 pot 应清零");
        assert_eq!(table.community_cards.len(), 0);
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "reset 后重新初始化 52 张牌"
        );
        assert_eq!(
            table.shuffle_phase(),
            super::super::constants::SHUFFLE_PHASE_NONE,
            "reset 后 shuffle 阶段应清零"
        );
        assert_eq!(
            table.reveal_phase(),
            super::super::constants::REVEAL_PHASE_NONE
        );
        assert_eq!(
            table.reconstruct_phase(),
            super::super::constants::RECONSTRUCT_PHASE_NONE
        );
        // 玩家仍在座位上（reset 不踢人，除非 stack=0）
        assert_eq!(table.occupied_count(), 2, "reset 不应踢出有筹码的玩家");
        assert_eq!(table.seats[0].stack(), 1000);
        assert_eq!(table.seats[1].stack(), 2000);
        // bet/total_bet 应清零
        assert_eq!(table.seats[0].bet(), 0);
        assert_eq!(table.seats[0].total_bet(), 0);
        assert_eq!(table.seats[1].bet(), 0);
        assert_eq!(table.seats[1].total_bet(), 0);
    }

    #[test]
    fn dispatch_kick_player_marks_seat() {
        let ctx = make_context();
        let mut table = make_table();
        // 设置 3 个玩家，确保 kick 后不触发 reset_for_next_hand
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(500).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        table.seats[2].fixture_set_player([0x03; 20]);
        table.seats[2].set_stack(500).unwrap();
        table.seats[2].set_status(SeatStatus::Active);
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 0),
                1,
                0,
            )
            .unwrap();
        table.arm_betting_deadline(ctx.block_timestamp).unwrap();
        table.chip_pool = 1_500;

        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        dispatch(&ctx, &mut table, &selectors::kick_player_v2(), &args_bytes).unwrap();
        assert!(table.seats[0].is_folded() || table.seats[0].has_left_hand());
        assert!(table.seats[0].has_left_hand());
        assert_eq!(table.seats[0].stack(), 0);
    }

    #[test]
    fn dispatch_advance_deadline_does_not_start_hand_without_a_deadline() {
        let ctx = make_context();
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        // WAITING is blocked on the explicit StartHand command, not on time.
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]).unwrap();
        let output = decode_output(&result);
        assert!(output.prove_task.is_none());
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 0);
        assert_eq!(table.round_state(), super::super::constants::ROUND_WAITING);
        assert_eq!(
            table.shuffle_phase(),
            super::super::constants::SHUFFLE_PHASE_NONE
        );
    }

    #[test]
    fn dispatch_advance_deadline_without_state_change_has_no_task_or_sequence_increment() {
        let ctx = make_context();
        let mut table = make_table();
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]).unwrap();
        let output = decode_output(&result);
        assert!(output.prove_task.is_none());
        assert_eq!(table.hand_id, 0);
        assert_eq!(table.call_seq, 0);
    }

    #[test]
    fn dispatch_advance_deadline_rejects_unarmed_active_state() {
        let ctx = make_context();
        let mut table = make_table();
        table
            .enter_initial_shuffling(
                super::super::types::ShuffleState {
                    pending_mask: 1,
                    completed_mask: 0,
                },
                0,
            )
            .unwrap();
        let pre = table.clone();
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]);
        assert!(result.is_err());
        assert_eq!(
            table, pre,
            "deadline consumption must never arm legacy state"
        );
    }

    #[test]
    fn dispatch_advance_deadline_rejects_every_timestamp_payload() {
        let ctx = make_context();
        let mut table = make_table();
        let args_bytes = borsh::to_vec(&5_000_000u64).unwrap();
        let result = dispatch(
            &ctx,
            &mut table,
            &selectors::advance_deadline(),
            &args_bytes,
        );
        assert!(result.is_err());
        assert_eq!(table, make_table());
    }

    fn make_auto_fold_table() -> TexasPokerTable {
        let mut table = make_table();
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                0,
                0,
            )
            .unwrap();
        for index in 0..3 {
            table.seats[index].fixture_set_player([u8::try_from(index + 1).unwrap(); 20]);
            table.seats[index].set_stack(1_000).unwrap();
            table.seats[index].set_status(SeatStatus::Active);
        }
        table
    }

    #[test]
    fn dispatch_advance_deadline_is_noop_before_consensus_timeout() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.arm_betting_deadline(ctx.block_timestamp - 1).unwrap();
        let pre = table.clone();
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]);

        let output = decode_output(&result.expect("early deadline advance is an idempotent no-op"));
        assert!(output.prove_task.is_none());
        assert_eq!(table, pre);
    }

    #[test]
    fn dispatch_advance_deadline_is_noop_while_time_bank_remains() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.arm_betting_deadline(1).unwrap();
        table.seats[0].set_time_bank_ms(1);
        let pre = table.clone();
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]);

        let output = decode_output(&result.expect("time-bank consumption is normalized in-place"));
        assert!(output.prove_task.is_some());
        assert_ne!(table, pre);
        assert_eq!(table.seats[0].time_bank_ms(), 0);
        assert!(!table.seats[0].is_folded());
    }

    #[test]
    fn dispatch_advance_deadline_accepts_expired_turn_without_time_bank() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.arm_betting_deadline(1).unwrap();
        table.seats[0].set_time_bank_ms(0);
        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]);

        assert!(result.is_ok());
        assert!(table.seats[0].is_folded());
        assert_eq!(table.call_seq, 1);
    }

    #[test]
    fn dispatch_advance_deadline_lowers_to_the_tick_proof_tag() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.arm_betting_deadline(1).unwrap();
        table.seats[0].set_time_bank_ms(0);

        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]).unwrap();
        let task = decode_output(&result)
            .prove_task
            .expect("expired deadline must emit a proof task");

        assert!(table.seats[0].is_folded());
        assert_eq!(task.method_kind, CanonicalCommand::AdvanceDeadline as u8);
        assert!(task.raw_args.is_empty());
    }

    #[test]
    fn dispatch_advance_deadline_rejects_legacy_timestamp_payload() {
        let ctx = make_context();
        let mut table = make_auto_fold_table();
        table.arm_betting_deadline(1).unwrap();
        table.seats[0].set_time_bank_ms(0);
        let pre = table.clone();
        let args = borsh::to_vec(&ctx.block_timestamp).unwrap();

        let result = dispatch(&ctx, &mut table, &selectors::advance_deadline(), &args);

        assert!(result.is_err());
        assert_eq!(
            table, pre,
            "non-canonical payload must be rejected atomically"
        );
    }

    // ========== P0-1 / P0-2 回归测试 ==========

    /// P0-2：非座位玩家调用 fold 应被拒绝。
    #[test]
    fn dispatch_fold_rejects_non_seat_player() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                0,
                0,
            )
            .unwrap();

        // seat 0 的玩家是 [0x01;20]，用 [0x99;20] 冒充调用应失败
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::fold(),
            &args_bytes,
        );
        assert!(result.is_err(), "非座位玩家不应能 fold 别人的牌");
    }

    #[test]
    fn player_command_rejects_claimed_seat_different_from_authenticated_caller_seat() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1_000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1_000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                0,
                0,
            )
            .unwrap();
        table.arm_betting_deadline(1).unwrap();
        let before = table.clone();

        let error = dispatch(
            &make_context_as([0x01; 20]),
            &mut table,
            &selectors::fold(),
            &borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("authenticated caller seat 0"));
        assert_eq!(table, before, "actor mismatch must be rejected atomically");
    }

    #[test]
    fn proof_input_lowering_omits_actor_and_rejects_legacy_actor_bytes() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        let context = make_context_as([0x01; 20]);
        let raw_args = borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap();

        assert!(derive_method_input(CanonicalCommand::Fold as u8, &raw_args).is_err());
        let error = derive_authenticated_method_input(
            CanonicalCommand::Fold as u8,
            &raw_args,
            &context,
            &table,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("canonical payload must be empty")
        );

        let input =
            derive_authenticated_method_input(CanonicalCommand::Fold as u8, &[], &context, &table)
                .unwrap();
        assert_eq!(
            input,
            super::super::prove_task::MethodInput::SeatOnly { seat_index: 0 }
        );
    }

    #[test]
    fn canonical_payload_physically_omits_derivable_actor_fields() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        let context = make_context_as([0x01; 20]);

        let fold_legacy = borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap();
        let (fold_tag, fold_canonical) =
            canonical_command_parts(&selectors::fold(), &fold_legacy).unwrap();
        assert!(fold_canonical.is_empty());
        assert_eq!(
            replay_dispatch_args(fold_tag, &fold_canonical, &context, &table).unwrap(),
            fold_legacy
        );

        let raise_legacy = borsh::to_vec(&RaiseArgs {
            seat_index: 0,
            total_bet: 500,
        })
        .unwrap();
        let (raise_tag, raise_canonical) =
            canonical_command_parts(&selectors::raise(), &raise_legacy).unwrap();
        assert_eq!(raise_canonical.len(), std::mem::size_of::<u64>());
        assert_eq!(
            replay_dispatch_args(raise_tag, &raise_canonical, &context, &table).unwrap(),
            raise_legacy
        );

        let join_legacy = borsh::to_vec(&join_args([0x02; 20], 1_000, 2)).unwrap();
        let (_, join_canonical) =
            canonical_command_parts(&selectors::join_table(), &join_legacy).unwrap();
        assert_eq!(join_canonical.len() + 20, join_legacy.len());
    }

    /// P0-2：非 creator 调用 kick_player 应被拒绝。
    #[test]
    fn dispatch_kick_rejects_non_creator() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();

        // make_table 的 creator = [0xAA;20]，用 [0x99;20] 调用应失败
        let ctx_non_creator = make_context_as([0x99; 20]);
        let args = SeatIndexArgs { seat_index: 0 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_non_creator,
            &mut table,
            &selectors::kick_player_v2(),
            &args_bytes,
        );
        assert!(result.is_err(), "非 creator 不应能 kick 玩家");
    }

    /// P0-1：kick_player 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn dispatch_kick_rejects_out_of_range_seat() {
        let ctx = make_context(); // caller = [0xAA;20] = creator
        let mut table = make_table(); // max_players = 6
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();

        // seat_index=200 远超 max_players=6，应返回 Err 而非 panic
        let args = SeatIndexArgs { seat_index: 200 };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(&ctx, &mut table, &selectors::kick_player_v2(), &args_bytes);
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    // ========== set_leave_after_hand 单元测试 ==========

    /// 辅助：构造一个已入座的 table（seat 0 = p1，seat 1 = p2）。
    fn make_table_with_two_players() -> TexasPokerTable {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x11; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x22; 20]);
        table.seats[1].set_stack(2000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        // 同步 chip_pool（join 时 buy_in 计入），便于后续资金账断言
        table.chip_pool = 3000;
        table
    }

    /// 显式幂等测试：重复设置 true 为 no-op，再显式设置 false 取消预约。
    #[test]
    fn set_leave_is_explicit_and_idempotent() {
        let mut table = make_table_with_two_players();
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = SetLeaveAfterHandArgs {
            seat_index: 0,
            want_leave: true,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();

        // 第一次：false → true（预约离场）
        let first = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::set_leave_after_hand(),
            &args_bytes,
        )
        .unwrap();
        let first_task = decode_output(&first)
            .prove_task
            .expect("set_leave_after_hand 状态变化必须产生 task");
        assert_eq!(first_task.method_kind, 21);
        assert_eq!(
            first_task.method_input().unwrap(),
            super::super::prove_task::MethodInput::SetLeaveAfterHand {
                seat_index: 0,
                want_leave: true,
            }
        );
        assert_eq!(first_task.call_seq, 1);
        assert!(
            table.seat_wants_leave(0),
            "第一次调用后 want_leave 应为 true"
        );

        // 第二次重复设置 true：幂等 no-op，不推进 call_seq，也不产生 proof task。
        let second = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::set_leave_after_hand(),
            &args_bytes,
        )
        .unwrap();
        assert_eq!(table.call_seq, 1);
        assert!(decode_output(&second).prove_task.is_none());
        assert!(table.seat_wants_leave(0));

        // 第三次显式设置 false：取消预约并产生第二个状态转换。
        dispatch(
            &ctx_p1,
            &mut table,
            &selectors::set_leave_after_hand(),
            &borsh::to_vec(&SetLeaveAfterHandArgs {
                seat_index: 0,
                want_leave: false,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(table.call_seq, 2);
        assert!(
            !table.seat_wants_leave(0),
            "显式取消后 want_leave 应为 false"
        );

        // 其余座位不受影响
        assert!(!table.seat_wants_leave(1));
    }

    /// 权限校验：非 seat player 调用应失败。
    #[test]
    fn set_leave_rejects_non_seat_player() {
        let mut table = make_table_with_two_players();
        // seat 0 玩家是 [0x11;20]，用 [0x99;20] 冒充调用应失败
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = SetLeaveAfterHandArgs {
            seat_index: 0,
            want_leave: true,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::set_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_err(), "非座位玩家不应能为他人的座位预约离场");
        assert!(
            !table.seat_wants_leave(0),
            "失败调用不应改变 want_leave 标志"
        );
    }

    /// 对局中调用：在 ROUND_PREFLOP 状态调用应成功（验证「任意时刻可预约」）。
    #[test]
    fn set_leave_works_mid_hand() {
        let mut table = make_table_with_two_players();
        // 模拟对局进行中
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                0,
                0,
            )
            .unwrap();

        let ctx_p1 = make_context_as([0x11; 20]);
        table.arm_betting_deadline(ctx_p1.block_timestamp).unwrap();
        let args = SetLeaveAfterHandArgs {
            seat_index: 0,
            want_leave: true,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::set_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_ok(), "对局中应可预约离场: {result:?}");
        assert!(table.seat_wants_leave(0));
        // 对局状态不被破坏
        assert_eq!(table.round_state(), super::super::constants::ROUND_PREFLOP);
    }

    /// 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn set_leave_rejects_out_of_range_seat() {
        let mut table = make_table_with_two_players();
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = SetLeaveAfterHandArgs {
            seat_index: 200,
            want_leave: true,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::set_leave_after_hand(),
            &args_bytes,
        );
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    /// reset_for_next_hand 强制执行：设置 want_leave → reset → seat 清空 + chip_pool 扣减。
    #[test]
    fn reset_for_next_hand_enforces_want_leave() {
        let mut table = make_table_with_two_players();
        // p1 预约离场
        table.set_seat_wants_leave(0, true);

        // reset 前：2 名玩家，chip_pool = 3000
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.chip_pool, 3000);

        state_machine::reset_for_next_hand(&mut table, &mut Vec::new()).unwrap();

        // reset 后：seat 0 被清空（退款 1000），seat 1 保留
        assert_eq!(table.occupied_count(), 1, "want_leave 玩家应被踢出");
        assert_eq!(table.seats[0].player(), super::super::types::EMPTY_PLAYER);
        assert_eq!(table.seats[0].stack(), 0);
        assert_eq!(table.seats[1].player(), [0x22; 20], "未预约的玩家应保留");
        assert_eq!(table.seats[1].stack(), 2000);
        // chip_pool 扣减退款（3000 - 1000 = 2000）
        assert_eq!(table.chip_pool, 2000, "chip_pool 应扣减已退款的 stack");
    }

    /// 资金账平衡 + 事件：join (buy_in=X) → set_leave → reset
    /// → 退款 X 后 chip_pool 回到 join 前，并发出 PlayerRefund + PlayerLeft。
    #[test]
    fn set_leave_full_lifecycle_refund_and_events() {
        let ctx_creator = make_context(); // caller = [0xAA;20] = creator
        let mut table = make_table();

        // create_table（creator 发起）
        let create_args = CreateTableArgs {
            max_players: 4,
            small_blind: 10,
            big_blind: 20,
            rit_mode: RIT_MODE_DISABLED,
        };
        dispatch(
            &ctx_creator,
            &mut table,
            &selectors::create_table(),
            &borsh::to_vec(&create_args).unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 0, "create_table 后 chip_pool 应为 0");

        // p1 join_table（buy_in = 1500）
        let p1: Address = [0x11; 20];
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join_args(p1, 1500, 1)).unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 1500);

        // p2 join_table（buy_in = 2500）
        let p2: Address = [0x22; 20];
        dispatch(
            &make_context_as(p2),
            &mut table,
            &selectors::join_table(),
            &borsh::to_vec(&join_args(p2, 2500, 2)).unwrap(),
        )
        .unwrap();
        assert_eq!(table.chip_pool, 4000);

        // p1 预约离场（任意时刻，此处 WAITING 状态）
        dispatch(
            &make_context_as(p1),
            &mut table,
            &selectors::set_leave_after_hand(),
            &borsh::to_vec(&SetLeaveAfterHandArgs {
                seat_index: 0,
                want_leave: true,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(table.seat_wants_leave(0));

        // reset：强制执行 p1 离场
        let mut events = Vec::new();
        state_machine::reset_for_next_hand(&mut table, &mut events).unwrap();

        // 资金账：chip_pool 扣减退款 1500 → 4000 - 1500 = 2500
        assert_eq!(table.chip_pool, 2500);
        assert_eq!(table.seats[0].player(), super::super::types::EMPTY_PLAYER);
        assert_eq!(table.seats[1].player(), p2);

        // 事件：应包含 PlayerRefund(seat 0, 1500) + PlayerLeft(seat 0)
        let has_refund = events.iter().any(|e| {
            matches!(
                e,
                super::super::events::TexasPokerEvent::PlayerRefund {
                    seat_index: 0,
                    amount: 1500,
                    ..
                }
            )
        });
        let has_left = events.iter().any(|e| {
            matches!(
                e,
                super::super::events::TexasPokerEvent::PlayerLeft { seat_index: 0, .. }
            )
        });
        assert!(has_refund, "应发出 seat 0 的 PlayerRefund(1500) 事件");
        assert!(has_left, "应发出 seat 0 的 PlayerLeft 事件");
    }

    /// want_leave=false 的玩家在 reset 后不应被踢出（回归：不应误清）。
    #[test]
    fn reset_does_not_remove_players_without_leave_request() {
        let mut table = make_table_with_two_players();
        // 无人预约离场
        assert!(!table.seat_wants_leave(0));
        assert!(!table.seat_wants_leave(1));

        state_machine::reset_for_next_hand(&mut table, &mut Vec::new()).unwrap();

        // 两名玩家都应保留（stack > 0）
        assert_eq!(table.occupied_count(), 2);
        assert_eq!(table.seats[0].player(), [0x11; 20]);
        assert_eq!(table.seats[1].player(), [0x22; 20]);
    }

    // ========== fold_with_proof 单元测试 ==========

    /// 辅助：构造一个处于下注轮、3 名玩家的桌台。
    /// - seat 0/1/2 各有 stack 与已下注 total_bet
    /// - round_state = PREFLOP，betting_round 已设置，current_turn = turn
    /// - contributor mask covers every protocol participant and derives the aggregate key
    fn make_betting_table_with_players(turn: u8, set_aggregated_pk: bool) -> TexasPokerTable {
        let mut table = make_table();
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                turn,
                0,
            )
            .unwrap();
        table
            .arm_betting_deadline(make_context().block_timestamp)
            .unwrap();

        // 3 名玩家，pk 都用 generator；lineage 是 canonical fact，aggregate 由其派生。
        let g = g1_generator();
        for i in 0..3u8 {
            table.seats[i as usize].fixture_set_player([0x11 + i; 20]);
            table.seats[i as usize].set_stack(1000).unwrap();
            table.seats[i as usize].fixture_set_total_bet(100);
            table.seats[i as usize].fixture_set_pk(ECPoint(g));
            table.seats[i as usize].set_status(SeatStatus::Active);
        }
        if set_aggregated_pk {
            table.deck_state.contributor_mask = 0b111;
            table.derived_aggregated_pk().unwrap();
        }
        // 模拟已发牌（52 张加密牌），c1 = generator（DLEq verify 强制 c1 不变）
        table.deck_state.encrypted = (0..52)
            .map(|_| ElGamalCiphertext {
                c1: g,
                c2: g, // 占位，skip_remask=true 不验证
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        table
    }

    /// 辅助：构造一个空的 DLEqProof<LeaveKind>（skip_remask=true 时不会真正验证）。
    fn empty_fold_proof() -> DLEqProof<DefaultCurve, LeaveKind> {
        // _kind 字段私有，必须用 from_parts 构造（DLEqProof 不 derive Default）。
        // skip_remask=true（默认 dev config）时 verify 不执行，字段值不影响测试。
        // 零标量复用 utils::scalar_zero()（封装了 ff::Field trait 的 ZERO 常量）。
        let zero = super::super::utils::scalar_zero();
        DLEqProof::from_parts(
            vec![],        // per_card_commitments
            g1_identity(), // commitment_pk（C::Point）
            zero,          // response（C::Scalar = BlsScalar）
            zero,          // nonce（C::Scalar = BlsScalar）
        )
    }

    fn empty_schnorr_proof()
    -> poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<DefaultCurve>
    {
        poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof {
            commitment: g1_identity(),
            responses: vec![],
        }
    }

    fn empty_shuffle_proof() -> ShuffleProof {
        let schnorr = empty_schnorr_proof();
        let legacy = poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof {
            sum_c1_commit: g1_identity(),
            sum_c2_commit: g1_identity(),
            combined_schnorr_proof: schnorr.clone(),
            sum_c1_schnorr_proof: schnorr.clone(),
            sum_c2_schnorr_proof: schnorr,
            nonce: super::super::utils::scalar_zero(),
        };
        ShuffleProof::LegacyV1(legacy)
    }

    fn empty_reconstruct_v3() -> (
        ReconstructionStatement<DefaultCurve>,
        ReconstructProof<DefaultCurve>,
    ) {
        use poker_protocol::zk_shuffle::bayer_groth::{
            BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
        };
        use poker_protocol::zk_shuffle::reconstruction::{
            CrossKeyNegationProof, SlotContributionOrProof,
        };

        let zero = super::super::utils::scalar_zero();
        let identity = g1_identity();
        let generator = super::super::utils::g1_generator();
        let aggregate_pk = generator * super::super::utils::scalar_from_u64(17);
        let owner_pk = generator * super::super::utils::scalar_from_u64(19);
        let cards = vec![
            generator * super::super::utils::scalar_from_u64(23),
            generator * super::super::utils::scalar_from_u64(29),
        ];
        let identity_ciphertext = ElGamalCiphertext {
            c1: identity,
            c2: identity,
        };
        // `build_method_input` validates the strict V3 wire shape even though
        // these dispatch tests never execute the proof. Use a structurally
        // valid public statement and keep only the proof equations as dummies.
        let readable_ciphertext = ElGamalCiphertext::encrypt(
            &cards[0],
            &owner_pk,
            &super::super::utils::scalar_from_u64(31),
        );
        let contributions = vec![
            ElGamalCiphertext::encrypt(
                &identity,
                &aggregate_pk,
                &super::super::utils::scalar_from_u64(37),
            ),
            ElGamalCiphertext::encrypt(
                &identity,
                &aggregate_pk,
                &super::super::utils::scalar_from_u64(41),
            ),
        ];
        let contribution_shuffle_proof = BayerGrothShuffleProof {
            c_permutation: identity,
            c_permuted_powers: identity,
            multi_exponentiation: MultiExponentiationArgument {
                c_alpha: identity,
                c_beta: identity,
                ciphertext_0: identity_ciphertext,
                ciphertext_1: identity_ciphertext,
                alpha_response: vec![zero; 2],
                commitment_response: zero,
                beta: zero,
                beta_blinding_response: zero,
                rerandomization_response: zero,
            },
            product: ProductArgument {
                c_d: identity,
                c_delta: identity,
                c_capital_delta: identity,
                a_response: vec![zero; 2],
                b_response: vec![zero; 2],
                r_response: zero,
                s_response: zero,
            },
        };
        let statement = ReconstructionStatement {
            version: 3,
            context_digest: [0; 32],
            reconstruction_epoch: 0,
            prior_state_digest: [0; 32],
            aggregate_pk,
            owner_pk,
            cards,
            residual_carriers: vec![readable_ciphertext],
            contributions,
        };
        let cross_key = CrossKeyNegationProof {
            commitment_owner_key: identity,
            commitment_contribution_c1: identity,
            commitment_joint_c2: identity,
            response_owner_sk: zero,
            response_contribution_randomness: zero,
        };
        let slot = SlotContributionOrProof {
            commitment_g: [identity; 2],
            commitment_pk: [identity; 2],
            challenges: [zero; 2],
            responses: [zero; 2],
        };
        let proof = ReconstructProof {
            negative_contributions: vec![identity_ciphertext],
            cross_key_proofs: vec![cross_key],
            contribution_shuffle_proof,
            slot_membership_proofs: vec![slot; 2],
        };
        (statement, proof)
    }

    fn active_crypto_args() -> Vec<([u8; 32], Vec<u8>, u8)> {
        let shuffle = SubmitShuffleV2Args {
            seat_index: 3,
            output_cards: vec![],
            shuffle_proof: empty_shuffle_proof(),
        };
        let reveal = SubmitRevealTokensArgs {
            seat_index: 4,
            reveal_tokens: vec![],
            proofs: vec![],
        };
        let (statement, proof) = empty_reconstruct_v3();
        let reconstruct = SubmitReconstructDeckArgs {
            seat_index: 5,
            statement,
            proof,
        };
        let fold = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        vec![
            (
                selectors::submit_shuffle_v2(),
                borsh::to_vec(&shuffle).unwrap(),
                17,
            ),
            (
                selectors::submit_player_reveal_tokens(),
                borsh::to_vec(&reveal).unwrap(),
                18,
            ),
            (
                selectors::submit_reconstruct_deck(),
                borsh::to_vec(&reconstruct).unwrap(),
                19,
            ),
            (
                selectors::fold_with_proof(),
                borsh::to_vec(&fold).unwrap(),
                22,
            ),
        ]
    }

    #[test]
    fn build_method_input_covers_remaining_internal_selectors() {
        let mut cases = vec![
            (
                selectors::create_table(),
                borsh::to_vec(&CreateTableArgs {
                    max_players: 6,
                    small_blind: 50,
                    big_blind: 100,
                    rit_mode: RIT_MODE_DISABLED,
                })
                .unwrap(),
                0,
            ),
            (
                selectors::join_table(),
                borsh::to_vec(&join_args([0x41; 20], 1_000, 1)).unwrap(),
                1,
            ),
            (
                selectors::leave_table(),
                borsh::to_vec(&LeaveTableArgs { seat_index: 1 }).unwrap(),
                2,
            ),
            (selectors::start_hand(), vec![], 3),
            (selectors::advance_deadline(), vec![], 4),
            (
                selectors::fold(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                6,
            ),
            (
                selectors::check(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                7,
            ),
            (
                selectors::call(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                8,
            ),
            (
                selectors::raise(),
                borsh::to_vec(&RaiseArgs {
                    seat_index: 1,
                    total_bet: 200,
                })
                .unwrap(),
                9,
            ),
            (
                selectors::force_fold(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                11,
            ),
            (
                selectors::kick_player_v2(),
                borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap(),
                12,
            ),
            (
                selectors::addon(),
                borsh::to_vec(&AddonArgs {
                    seat_index: 1,
                    amount: 500,
                })
                .unwrap(),
                13,
            ),
            (
                selectors::rebuy(),
                borsh::to_vec(&RebuyArgs {
                    seat_index: 1,
                    amount: 500,
                })
                .unwrap(),
                14,
            ),
            (
                selectors::bet(),
                borsh::to_vec(&BetArgs {
                    seat_index: 1,
                    amount: 100,
                })
                .unwrap(),
                20,
            ),
            (
                selectors::set_leave_after_hand(),
                borsh::to_vec(&SetLeaveAfterHandArgs {
                    seat_index: 1,
                    want_leave: true,
                })
                .unwrap(),
                21,
            ),
        ];
        cases.extend(active_crypto_args());
        assert_eq!(cases.len(), 19);
        for (selector, args, expected_kind) in cases {
            let (kind, _) = build_method_input(&selector, &args).unwrap();
            assert_eq!(kind, expected_kind);
        }
    }

    #[test]
    fn crypto_canonical_payloads_omit_authenticated_actors_and_replay_exactly() {
        let mut table = make_table();
        for seat_index in 0..6 {
            table.seats[seat_index].fixture_set_player([0x40 + seat_index as u8; 20]);
            table.seats[seat_index].set_status(SeatStatus::Active);
        }
        for (selector, raw_args, expected_kind) in active_crypto_args() {
            let (kind, input) = build_method_input(&selector, &raw_args).unwrap();
            assert_eq!(kind, expected_kind);
            let seat_index = match input {
                super::super::prove_task::MethodInput::SubmitShuffleV2 { seat_index }
                | super::super::prove_task::MethodInput::SubmitPlayerRevealTokens { seat_index }
                | super::super::prove_task::MethodInput::SubmitReconstructDeck { seat_index }
                | super::super::prove_task::MethodInput::FoldWithProof { seat_index } => seat_index,
                other => panic!("crypto selector 映射到了错误 variant: {other:?}"),
            };
            assert!(seat_index < 6);
            let caller = [0x40 + seat_index; 20];
            let context = make_context_as(caller);
            let (canonical_kind, canonical_args) =
                canonical_command_parts(&selector, &raw_args).unwrap();
            assert_eq!(canonical_kind, expected_kind);
            assert_eq!(canonical_args.len() + 1, raw_args.len());
            assert_ne!(canonical_args, raw_args);
            assert_eq!(
                replay_dispatch_args(canonical_kind, &canonical_args, &context, &table).unwrap(),
                raw_args
            );
            let authenticated = derive_authenticated_method_input(
                canonical_kind,
                &canonical_args,
                &context,
                &table,
            )
            .unwrap();
            match authenticated {
                super::super::prove_task::MethodInput::SubmitShuffleV2 {
                    seat_index: derived,
                }
                | super::super::prove_task::MethodInput::SubmitPlayerRevealTokens {
                    seat_index: derived,
                }
                | super::super::prove_task::MethodInput::SubmitReconstructDeck {
                    seat_index: derived,
                }
                | super::super::prove_task::MethodInput::FoldWithProof {
                    seat_index: derived,
                } => assert_eq!(derived, seat_index),
                other => panic!("canonical crypto payload 映射到了错误 variant: {other:?}"),
            }
        }
    }

    #[test]
    fn reveal_wire_physically_omits_assignment_indices_and_rejects_old_shape() {
        #[derive(BorshSerialize)]
        struct RetiredRevealArgs {
            seat_index: u8,
            assignment_indices: Vec<u8>,
            reveal_tokens: Vec<ECPoint>,
            proofs: Vec<RevealTokenProof<DefaultCurve>>,
        }

        let current = borsh::to_vec(&SubmitRevealTokensArgs {
            seat_index: 4,
            reveal_tokens: vec![],
            proofs: vec![],
        })
        .unwrap();
        assert_eq!(current.len(), 1 + 4 + 4);

        let retired = borsh::to_vec(&RetiredRevealArgs {
            seat_index: 4,
            assignment_indices: vec![0],
            reveal_tokens: vec![],
            proofs: vec![],
        })
        .unwrap();
        assert!(
            build_method_input(&selectors::submit_player_reveal_tokens(), &retired).is_err(),
            "retired reveal payload with caller-selected assignment indices must fail closed"
        );
    }

    #[test]
    fn crypto_selectors_reject_seat_only_substitution() {
        let seat_only = borsh::to_vec(&SeatIndexArgs { seat_index: 1 }).unwrap();
        for (selector, _, _) in active_crypto_args() {
            assert!(
                build_method_input(&selector, &seat_only).is_err(),
                "crypto selector 不得把 SeatIndexArgs 当作完整参数"
            );
        }
    }

    /// 基本流程：下注中 → p1 fold_with_proof → folded=true + pk 已从 aggregated_pk 移除
    /// + deck 已替换 + reveal assignments 中无 p1（下注轮本就为空）+ total_bet 保留。
    #[test]
    fn fold_with_proof_basic_flow() {
        let mut table = make_betting_table_with_players(0, true);
        let agg_pk_before = table.derived_aggregated_pk().unwrap();
        let deck_before = table.deck_state.encrypted.clone();

        let ctx_p1 = make_context_as([0x11; 20]);
        // output_cards 用一个新的占位牌组（与 deck_before 不同，验证替换生效）
        let g = g1_generator();
        let output_cards: Vec<ElGamalCiphertext> = (0..52)
            .map(|_| ElGamalCiphertext {
                c1: g,
                c2: g + g, // 不同于 deck_before 的 c2=g
            })
            .collect();
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: output_cards.clone(),
            fold_proof: empty_fold_proof(),
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &args_bytes,
        )
        .unwrap();
        let task = decode_output(&result)
            .prove_task
            .expect("fold_with_proof 状态变化必须产生 task");
        assert_eq!(task.method_kind, 22);
        assert_eq!(task.call_seq, 1);
        assert_eq!(
            task.method_input().unwrap(),
            super::super::prove_task::MethodInput::FoldWithProof { seat_index: 0 }
        );

        // folded 标记
        assert!(table.seats[0].is_folded(), "folded 应为 true");
        assert!(table.seat_acted_this_round(0));
        // 关键：total_bet / bet / stack / pk 保留（side-pot 记账）
        assert_eq!(table.seats[0].total_bet(), 100, "total_bet 应保留");
        assert_eq!(table.seats[0].stack(), 1000, "stack 应保留");
        assert_eq!(
            table.seats[0].pk().copied(),
            Some(ECPoint(g1_generator())),
            "seat.pk 应保留（不置 identity）"
        );
        assert!(!table.seats[0].has_left_hand(), "left_during_hand 不应设置");

        // aggregated_pk 已移除 p1.pk（移除后可能为 None 或不同点）
        assert_ne!(
            table.derived_aggregated_pk().unwrap(),
            agg_pk_before,
            "aggregated_pk 应已移除 p1 的 pk"
        );

        // encrypted deck 已替换为 output_cards
        assert_eq!(
            table.deck_state.encrypted.len(),
            52,
            "deck 大小不变（52 张）"
        );
        assert_ne!(
            table.deck_state.encrypted[0].c2, deck_before[0].c2,
            "deck 应已被 output_cards 替换"
        );
        // c1 不变（DLEq 不变量）
        assert_eq!(table.deck_state.encrypted[0].c1, deck_before[0].c1);

        // reveal_token_state.assignments 中无 p1（下注轮本就为空）
        for a in table.reveal_assignments() {
            assert!(
                !super::super::types::seat_mask_contains(a.pending_mask(), 0),
                "p1 不应在任何 reveal pending_players 中"
            );
        }
    }

    /// 权限校验：非 seat player 调用应失败。
    #[test]
    fn fold_with_proof_rejects_non_seat_player() {
        let mut table = make_betting_table_with_players(0, true);
        let ctx_impersonator = make_context_as([0x99; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_impersonator,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "非座位玩家不应能 fold_with_proof");
        assert!(!table.seats[0].is_folded(), "失败调用不应改变 folded 标志");
    }

    /// 非下注轮拒绝：在 WAITING 状态调用应失败。
    #[test]
    fn fold_with_proof_rejects_waiting_state() {
        let mut table = make_table_with_two_players();
        // round_state = WAITING（make_table 默认），betting_round = None
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(
            result.is_err(),
            "WAITING 状态不应能 fold_with_proof（应在下注轮）"
        );
    }

    /// 非该玩家行动轮拒绝：current_turn != seat_index 应失败。
    #[test]
    fn fold_with_proof_rejects_not_turn() {
        // current_turn = 1，但调用 seat 0
        let mut table = make_betting_table_with_players(1, true);
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "非该玩家行动轮不应能 fold_with_proof");
    }

    /// 越界 seat_index 应返回错误而非 panic。
    #[test]
    fn fold_with_proof_rejects_out_of_range_seat() {
        let mut table = make_betting_table_with_players(0, false);
        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 200,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "越界 seat_index 应返回错误而非 panic");
    }

    /// 重复 fold 拒绝：已 folded 的 seat 再次调用应失败。
    #[test]
    fn fold_with_proof_rejects_already_folded() {
        let mut table = make_betting_table_with_players(0, true);
        table.seats[0].set_status(SeatStatus::Folded); // 预设已 folded

        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        let result = dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        );
        assert!(result.is_err(), "已 folded 的座位不应再次 fold_with_proof");
    }

    /// last-player-standing：fold 后只剩 1 活跃玩家 → 触发 end_without_showdown（pot 分配）。
    #[test]
    fn fold_with_proof_last_player_standing_ends_hand() {
        // 2 名玩家（只有 seat 0 和 1 入座），p1 fold_with_proof 后只剩 p2 → 结算
        let mut table = make_table();
        table
            .enter_betting(
                super::super::constants::ROUND_PREFLOP,
                super::super::betting::BettingRound::new(100, 100),
                0,
                0,
            )
            .unwrap();
        table
            .arm_betting_deadline(make_context().block_timestamp)
            .unwrap();
        table.seats[0].fixture_set_player([0x11; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_total_bet(100);
        table.seats[0].fixture_set_pk(ECPoint(g1_generator()));
        table.seats[1].fixture_set_player([0x22; 20]);
        table.seats[1].set_status(SeatStatus::Active);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_total_bet(100);
        table.seats[1].fixture_set_pk(ECPoint(g1_generator()));
        table.deck_state.contributor_mask = 0b11;
        table.derived_aggregated_pk().unwrap();
        let g = g1_generator();
        table.deck_state.encrypted = (0..52)
            .map(|_| ElGamalCiphertext { c1: g, c2: g })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        // Prior-round pot plus live current-round bets. Terminal fold must
        // collect the live bets before payout instead of clearing them in reset.
        table.pot = 200;
        table.seats[0].fixture_set_bet(25);
        table.seats[1].fixture_set_bet(75);

        let ctx_p1 = make_context_as([0x11; 20]);
        let args = FoldWithProofArgs {
            seat_index: 0,
            output_cards: vec![],
            fold_proof: empty_fold_proof(),
        };
        dispatch(
            &ctx_p1,
            &mut table,
            &selectors::fold_with_proof(),
            &borsh::to_vec(&args).unwrap(),
        )
        .unwrap();

        // end_without_showdown：p2（seat 1）独得 pot，随后 reset_for_next_hand 清理 folded 标志。
        // （reset 第二阶段会把所有 seat.folded 重置为 false，故此处不能断言 folded=true）
        assert_eq!(
            table.seats[1].stack(),
            1000 + 300,
            "p2 应独得 prior pot + current-round bets（end_without_showdown）"
        );
        assert_eq!(table.pot, 0, "pot 应清零");
        // reset 后回到 WAITING
        assert_eq!(table.round_state(), super::super::constants::ROUND_WAITING);
        // p1 仍在座位上（reset 不踢有筹码的玩家），stack 不变（未参与底池分配）
        assert_eq!(table.seats[0].player(), [0x11; 20]);
        assert_eq!(table.seats[0].stack(), 1000);
        assert_eq!(table.deck_state.contributor_mask, 0b11);
        assert!(table.derived_aggregated_pk().unwrap().is_some());
    }
}
