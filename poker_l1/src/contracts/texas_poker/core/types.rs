//! Texas Poker 核心数据结构（移植自 `texas_poker_move/sources/table.move` 的 struct 定义）。
//!
//! 包含桌台、座位、洗牌状态、揭示状态、重构状态、超时配置、时间戳、
//! 牌组状态等所有状态机所需数据结构。
//!
//! 所有结构 `#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]`，
//! borsh 兼容，便于 `TexasPokerPrecompile::call` 通过 borsh 序列化/反序列化存入 ObjectDb。
//!
//! # typed 化说明
//!
//! 密码学相关字段（pk、token、ciphertext_bytes、plaintext_bytes、
//! plaintext）已从 `Vec<u8>` 改为 typed `poker_protocol` 类型（`ECPoint` / `ECScalar` /
//! `ElGamalCiphertext`），消除 state_machine.rs 中的 bytes↔G1 转换样板代码。
//! `ElGamalCiphertext` 直接复用 `poker_protocol::crypto::types::ElGamalCiphertext`
//! （= `ElGamalCiphertextGeneric<DefaultCurve>`，Plan D 后为 Stark 曲线点）。
//!
//! # Borsh orphan rule 处理
//!
//! `G1Projective` / `BlsScalar` 是外部 blstrs 类型，无法在 poker_l1 直接 impl
//! `BorshSerialize`/`BorshDeserialize`（orphan rule）。所有 struct 字段使用本地 newtype
//! `ECPoint(pub G1Projective)` / `ECScalar(pub BlsScalar)` 包装，borsh impl 在
//! `poker_protocol::borsh_impls` 中实现（48B G1 compressed / 32B scalar big-endian）。

use std::borrow::Cow;
use std::ops::{Deref, DerefMut, Index, IndexMut};

use borsh::{BorshDeserialize, BorshSerialize};

use super::utils::g1_generator;
use poker_protocol::crypto::curve::CurvePoint as CPt;
use poker_protocol::crypto::types::ECPoint;
// 注：`ElGamalCiphertext` 通过下方 `pub use` 重导出，避免重复导入。

use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;

use super::betting::BettingRound;
use super::card::{BoardCards, Card, HoleCards};
// 复用 constants.rs 中与 Move 端逐字节一致的 phase 常量（避免本地重复定义导致语义分叉）
use super::constants::{
    ANTE_MODE_BBA, ANTE_MODE_NONE, ANTE_MODE_NORMAL, DEFAULT_BETTING_TIMEOUT_MS,
    DEFAULT_RECONSTRUCT_TIMEOUT_MS, DEFAULT_REVEAL_TIMEOUT_MS, DEFAULT_SHOWDOWN_DISPLAY_MS,
    DEFAULT_SHUFFLE_TIMEOUT_MS, RAKE_MODE_NONE, RAKE_MODE_PERCENTAGE, RECONSTRUCT_PHASE_COLLECTING,
    RECONSTRUCT_PHASE_NONE, REVEAL_PHASE_FLOP, REVEAL_PHASE_NONE, REVEAL_PHASE_PREFLOP,
    REVEAL_PHASE_REDEAL, REVEAL_PHASE_RIVER, REVEAL_PHASE_SHOWDOWN, REVEAL_PHASE_TURN,
    RIT_MODE_DISABLED, RIT_MODE_TWICE, ROUND_FLOP, ROUND_PREFLOP, ROUND_RIVER, ROUND_SHOWDOWN,
    ROUND_TURN, ROUND_WAITING, SHUFFLE_PHASE_BEFORE_PREFLOP, SHUFFLE_PHASE_NONE,
    SHUFFLE_PHASE_RECONSTRUCT,
};

// ========== 常量 ==========

/// 空座位标识（player = [0; 20]）。
pub const EMPTY_PLAYER: Address = [0u8; 20];

/// Maximum supported seat count. Seat membership is encoded in a [`SeatMask`].
pub const MAX_SEATS: u8 = 9;

/// Canonical sentinel for a missing seat index in persisted state and AIR projections.
pub const NO_SEAT: u8 = 0x0f;

/// Fixed number of ciphertexts in an active mental-poker deck.
pub const CIPHER_DECK_SIZE: usize = 52;

/// Bit `i` denotes seat `i`. Only the low `max_players` bits may be set.
pub type SeatMask = u16;

#[must_use]
/// Return the mask containing only `seat_index`.
pub const fn seat_mask_bit(seat_index: u8) -> SeatMask {
    1u16 << seat_index
}

#[must_use]
/// Return whether `seat_index` is present in a canonical seat mask.
pub const fn seat_mask_contains(mask: SeatMask, seat_index: u8) -> bool {
    seat_index < MAX_SEATS && mask & seat_mask_bit(seat_index) != 0
}

/// Insert `seat_index`, rejecting indices outside the supported table size.
pub fn seat_mask_insert(mask: &mut SeatMask, seat_index: u8) -> PokerL1Result<()> {
    if seat_index >= MAX_SEATS {
        return Err(PokerL1Error::Serialization(format!(
            "Texas seat index {seat_index} exceeds mask capacity {MAX_SEATS}"
        )));
    }
    *mask |= seat_mask_bit(seat_index);
    Ok(())
}

/// Remove `seat_index`; out-of-range indices are harmless no-ops.
pub fn seat_mask_remove(mask: &mut SeatMask, seat_index: u8) {
    if seat_index < MAX_SEATS {
        *mask &= !seat_mask_bit(seat_index);
    }
}

#[must_use]
/// Count the seats present in `mask`.
pub const fn seat_mask_count(mask: SeatMask) -> u8 {
    mask.count_ones() as u8
}

#[must_use]
/// Return the lowest-numbered seat in `mask`.
pub fn seat_mask_first(mask: SeatMask) -> Option<u8> {
    (mask != 0).then(|| mask.trailing_zeros() as u8)
}

#[must_use]
/// Expand a canonical mask into ascending seat indices below `max_players`.
pub fn seat_mask_to_indices(mask: SeatMask, max_players: u8) -> Vec<u8> {
    (0..max_players)
        .filter(|seat| seat_mask_contains(mask, *seat))
        .collect()
}

/// Build a canonical seat mask, rejecting duplicates and out-of-range indices.
pub fn seat_mask_from_indices(
    indices: &[u8],
    max_players: u8,
    label: &str,
) -> PokerL1Result<SeatMask> {
    if max_players > MAX_SEATS {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: max_players {max_players} exceeds {MAX_SEATS}"
        )));
    }
    let mut mask = 0;
    for &seat_index in indices {
        if seat_index >= max_players {
            return Err(PokerL1Error::Serialization(format!(
                "{label}: seat index {seat_index} outside max_players {max_players}"
            )));
        }
        let bit = seat_mask_bit(seat_index);
        if mask & bit != 0 {
            return Err(PokerL1Error::Serialization(format!(
                "{label}: duplicate seat index {seat_index}"
            )));
        }
        mask |= bit;
    }
    Ok(mask)
}

#[must_use]
/// Return whether `mask` contains only seats below `max_players`.
pub const fn seat_mask_is_canonical(mask: SeatMask, max_players: u8) -> bool {
    max_players <= MAX_SEATS && (max_players == MAX_SEATS || mask < (1u16 << max_players))
}

// ========== ElGamal 密文 ==========

// `ElGamalCiphertext` 直接复用 `poker_protocol::crypto::types::ElGamalCiphertext`
// （= `ElGamalCiphertextGeneric<DefaultCurve>`，字段 `c1/c2` 为曲线点，
//   已在 `poker_protocol::borsh_impls` impl BorshSerialize/BorshDeserialize）。
// 重导出供外部模块使用。
pub use poker_protocol::crypto::types::ElGamalCiphertext;

// ========== 座位 ==========

/// 玩家座位状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SeatStatus {
    /// 空座位（player = [0; 20]）。
    Empty,
    /// 等待下一局（已入座但本局不参与）。
    Waiting,
    /// 活跃（本局参与）。
    Active,
    /// 已弃牌（本局不再参与下注，但 total_bet 保留供 side pot 计算）。
    Folded,
    /// All-in（已全押，本局不再下注）。
    AllIn,
    /// 出局（stack=0 或被踢后清理）。
    Out,
}

impl Default for SeatStatus {
    fn default() -> Self {
        Self::Empty
    }
}

/// Common custody and identity payload of a live occupied seat.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct OccupiedSeat {
    /// Player address.
    pub player: Address,
    /// Chips currently available to wager.
    pub stack: u64,
    /// Mental Poker public key.
    pub pk: ECPoint,
    /// 会话交易公钥（P1-2 修复，2026-09-09）：该座位 VM 层交易签名的
    /// 验证锚——Stark Schnorr 32B 压缩点。join 时经链上 vault
    /// `set_session_tx_pk`（买入同笔 multicall）核验后写入；后续
    /// `TableRuntime` 签名交易按此钥验证。定宽形式（2026-09-10）：
    /// tag 恒 Stark v1、raw 恒 32B，全零压缩点 = 未登记（仅 fixture/旧路径；
    /// 签名路径拒绝）。
    pub tx_pk: crate::signature::StarkTxPubkey,
    /// Addon held until the next-hand reset boundary.
    pub pending_addon: u64,
    /// Remaining time-bank allowance in milliseconds.
    pub time_bank_ms: u32,
}

/// 未登记的会话交易公钥（Stark v1 tag + 全零 32B 压缩点 = 恒等元）。
///
/// fixture 与不关心交易签名的构造路径使用；`TableRuntime::submit_signed`
/// 遇到未登记座位显式拒绝（fail-closed）。
#[must_use]
pub fn unregistered_tx_pk() -> crate::signature::StarkTxPubkey {
    crate::signature::StarkTxPubkey::UNREGISTERED
}

/// 会话交易公钥结构合法性：tag 恒为 Stark v1（32B 不变量已由类型承载）。
#[must_use]
pub fn is_well_formed_tx_pk(pk: &crate::signature::StarkTxPubkey) -> bool {
    pk.tag
        == crate::signature::encode_tag(
            crate::signature::SignatureScheme::Stark,
            crate::signature::CURRENT_VERSION,
        )
}

/// 会话交易公钥是否为**已登记**（结构合法且非恒等元/全零哨兵）。
#[must_use]
pub fn is_registered_tx_pk(pk: &crate::signature::StarkTxPubkey) -> bool {
    is_well_formed_tx_pk(pk) && pk.is_registered()
}

/// Mutually exclusive status of a player participating in the current hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum PlayingSeatStatus {
    /// May act in the current betting round.
    Active,
    /// Folded, but contribution remains eligible for side-pot accounting.
    Folded,
    /// Has no remaining stack and cannot act again.
    AllIn,
}

/// Hand-local payload that only exists while a player participates in the current hand.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PlayingSeat {
    /// Live identity/custody payload.
    pub occupied: OccupiedSeat,
    /// Private hole cards, materialized by the reveal protocol.
    pub hand: HoleCards,
    /// Amount committed in the current betting round.
    pub bet: u64,
    /// Total amount committed in this hand, retained for side pots.
    pub total_bet: u64,
    /// In-hand lifecycle state.
    pub status: PlayingSeatStatus,
}

/// 定宽记录公共写入：`payload_len(u32 LE) || tag || 载荷 ||
/// 零填充到 width`。载荷+头部超宽即失败。
fn to_payload<T: BorshSerialize>(value: &T) -> borsh::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    value.serialize(&mut buf)?;
    Ok(buf)
}

fn write_padded_record<W: borsh::io::Write>(
    writer: &mut W,
    tag: u8,
    payload: &[u8],
    width: usize,
) -> borsh::io::Result<()> {
    use borsh::io::Write as _;
    // 记录体 = tag(1) + 载荷；len 字段覆盖 tag+载荷，与读取端一致。
    let body_len = payload
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(4))
        .filter(|len| *len <= width)
        .ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "fixed-width record payload exceeds record width",
            )
        })?;
    let len = u32::try_from(payload.len() + 1).map_err(|_| {
        borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "record too large")
    })?;
    len.serialize(writer)?;
    writer.write_all(&[tag])?;
    writer.write_all(payload)?;
    let pad = width - body_len;
    writer.write_all(&vec![0u8; pad])
}

/// 定宽记录公共读取：校验长度上界与零填充规范形，返回 (tag, 载荷)。
fn read_padded_record<R: borsh::io::Read>(
    reader: &mut R,
    width: usize,
) -> borsh::io::Result<(u8, Vec<u8>)> {
    use borsh::io::Read as _;
    let len = u32::deserialize_reader(reader)? as usize;
    // len 覆盖 tag+载荷；记录体 = len(u32) + len 字节 = len + 4。
    let body_len = len
        .checked_add(4)
        .filter(|len| *len <= width)
        .ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "fixed-width record length exceeds record width",
            )
        })?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    let pad = width - body_len;
    let mut padding = vec![0u8; pad];
    reader.read_exact(&mut padding)?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "non-canonical fixed-width record: padding must be zero",
        ));
    }
    let tag = buf[0];
    Ok((tag, buf[1..].to_vec()))
}

/// `Seat` 的定宽记录宽度。载荷超宽即序列化
/// 失败（fail-closed）；所有变体序列化结果恒等长，native borsh 与
/// canonical ABI 的固定宽度语义合一。
const SEAT_RECORD_WIDTH: usize = 512;

/// 变体判别值（与历史 derive 枚举序一致：Vacant/Waiting/Playing/DepartedThisHand）。
const SEAT_TAG_VACANT: u8 = 0;
const SEAT_TAG_WAITING: u8 = 1;
const SEAT_TAG_PLAYING: u8 = 2;
const SEAT_TAG_DEPARTED: u8 = 3;

/// `Seat` 手写固定宽度 Borsh。
///
/// 记录布局：`payload_len(u32 LE) || tag(u8) || 派生载荷 || 零填充到
/// [`SEAT_RECORD_WIDTH`]。单射性 = len/tag/载荷一致 + 填充必须全零
/// （非零填充拒绝，防同一变体多种字节形态）。
impl BorshSerialize for Seat {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let (tag, payload): (u8, Vec<u8>) = match self {
            Seat::Vacant { time_bank_ms } => (SEAT_TAG_VACANT, to_payload(&time_bank_ms)?),
            Seat::Waiting { occupied } => (SEAT_TAG_WAITING, to_payload(&occupied)?),
            Seat::Playing { playing } => (SEAT_TAG_PLAYING, to_payload(&playing)?),
            Seat::DepartedThisHand {
                player,
                total_bet,
                time_bank_ms,
            } => {
                let mut payload = Vec::new();
                player.serialize(&mut payload)?;
                total_bet.serialize(&mut payload)?;
                time_bank_ms.serialize(&mut payload)?;
                (SEAT_TAG_DEPARTED, payload)
            }
        };
        write_padded_record(writer, tag, &payload, SEAT_RECORD_WIDTH)
    }
}

impl BorshDeserialize for Seat {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let (tag, payload) = read_padded_record(reader, SEAT_RECORD_WIDTH)?;
        let mut slice = payload.as_slice();
        Ok(match tag {
            SEAT_TAG_VACANT => Seat::Vacant {
                time_bank_ms: u32::deserialize_reader(&mut slice)?,
            },
            SEAT_TAG_WAITING => Seat::Waiting {
                occupied: OccupiedSeat::deserialize_reader(&mut slice)?,
            },
            SEAT_TAG_PLAYING => Seat::Playing {
                playing: PlayingSeat::deserialize_reader(&mut slice)?,
            },
            SEAT_TAG_DEPARTED => Seat::DepartedThisHand {
                player: Address::deserialize_reader(&mut slice)?,
                total_bet: u64::deserialize_reader(&mut slice)?,
                time_bank_ms: u32::deserialize_reader(&mut slice)?,
            },
            other => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    format!("unknown Seat record tag {other}"),
                ));
            }
        })
    }
}

/// Canonical runtime seat representation.
///
/// Each lifecycle variant carries only meaningful data. This is also the canonical Borsh/state-root
/// representation; impossible flat combinations such as an empty seat with chips or a waiting seat
/// with hole cards cannot be constructed. Borsh 采用手写定宽记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seat {
    /// Unoccupied slot. Time-bank is retained as a slot policy counter.
    Vacant {
        /// Remaining time-bank allowance for the slot.
        time_bank_ms: u32,
    },
    /// Occupied player waiting for the next hand.
    Waiting {
        /// Live identity/custody payload.
        occupied: OccupiedSeat,
    },
    /// Player participating in the current hand.
    Playing {
        /// Hand-local player payload.
        playing: PlayingSeat,
    },
    /// Player removed during a hand whose contribution must remain for settlement.
    DepartedThisHand {
        /// Address retained for deterministic events and audit output.
        player: Address,
        /// Hand contribution retained for side-pot construction.
        total_bet: u64,
        /// Remaining time-bank allowance.
        time_bank_ms: u32,
    },
}

impl Seat {
    /// 构造空座位。
    #[must_use]
    pub fn empty() -> Self {
        Self::Vacant {
            time_bank_ms: super::constants::DEFAULT_TIME_BANK_MS,
        }
    }

    /// Construct one occupied seat in a payload shape accepted by the tagged seat codec.
    pub fn occupied(
        player: Address,
        stack: u64,
        pk: ECPoint,
        tx_pk: crate::signature::TaggedPubkey,
        status: SeatStatus,
    ) -> PokerL1Result<Self> {
        if player == EMPTY_PLAYER {
            return Err(PokerL1Error::Serialization(
                "Texas occupied seat cannot use the empty player address".into(),
            ));
        }
        if !matches!(status, SeatStatus::Waiting | SeatStatus::Active) {
            return Err(PokerL1Error::Serialization(
                "Texas newly occupied seat must be waiting or active".into(),
            ));
        }
        if pk.0.is_identity() {
            return Err(PokerL1Error::Serialization(
                "Texas newly occupied seat cannot use an identity public key".into(),
            ));
        }
        // 结构校验（Stark v1 + 32B 压缩点，收敛为定宽 StarkTxPubkey）；
        // "已登记"（非恒等元）与否不在 core 强制——策略归 runtime：
        // TableRuntime 的签名路径对未登记座位 fail-closed（mirror 注入
        // 路径不需要 tx 签名，允许哨兵）。
        let tx_pk = crate::signature::StarkTxPubkey::from_tagged(&tx_pk).map_err(|_| {
            PokerL1Error::Serialization(
                "Texas join tx_pk must be a Stark-scheme 32-byte compressed point".into(),
            )
        })?;
        let occupied = OccupiedSeat {
            player,
            stack,
            pk,
            tx_pk,
            pending_addon: 0,
            time_bank_ms: super::constants::DEFAULT_TIME_BANK_MS,
        };
        Ok(match status {
            SeatStatus::Waiting => Self::Waiting { occupied },
            SeatStatus::Active => Self::Playing {
                playing: PlayingSeat {
                    occupied,
                    hand: HoleCards::empty(),
                    bet: 0,
                    total_bet: 0,
                    status: PlayingSeatStatus::Active,
                },
            },
            _ => unreachable!("occupied status validated above"),
        })
    }

    /// Replace this slot with the unique vacant representation.
    pub fn vacate(&mut self) {
        *self = Self::empty();
    }

    /// Convert an occupied player into the minimal departed-this-hand payload.
    ///
    /// `player`, `total_bet`, and `time_bank_ms` remain available for side-pot settlement and
    /// audit events. Live custody, cards, the encryption key, and pending funding are cleared.
    pub fn depart_this_hand(&mut self) -> PokerL1Result<()> {
        let (player, total_bet, time_bank_ms) = match self {
            Self::Waiting { occupied } => (occupied.player, 0, occupied.time_bank_ms),
            Self::Playing { playing } => (
                playing.occupied.player,
                playing.total_bet,
                playing.occupied.time_bank_ms,
            ),
            Self::Vacant { .. } => {
                return Err(PokerL1Error::Serialization(
                    "Texas cannot depart a vacant seat".into(),
                ));
            }
            Self::DepartedThisHand { .. } => return Ok(()),
        };
        *self = Self::DepartedThisHand {
            player,
            total_bet,
            time_bank_ms,
        };
        Ok(())
    }

    /// Clear hand-local payload and project a retained player into the next-hand ready state.
    ///
    /// Waiting 座位（waiting-for-big-blind）保持 Waiting：跨手保留等待状态，
    /// 只在 `start_hand` 的盲注位提升逻辑中被显式拉回参与。
    pub fn prepare_next_hand(&mut self) {
        match self {
            Self::Vacant { .. } | Self::DepartedThisHand { .. } | Self::Waiting { .. } => {}
            Self::Playing { playing } => {
                playing.hand.clear();
                playing.bet = 0;
                playing.total_bet = 0;
                playing.status = PlayingSeatStatus::Active;
            }
        }
    }

    /// 把 Waiting 座位提升为下一手-ready 的参与座位（waiting-for-BB 到位时调用）。
    ///
    /// 返回是否发生了提升；非 Waiting 座位不受影响。
    pub fn promote_waiting(&mut self) -> bool {
        if let Self::Waiting { occupied } = self {
            let occupied = occupied.clone();
            *self = Self::Playing {
                playing: PlayingSeat {
                    occupied,
                    hand: HoleCards::empty(),
                    bet: 0,
                    total_bet: 0,
                    status: PlayingSeatStatus::Active,
                },
            };
            return true;
        }
        false
    }

    /// 判断座位是否被活跃占用（player != [0;20] 且未中途离开）。
    #[must_use]
    pub fn is_occupied(&self) -> bool {
        matches!(self, Self::Waiting { .. } | Self::Playing { .. })
    }

    /// 获取座位状态枚举。
    #[must_use]
    pub fn status(&self) -> SeatStatus {
        match self {
            Self::Vacant { .. } => SeatStatus::Empty,
            Self::Waiting { .. } => SeatStatus::Waiting,
            Self::Playing { playing } => match playing.status {
                PlayingSeatStatus::Active => SeatStatus::Active,
                PlayingSeatStatus::Folded => SeatStatus::Folded,
                PlayingSeatStatus::AllIn => SeatStatus::AllIn,
            },
            Self::DepartedThisHand { .. } => SeatStatus::Out,
        }
    }

    /// Whether the seat has folded this hand.
    #[must_use]
    pub fn is_folded(&self) -> bool {
        self.status() == SeatStatus::Folded
    }

    /// Whether the seat is all-in this hand.
    #[must_use]
    pub fn is_all_in(&self) -> bool {
        self.status() == SeatStatus::AllIn
    }

    /// Whether the occupied seat is waiting for the next hand.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        matches!(self, Self::Waiting { .. })
    }

    /// Whether the player left or was removed during the current hand.
    #[must_use]
    pub fn has_left_hand(&self) -> bool {
        matches!(self, Self::DepartedThisHand { .. })
    }

    /// Replace the mutually-exclusive lifecycle state.
    pub fn set_status(&mut self, status: SeatStatus) {
        match status {
            SeatStatus::Empty => self.vacate(),
            SeatStatus::Out => self
                .depart_this_hand()
                .expect("only occupied seats may transition to Out"),
            SeatStatus::Waiting => match self {
                Self::Waiting { .. } => {}
                Self::Playing { playing }
                    if playing.hand.is_empty() && playing.bet == 0 && playing.total_bet == 0 =>
                {
                    let occupied = playing.occupied.clone();
                    *self = Self::Waiting { occupied };
                }
                _ => panic!("only a clean live seat may transition to Waiting"),
            },
            SeatStatus::Active => match self {
                Self::Waiting { occupied } => {
                    let occupied = occupied.clone();
                    *self = Self::Playing {
                        playing: PlayingSeat {
                            occupied,
                            hand: HoleCards::empty(),
                            bet: 0,
                            total_bet: 0,
                            status: PlayingSeatStatus::Active,
                        },
                    };
                }
                Self::Playing { playing } => playing.status = PlayingSeatStatus::Active,
                _ => panic!("only a live occupied seat may transition to Active"),
            },
            SeatStatus::Folded | SeatStatus::AllIn => match self {
                Self::Playing { playing } => {
                    playing.status = if status == SeatStatus::Folded {
                        PlayingSeatStatus::Folded
                    } else {
                        PlayingSeatStatus::AllIn
                    };
                }
                _ => panic!("only an in-hand seat may fold or become all-in"),
            },
        }
    }

    /// Player address, or the canonical empty address for a vacant slot.
    #[must_use]
    pub const fn player(&self) -> Address {
        match self {
            Self::Vacant { .. } => EMPTY_PLAYER,
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => occupied.player,
            Self::DepartedThisHand { player, .. } => *player,
        }
    }

    /// Available stack; zero for vacant or departed seats.
    #[must_use]
    pub const fn stack(&self) -> u64 {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => occupied.stack,
            Self::Vacant { .. } | Self::DepartedThisHand { .. } => 0,
        }
    }

    /// Current-round wager; zero outside an active hand.
    #[must_use]
    pub const fn bet(&self) -> u64 {
        match self {
            Self::Playing { playing } => playing.bet,
            _ => 0,
        }
    }

    /// Total hand contribution retained for side-pot accounting.
    #[must_use]
    pub const fn total_bet(&self) -> u64 {
        match self {
            Self::Playing { playing } => playing.total_bet,
            Self::DepartedThisHand { total_bet, .. } => *total_bet,
            Self::Vacant { .. } | Self::Waiting { .. } => 0,
        }
    }

    /// Pending addon; zero for vacant or departed seats.
    #[must_use]
    pub const fn pending_addon(&self) -> u64 {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => occupied.pending_addon,
            Self::Vacant { .. } | Self::DepartedThisHand { .. } => 0,
        }
    }

    /// Remaining time bank.
    #[must_use]
    pub const fn time_bank_ms(&self) -> u32 {
        match self {
            Self::Vacant { time_bank_ms } | Self::DepartedThisHand { time_bank_ms, .. } => {
                *time_bank_ms
            }
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => occupied.time_bank_ms,
        }
    }

    /// Live Mental Poker key, absent for vacant and departed seats.
    #[must_use]
    pub const fn pk(&self) -> Option<&ECPoint> {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => Some(&occupied.pk),
            Self::Vacant { .. } | Self::DepartedThisHand { .. } => None,
        }
    }

    /// 已登记的会话交易公钥（VM 层交易签名验证锚）；未登记/空座位返回 None。
    #[must_use]
    pub fn registered_tx_pk(&self) -> Option<&crate::signature::StarkTxPubkey> {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => is_registered_tx_pk(&occupied.tx_pk).then_some(&occupied.tx_pk),
            Self::Vacant { .. } | Self::DepartedThisHand { .. } => None,
        }
    }

    /// Hole cards when participating in the current hand.
    #[must_use]
    pub const fn hand(&self) -> Option<&HoleCards> {
        match self {
            Self::Playing { playing } => Some(&playing.hand),
            _ => None,
        }
    }

    /// Mutable in-hand payload.
    pub fn playing_mut(&mut self) -> PokerL1Result<&mut PlayingSeat> {
        match self {
            Self::Playing { playing } => Ok(playing),
            _ => Err(PokerL1Error::Serialization(
                "Texas seat is not participating in the current hand".into(),
            )),
        }
    }

    /// Mutable occupied payload, available to waiting and playing seats.
    pub fn occupied_mut(&mut self) -> PokerL1Result<&mut OccupiedSeat> {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => Ok(occupied),
            _ => Err(PokerL1Error::Serialization(
                "Texas seat has no live occupied payload".into(),
            )),
        }
    }

    /// Set the available stack of a live occupied seat.
    pub fn set_stack(&mut self, stack: u64) -> PokerL1Result<()> {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => {
                occupied.stack = stack;
            }
            _ if stack == 0 => {}
            _ => {
                return Err(PokerL1Error::Serialization(
                    "Texas vacant/departed seat cannot carry a stack".into(),
                ));
            }
        }
        Ok(())
    }

    /// Set the current-round wager of an in-hand seat.
    pub fn set_bet(&mut self, bet: u64) -> PokerL1Result<()> {
        match self {
            Self::Playing { playing } => playing.bet = bet,
            _ if bet == 0 => {}
            _ => {
                return Err(PokerL1Error::Serialization(
                    "Texas non-playing seat cannot carry a round wager".into(),
                ));
            }
        }
        Ok(())
    }

    /// Set the total hand contribution used by side-pot accounting.
    pub fn set_total_bet(&mut self, total_bet: u64) -> PokerL1Result<()> {
        match self {
            Self::Playing { playing } => playing.total_bet = total_bet,
            Self::DepartedThisHand {
                total_bet: current, ..
            } => *current = total_bet,
            _ if total_bet == 0 => {}
            _ => {
                return Err(PokerL1Error::Serialization(
                    "Texas non-playing seat cannot carry a hand contribution".into(),
                ));
            }
        }
        Ok(())
    }

    /// Set a live occupied seat's pending addon.
    pub fn set_pending_addon(&mut self, pending_addon: u64) -> PokerL1Result<()> {
        match self {
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => {
                occupied.pending_addon = pending_addon;
            }
            _ if pending_addon == 0 => {}
            _ => {
                return Err(PokerL1Error::Serialization(
                    "Texas vacant/departed seat cannot carry a pending addon".into(),
                ));
            }
        }
        Ok(())
    }

    /// Set the slot's remaining time bank.
    pub fn set_time_bank_ms(&mut self, value: u32) {
        match self {
            Self::Vacant { time_bank_ms } | Self::DepartedThisHand { time_bank_ms, .. } => {
                *time_bank_ms = value
            }
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => {
                occupied.time_bank_ms = value;
            }
        }
    }

    /// Replace the hole cards of an in-hand seat.
    pub fn set_hand(&mut self, hand: HoleCards) -> PokerL1Result<()> {
        hand.validate_canonical().map_err(|error| {
            PokerL1Error::Serialization(format!("Texas seat hand is non-canonical: {error}"))
        })?;
        self.playing_mut()?.hand = hand;
        Ok(())
    }

    /// Mutable hole-card payload of an in-hand seat.
    pub fn hand_mut(&mut self) -> PokerL1Result<&mut HoleCards> {
        Ok(&mut self.playing_mut()?.hand)
    }

    /// Replace a slot with an exact in-hand fixture/state payload.
    pub fn replace_playing(
        &mut self,
        player: Address,
        stack: u64,
        pk: ECPoint,
        hand: HoleCards,
        bet: u64,
        total_bet: u64,
        status: PlayingSeatStatus,
        pending_addon: u64,
        time_bank_ms: u32,
    ) -> PokerL1Result<()> {
        if player == EMPTY_PLAYER || pk.0.is_identity() {
            return Err(PokerL1Error::Serialization(
                "Texas playing seat requires a live identity and key".into(),
            ));
        }
        hand.validate_canonical().map_err(|error| {
            PokerL1Error::Serialization(format!("Texas seat hand is non-canonical: {error}"))
        })?;
        *self = Self::Playing {
            playing: PlayingSeat {
                occupied: OccupiedSeat {
                    player,
                    stack,
                    pk,
                    tx_pk: unregistered_tx_pk(),
                    pending_addon,
                    time_bank_ms,
                },
                hand,
                bet,
                total_bet,
                status,
            },
        };
        Ok(())
    }

    /// Test-fixture helper that installs or replaces the player identity without ever creating a
    /// partially occupied flat seat. Production transitions must use `occupied`/`replace_playing`.
    pub fn fixture_set_player(&mut self, player: Address) {
        assert_ne!(player, EMPTY_PLAYER, "fixture player must be non-empty");
        match self {
            Self::Vacant { time_bank_ms } => {
                let time_bank_ms = *time_bank_ms;
                *self = Self::Playing {
                    playing: PlayingSeat {
                        occupied: OccupiedSeat {
                            player,
                            stack: 0,
                            pk: ECPoint(g1_generator()),
                            tx_pk: unregistered_tx_pk(),
                            pending_addon: 0,
                            time_bank_ms,
                        },
                        hand: HoleCards::empty(),
                        bet: 0,
                        total_bet: 0,
                        status: PlayingSeatStatus::Active,
                    },
                };
            }
            Self::Waiting { occupied }
            | Self::Playing {
                playing: PlayingSeat { occupied, .. },
            } => {
                occupied.player = player;
            }
            Self::DepartedThisHand {
                player: current, ..
            } => *current = player,
        }
    }

    /// Test-fixture helper that promotes a waiting seat before installing a hand-local wager.
    #[cfg(test)]
    pub(crate) fn fixture_set_bet(&mut self, bet: u64) {
        if matches!(self, Self::Waiting { .. }) {
            self.set_status(SeatStatus::Active);
        }
        self.set_bet(bet)
            .expect("fixture bet requires a playing seat");
    }

    /// Test-fixture helper that promotes a waiting seat before installing a hand contribution.
    pub fn fixture_set_total_bet(&mut self, total_bet: u64) {
        if matches!(self, Self::Waiting { .. }) {
            self.set_status(SeatStatus::Active);
        }
        self.set_total_bet(total_bet)
            .expect("fixture total_bet requires a playing/departed seat");
    }

    /// Test-fixture helper that promotes a waiting seat before installing hole cards.
    pub fn fixture_set_hand(&mut self, hand: HoleCards) {
        if matches!(self, Self::Waiting { .. }) {
            self.set_status(SeatStatus::Active);
        }
        self.set_hand(hand)
            .expect("fixture hand requires a playing seat");
    }

    /// Test-fixture helper for explicit Mental Poker key replacement.
    #[cfg(test)]
    pub(crate) fn fixture_set_pk(&mut self, pk: ECPoint) {
        self.occupied_mut()
            .expect("fixture key requires a live occupied seat")
            .pk = pk;
    }

    /// 校验可持久化的 canonical seat 表达。
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        match self {
            Self::Vacant { .. } => {}
            Self::Waiting { occupied } => validate_occupied_seat(occupied)?,
            Self::Playing { playing } => {
                validate_occupied_seat(&playing.occupied)?;
                playing.hand.validate_canonical().map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "Texas seat hand is non-canonical: {error}"
                    ))
                })?;
            }
            Self::DepartedThisHand { player, .. } => {
                if *player == EMPTY_PLAYER {
                    return Err(PokerL1Error::Serialization(
                        "Texas departed seat cannot use the empty player address".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_occupied_seat(occupied: &OccupiedSeat) -> PokerL1Result<()> {
    if occupied.player == EMPTY_PLAYER {
        return Err(PokerL1Error::Serialization(
            "Texas occupied seat cannot use the empty player address".into(),
        ));
    }
    if occupied.pk.0.is_identity() {
        return Err(PokerL1Error::Serialization(
            "Texas occupied seat cannot use an identity public key".into(),
        ));
    }
    Ok(())
}

// ========== 洗牌状态 ==========

/// Typed reason for the single active shuffle phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ShufflingPurpose {
    /// Fresh per-hand shuffle before private cards are dealt.
    Initial,
    /// Shuffle of a reconstructed deck before the suspended reveal resumes.
    Reconstruct,
}

impl ShufflingPurpose {
    /// Legacy numeric projection retained for events and the current AIR boundary.
    #[must_use]
    pub const fn legacy_phase(self) -> u8 {
        match self {
            Self::Initial => SHUFFLE_PHASE_BEFORE_PREFLOP,
            Self::Reconstruct => SHUFFLE_PHASE_RECONSTRUCT,
        }
    }
}

/// Canonical progress payload of an active shuffle.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShuffleState {
    /// 等待洗牌的玩家集合。
    pub pending_mask: SeatMask,
    /// 已完成洗牌的玩家集合。
    pub completed_mask: SeatMask,
}

impl Default for ShuffleState {
    fn default() -> Self {
        Self {
            pending_mask: 0,
            completed_mask: 0,
        }
    }
}

impl ShuffleState {
    /// Canonical actor is always the lowest pending seat; no independent scheduling fact exists.
    #[must_use]
    pub fn derived_current_shuffler(&self) -> u8 {
        seat_mask_first(self.pending_mask).unwrap_or(NO_SEAT)
    }
}

// ========== Reveal Token 状态 ==========

/// Canonical destination of one encrypted card reveal.
///
/// Hole-card and public-board targets are mutually exclusive. Encoding them as a tagged union
/// removes the legacy `board_position = 0xff` sentinel and prevents a hole assignment from also
/// carrying a runout/board position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RevealTarget {
    /// One private card belonging to `seat_index` at canonical slot `0..=1`.
    Hole {
        /// Owning seat.
        seat_index: u8,
        /// Hole-card slot in dealing order.
        card_slot: u8,
    },
    /// One public card on runout zero or one at canonical board position `0..=4`.
    Board {
        /// Public runout (`0` for the first board, `1` for the RIT second board).
        runout_index: u8,
        /// Position in the full target board.
        board_position: u8,
    },
}

impl RevealTarget {
    /// Stable sort key used to keep assignment order canonical after completed entries are drained.
    #[must_use]
    pub const fn canonical_key(self) -> (u8, u8, u8) {
        match self {
            Self::Hole {
                seat_index,
                card_slot,
            } => (0, seat_index, card_slot),
            Self::Board {
                runout_index,
                board_position,
            } => (1, runout_index, board_position),
        }
    }
}

/// Reveal assignment with one typed target and canonical in-flight token collection.
///
/// Completed results are materialized in the same dispatch and the assignment is removed, so the
/// persisted representation has no `Ready*` variant. Tokens are stored in ascending seat order;
/// `submitted_mask` is the only seat-to-token index.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealAssignment {
    /// 牌组中的加密牌索引。
    pub encrypted_card_index: u8,
    /// Typed destination of this reveal.
    pub target: RevealTarget,
    /// Seats that still owe a token.
    pub pending_mask: SeatMask,
    /// Seats whose tokens are already present in `reveal_tokens`.
    pub submitted_mask: SeatMask,
    /// Verified tokens in ascending seat-index order.
    pub reveal_tokens: Vec<ECPoint>,
}

impl RevealAssignment {
    /// Seats that still owe a reveal token.
    #[must_use]
    pub const fn pending_mask(&self) -> SeatMask {
        self.pending_mask
    }

    /// Whether the assignment has resolved and can be drained by normalization.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        self.pending_mask == 0
    }
}

/// Street at which a two-runout schedule started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RitStartStreet {
    /// No public cards were exposed; both boards receive five independent cards.
    Preflop,
    /// The flop is shared; both boards receive an independent turn and river.
    Flop,
    /// Flop and turn are shared; both boards receive an independent river.
    Turn,
}

impl RitStartStreet {
    /// Number of first-board cards shared by both runouts.
    #[must_use]
    pub const fn shared_board_len(self) -> u8 {
        match self {
            Self::Preflop => 0,
            Self::Flop => 3,
            Self::Turn => 4,
        }
    }

    /// Recover the only canonical start street for a shared prefix length.
    pub fn from_shared_board_len(shared_board_len: u8) -> PokerL1Result<Self> {
        match shared_board_len {
            0 => Ok(Self::Preflop),
            3 => Ok(Self::Flop),
            4 => Ok(Self::Turn),
            value => Err(PokerL1Error::Serialization(format!(
                "Texas RIT shared prefix {value} has no canonical start street"
            ))),
        }
    }
}

/// Per-hand Run It Twice state.
///
/// `community_cards` is the canonical first board. The second board stores only cards after the
/// shared prefix; the prefix is reconstructed from the first board.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RunItTwiceState {
    /// Normal single-board play; no inactive RIT payload can be encoded.
    Single,
    /// Two runouts with the shared prefix derived solely from `start`.
    Twice {
        /// Street at which all remaining players became all-in.
        start: RitStartStreet,
        /// Canonical second-board suffix after the shared first-board prefix.
        second_board_suffix: BoardCards,
    },
}

impl Default for RunItTwiceState {
    fn default() -> Self {
        Self::Single
    }
}

impl RunItTwiceState {
    /// Whether this hand has two active runouts.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Twice { .. })
    }

    /// Shared first-board prefix length derived from the active variant.
    #[must_use]
    pub const fn shared_board_len(&self) -> u8 {
        match self {
            Self::Single => 0,
            Self::Twice { start, .. } => start.shared_board_len(),
        }
    }

    /// Canonical second-board suffix, empty for single-runout play.
    #[must_use]
    pub fn second_board_suffix(&self) -> &[Card] {
        match self {
            Self::Single => &[],
            Self::Twice {
                second_board_suffix,
                ..
            } => second_board_suffix,
        }
    }

    /// Mutable second-board suffix for an active two-runout schedule.
    pub fn second_board_suffix_mut(&mut self) -> PokerL1Result<&mut BoardCards> {
        match self {
            Self::Twice {
                second_board_suffix,
                ..
            } => Ok(second_board_suffix),
            Self::Single => Err(PokerL1Error::Serialization(
                "Texas single runout has no second-board suffix".into(),
            )),
        }
    }

    /// Current second-board length including its shared first-board prefix.
    #[must_use]
    pub fn second_board_len(&self) -> usize {
        usize::from(self.shared_board_len()) + self.second_board_suffix().len()
    }

    /// Materialize the full second board for settlement or event output.
    pub fn full_second_board(&self, first_board: &BoardCards) -> PokerL1Result<Vec<Card>> {
        let shared_board_len = self.shared_board_len();
        if usize::from(shared_board_len) > first_board.len() {
            return Err(PokerL1Error::Serialization(
                "Texas RIT shared prefix exceeds first board".into(),
            ));
        }
        let mut board = first_board[..usize::from(shared_board_len)].to_vec();
        board.extend_from_slice(self.second_board_suffix());
        Ok(board)
    }

    /// Validate the canonical single/twice tagged representation.
    pub fn validate_canonical(&self, first_board: &BoardCards) -> PokerL1Result<()> {
        match self {
            Self::Single => {}
            Self::Twice {
                start,
                second_board_suffix,
            } => {
                second_board_suffix.validate_canonical().map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "Texas RIT second-board suffix is non-canonical: {error}"
                    ))
                })?;
                let shared = usize::from(start.shared_board_len());
                if shared > 4 || shared > first_board.len() {
                    return Err(PokerL1Error::Serialization(
                        "Texas RIT shared prefix is outside the first board".into(),
                    ));
                }
                if shared + second_board_suffix.len() > 5 {
                    return Err(PokerL1Error::Serialization(
                        "Texas RIT second board exceeds five cards".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Typed purpose of an active or reconstruction-suspended reveal collection.
///
/// There is deliberately no `None` variant. Absence of reveal work is represented by the outer
/// [`HandPhase`], so a persisted `NONE + assignments` combination is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum RevealPurpose {
    /// Remove every non-owner layer while initially dealing private hole cards.
    DealHole = 1,
    /// Reveal public board cards for the outer flop/turn/river street.
    Board = 2,
    /// Let each remaining owner remove the final layer from their private cards.
    ShowdownOwner = 3,
    /// Re-collect non-owner layers for a hole card that was re-dealt (redeal) after its
    /// original ciphertext turned out to be a dead slot (owner-side decryption yields a
    /// non-canonical plaintext, e.g. the identity point). Semantically identical to
    /// [`RevealPurpose::DealHole`] for the replacement card; the completion transition
    /// restores the suspended betting round instead of posting blinds.
    RedealHole = 4,
}

impl RevealPurpose {
    /// Project the typed purpose plus its outer street into the stable event/AIR phase ABI.
    #[must_use]
    pub const fn legacy_phase(self, street: u8) -> u8 {
        match (self, street) {
            (Self::DealHole, ROUND_PREFLOP) => REVEAL_PHASE_PREFLOP,
            (Self::RedealHole, ROUND_PREFLOP)
            | (Self::RedealHole, ROUND_FLOP)
            | (Self::RedealHole, ROUND_TURN)
            | (Self::RedealHole, ROUND_RIVER) => REVEAL_PHASE_REDEAL,
            (Self::Board, ROUND_FLOP) => REVEAL_PHASE_FLOP,
            (Self::Board, ROUND_TURN) => REVEAL_PHASE_TURN,
            (Self::Board, ROUND_RIVER) => REVEAL_PHASE_RIVER,
            (Self::ShowdownOwner, ROUND_SHOWDOWN) => REVEAL_PHASE_SHOWDOWN,
            _ => REVEAL_PHASE_NONE,
        }
    }
}

/// Canonical reveal-token collection payload.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTokenState {
    /// Type-safe protocol purpose; the exact board street lives once in the outer [`HandPhase`].
    pub purpose: RevealPurpose,
    /// 当前阶段的分配列表。
    pub assignments: Vec<RevealAssignment>,
}

impl RevealTokenState {
    /// Validate purpose/street and target-shape invariants without consulting table seats.
    pub fn validate_for_street(&self, street: u8) -> PokerL1Result<()> {
        if self.purpose.legacy_phase(street) == REVEAL_PHASE_NONE {
            return Err(PokerL1Error::Serialization(format!(
                "Texas reveal purpose {:?} is incompatible with street {street}",
                self.purpose
            )));
        }
        let mut prior_key = None;
        let mut encrypted_indices = [false; 52];
        for (assignment_index, assignment) in self.assignments.iter().enumerate() {
            let target_matches = match (self.purpose, assignment.target) {
                (
                    RevealPurpose::DealHole
                    | RevealPurpose::ShowdownOwner
                    | RevealPurpose::RedealHole,
                    RevealTarget::Hole { card_slot, .. },
                ) => card_slot < 2,
                (
                    RevealPurpose::Board,
                    RevealTarget::Board {
                        runout_index,
                        board_position,
                    },
                ) => runout_index < 2 && board_position < 5,
                _ => false,
            };
            if !target_matches {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal assignment {assignment_index} target is incompatible with purpose {:?}",
                    self.purpose
                )));
            }
            let target_key = assignment.target.canonical_key();
            if prior_key.is_some_and(|prior| prior >= target_key) {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal assignment {assignment_index} target order is not canonical"
                )));
            }
            prior_key = Some(target_key);
            let encrypted_index = usize::from(assignment.encrypted_card_index);
            if encrypted_index >= encrypted_indices.len() || encrypted_indices[encrypted_index] {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas reveal assignment {assignment_index} has duplicate/out-of-range encrypted card index {}",
                    assignment.encrypted_card_index
                )));
            }
            encrypted_indices[encrypted_index] = true;
        }
        Ok(())
    }
}

// ========== Reconstruct 状态 ==========

/// Canonical progress payload of an active reconstruction phase.
///
/// 52 张聚合密文的累加器已迁至
/// [`DeckState::reconstruct_accumulated`]（材料统一由 deck 载体承载，
/// HandPhase 不再内嵌变长大对象）；本结构只保留进度掩码。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReconstructState {
    /// 待提交 reconstruct deck 的玩家列表。
    pub pending_mask: SeatMask,
}

impl Default for ReconstructState {
    fn default() -> Self {
        Self { pending_mask: 0 }
    }
}

// ========== 超时配置 ==========

/// Canonical production timeout durations.
///
/// Durations are bounded `u32`; absolute consensus deadlines remain `u64` in [`HandPhase`].
/// The retired ready/hand-complete waits were never read by production execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TimeoutConfig {
    /// 洗牌超时（默认 10000ms）。
    pub shuffle_timeout_ms: u32,
    /// 揭牌超时（默认 10000ms）。
    pub reveal_timeout_ms: u32,
    /// 下注超时（默认 30000ms）。
    pub betting_timeout_ms: u32,
    /// 重构投票超时（默认 10000ms）。
    pub reconstruct_timeout_ms: u32,
    /// 摊牌展示时间（默认 3000ms）。
    pub showdown_display_ms: u32,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        // 默认值唯一权威在 core/constants.rs 的 DEFAULT_*_TIMEOUT_MS 常量组。
        Self {
            shuffle_timeout_ms: DEFAULT_SHUFFLE_TIMEOUT_MS,
            reveal_timeout_ms: DEFAULT_REVEAL_TIMEOUT_MS,
            betting_timeout_ms: DEFAULT_BETTING_TIMEOUT_MS,
            reconstruct_timeout_ms: DEFAULT_RECONSTRUCT_TIMEOUT_MS,
            showdown_display_ms: DEFAULT_SHOWDOWN_DISPLAY_MS,
        }
    }
}

// ========== Canonical hand phase projection ==========

/// Stable tag used by source normalization and the persisted `HandPhase` union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum HandPhaseTag {
    /// Waiting for an explicit start-hand command.
    Waiting = 0,
    /// One shuffle/remask participant must submit a proof.
    Shuffling = 1,
    /// Reveal-token assignments are being collected or materialized.
    Revealing = 2,
    /// Reconstruction contributions are being collected.
    Reconstructing = 3,
    /// A signed betting action is required.
    Betting = 4,
    /// Hole cards are visible and settlement waits for the display deadline.
    ShowdownDisplay = 5,
    /// A re-dealt hole card is collecting non-owner reveal tokens; betting is suspended.
    Redealing = 6,
}

/// Canonical tagged representation of a hand phase.
///
/// Reconstruction and reconstruct-shuffle temporarily suspend the reveal assignments that will
/// be restarted after the deck is rebuilt; that suspended payload belongs to the same variant and
/// is not treated as a second simultaneously active phase. Persisted schema v7+ and the runtime
/// table both store this union directly; legacy flattened layouts exist only in codec mirrors.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ShufflingPhase {
    /// Fresh per-hand shuffle. The outer round is canonically WAITING and no reveal is suspended.
    Initial {
        /// Canonical shuffle progress.
        state: ShuffleState,
        /// Non-zero absolute timeout deadline in every committed table state.
        deadline_ms: u64,
    },
    /// Shuffle after reconstruction, carrying the reveal that must resume afterwards.
    Reconstruct {
        /// Betting street that will resume after shuffling.
        street: u8,
        /// Canonical shuffle progress.
        state: ShuffleState,
        /// Reveal payload suspended while the reconstructed deck is shuffled.
        suspended_reveal: RevealTokenState,
        /// Non-zero absolute timeout deadline in every committed table state.
        deadline_ms: u64,
    },
}

impl ShufflingPhase {
    /// Typed shuffle purpose derived from the union variant.
    #[must_use]
    pub const fn purpose(&self) -> ShufflingPurpose {
        match self {
            Self::Initial { .. } => ShufflingPurpose::Initial,
            Self::Reconstruct { .. } => ShufflingPurpose::Reconstruct,
        }
    }

    /// Canonical outer betting street.
    #[must_use]
    pub const fn street(&self) -> u8 {
        match self {
            Self::Initial { .. } => ROUND_WAITING,
            Self::Reconstruct { street, .. } => *street,
        }
    }

    /// Borrow the common shuffle progress payload.
    #[must_use]
    pub const fn state(&self) -> &ShuffleState {
        match self {
            Self::Initial { state, .. } | Self::Reconstruct { state, .. } => state,
        }
    }

    /// Mutably borrow the common shuffle progress payload.
    pub const fn state_mut(&mut self) -> &mut ShuffleState {
        match self {
            Self::Initial { state, .. } | Self::Reconstruct { state, .. } => state,
        }
    }

    /// Borrow the active absolute deadline.
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        match self {
            Self::Initial { deadline_ms, .. } | Self::Reconstruct { deadline_ms, .. } => {
                *deadline_ms
            }
        }
    }

    /// Mutably borrow the active absolute deadline.
    pub const fn deadline_ms_mut(&mut self) -> &mut u64 {
        match self {
            Self::Initial { deadline_ms, .. } | Self::Reconstruct { deadline_ms, .. } => {
                deadline_ms
            }
        }
    }
}

/// Single active hand phase. Shuffle uses a nested union so fresh and reconstruct payloads cannot
/// encode each other's fields.
///
/// Borsh 采用手写定宽记录式实现——所有变体
/// 序列化结果恒等长（[`HAND_PHASE_RECORD_WIDTH`]），native 编码长度不再
/// 随阶段/揭示批大小漂移。变体判别值与历史 derive 枚举序一致。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandPhase {
    /// No hand transition is active.
    Waiting,
    /// Active shuffle state with a second-level tag distinguishing fresh and reconstruct shuffle.
    Shuffling {
        /// Type-safe shuffle payload; invalid purpose/reveal combinations are unrepresentable.
        phase: ShufflingPhase,
    },
    /// Active reveal-token collection/materialization.
    Revealing {
        /// Current betting street.
        street: u8,
        /// Canonical reveal payload.
        state: RevealTokenState,
        /// Non-zero absolute timeout deadline in every committed table state.
        deadline_ms: u64,
    },
    /// Active reconstruct collection with its resume target.
    Reconstructing {
        /// Betting street that will resume after reconstruction.
        street: u8,
        /// Canonical reconstruct payload.
        state: ReconstructState,
        /// Reveal payload suspended until reconstruction and reshuffle finish.
        suspended_reveal: RevealTokenState,
        /// Transcript epoch used by reconstruction proofs.
        epoch_ms: u64,
        /// Absolute timeout deadline for the reconstruction collection.
        deadline_ms: u64,
    },
    /// Active hole-card redeal: one replacement card's non-owner token collection with the
    /// suspended betting round stored for the completion restore. Suspends (rather than
    /// destroys) the betting phase so the redeal window digests back into the exact
    /// round/turn that requested it — betting state is never derivable after the fact.
    Redealing {
        /// Betting street the redeal was requested on (restored on completion).
        street: u8,
        /// Suspended betting round (current bets, min raise, completion state).
        round: BettingRound,
        /// Suspended actor (`NO_SEAT` when normalization is pending).
        current_turn: u8,
        /// Canonical reveal payload for the replacement card.
        state: RevealTokenState,
        /// Absolute timeout deadline for the redeal token collection.
        deadline_ms: u64,
    },
    /// Active betting round.
    Betting {
        /// Preflop/flop/turn/river discriminator.
        street: u8,
        /// Current bet and minimum raise.
        round: BettingRound,
        /// Current actor or `NO_SEAT` while deterministic normalization is pending.
        current_turn: u8,
        /// Absolute timeout deadline, including any consumed time bank extension.
        deadline_ms: u64,
    },
    /// Canonical showdown-display wait before settlement.
    ShowdownDisplay {
        /// Non-zero absolute settlement deadline.
        deadline_ms: u64,
    },
}

/// `HandPhase` 定宽记录宽度。最宽变体为 Reconstructing
/// （含 ≤18 条揭示分配 + 悬挂揭示负载）；超宽即序列化失败（fail-closed）。
const HAND_PHASE_RECORD_WIDTH: usize = 4096;

/// 变体判别值（与历史 derive 枚举序一致）。
const PHASE_TAG_WAITING: u8 = 0;
const PHASE_TAG_SHUFFLING: u8 = 1;
const PHASE_TAG_REVEALING: u8 = 2;
const PHASE_TAG_RECONSTRUCTING: u8 = 3;
const PHASE_TAG_BETTING: u8 = 4;
const PHASE_TAG_SHOWDOWN_DISPLAY: u8 = 5;
const PHASE_TAG_REDEALING: u8 = 6;

impl BorshSerialize for HandPhase {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let (tag, payload): (u8, Vec<u8>) = match self {
            HandPhase::Waiting => (PHASE_TAG_WAITING, Vec::new()),
            HandPhase::Shuffling { phase } => (PHASE_TAG_SHUFFLING, to_payload(&phase)?),
            HandPhase::Revealing {
                street,
                state,
                deadline_ms,
            } => {
                let mut payload = Vec::new();
                street.serialize(&mut payload)?;
                state.serialize(&mut payload)?;
                deadline_ms.serialize(&mut payload)?;
                (PHASE_TAG_REVEALING, payload)
            }
            HandPhase::Reconstructing {
                street,
                state,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            } => {
                let mut payload = Vec::new();
                street.serialize(&mut payload)?;
                state.serialize(&mut payload)?;
                suspended_reveal.serialize(&mut payload)?;
                epoch_ms.serialize(&mut payload)?;
                deadline_ms.serialize(&mut payload)?;
                (PHASE_TAG_RECONSTRUCTING, payload)
            }
            HandPhase::Redealing {
                street,
                round,
                current_turn,
                state,
                deadline_ms,
            } => {
                let mut payload = Vec::new();
                street.serialize(&mut payload)?;
                round.serialize(&mut payload)?;
                current_turn.serialize(&mut payload)?;
                state.serialize(&mut payload)?;
                deadline_ms.serialize(&mut payload)?;
                (PHASE_TAG_REDEALING, payload)
            }
            HandPhase::Betting {
                street,
                round,
                current_turn,
                deadline_ms,
            } => {
                let mut payload = Vec::new();
                street.serialize(&mut payload)?;
                round.serialize(&mut payload)?;
                current_turn.serialize(&mut payload)?;
                deadline_ms.serialize(&mut payload)?;
                (PHASE_TAG_BETTING, payload)
            }
            HandPhase::ShowdownDisplay { deadline_ms } => {
                (PHASE_TAG_SHOWDOWN_DISPLAY, to_payload(&deadline_ms)?)
            }
        };
        write_padded_record(writer, tag, &payload, HAND_PHASE_RECORD_WIDTH)
    }
}

impl BorshDeserialize for HandPhase {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let (tag, payload) = read_padded_record(reader, HAND_PHASE_RECORD_WIDTH)?;
        let mut slice = payload.as_slice();
        Ok(match tag {
            PHASE_TAG_WAITING => HandPhase::Waiting,
            PHASE_TAG_SHUFFLING => HandPhase::Shuffling {
                phase: ShufflingPhase::deserialize_reader(&mut slice)?,
            },
            PHASE_TAG_REVEALING => HandPhase::Revealing {
                street: u8::deserialize_reader(&mut slice)?,
                state: RevealTokenState::deserialize_reader(&mut slice)?,
                deadline_ms: u64::deserialize_reader(&mut slice)?,
            },
            PHASE_TAG_RECONSTRUCTING => HandPhase::Reconstructing {
                street: u8::deserialize_reader(&mut slice)?,
                state: ReconstructState::deserialize_reader(&mut slice)?,
                suspended_reveal: RevealTokenState::deserialize_reader(&mut slice)?,
                epoch_ms: u64::deserialize_reader(&mut slice)?,
                deadline_ms: u64::deserialize_reader(&mut slice)?,
            },
            PHASE_TAG_REDEALING => HandPhase::Redealing {
                street: u8::deserialize_reader(&mut slice)?,
                round: BettingRound::deserialize_reader(&mut slice)?,
                current_turn: u8::deserialize_reader(&mut slice)?,
                state: RevealTokenState::deserialize_reader(&mut slice)?,
                deadline_ms: u64::deserialize_reader(&mut slice)?,
            },
            PHASE_TAG_BETTING => HandPhase::Betting {
                street: u8::deserialize_reader(&mut slice)?,
                round: BettingRound::deserialize_reader(&mut slice)?,
                current_turn: u8::deserialize_reader(&mut slice)?,
                deadline_ms: u64::deserialize_reader(&mut slice)?,
            },
            PHASE_TAG_SHOWDOWN_DISPLAY => HandPhase::ShowdownDisplay {
                deadline_ms: u64::deserialize_reader(&mut slice)?,
            },
            other => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    format!("unknown HandPhase record tag {other}"),
                ));
            }
        })
    }
}

impl HandPhase {
    /// Stable union tag used by AIR projections.
    #[must_use]
    pub const fn tag(&self) -> HandPhaseTag {
        match self {
            Self::Waiting => HandPhaseTag::Waiting,
            Self::Shuffling { .. } => HandPhaseTag::Shuffling,
            Self::Revealing { .. } => HandPhaseTag::Revealing,
            Self::Reconstructing { .. } => HandPhaseTag::Reconstructing,
            Self::Betting { .. } => HandPhaseTag::Betting,
            Self::ShowdownDisplay { .. } => HandPhaseTag::ShowdownDisplay,
            Self::Redealing { .. } => HandPhaseTag::Redealing,
        }
    }
}

fn canonical_absolute_deadline(
    started_at: u64,
    timeout_ms: u32,
    label: &str,
) -> PokerL1Result<u64> {
    if started_at == 0 {
        return Ok(0);
    }
    started_at.checked_add(u64::from(timeout_ms)).ok_or_else(|| {
        PokerL1Error::Serialization(format!(
            "Texas {label} deadline overflows u64: started_at={started_at}, timeout_ms={timeout_ms}"
        ))
    })
}

// ========== Owner-readable hole-card ledger ==========

/// Fixed number of private hole-card slots retained for each seat.
pub const HOLE_CARD_SLOTS: usize = 2;

/// One authenticated partial ciphertext retained until its owner reveal.
///
/// Owner seat and hole-card slot are deliberately absent: the enclosing fixed ledger position is
/// their canonical representation. `encrypted_card_index` is lineage metadata only and never a
/// plaintext card identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PartialHoleCard {
    /// Original encrypted-deck index in the deck lineage that produced this partial.
    pub encrypted_card_index: u8,
    /// Ciphertext after every non-owner reveal layer has been removed.
    pub ciphertext: ElGamalCiphertext,
    /// The pre-reveal deck ciphertext every non-owner proof was generated against.
    ///
    /// Client reveal-token proofs bind the full ciphertext (the challenge hashes
    /// `c2`), while showdown decryption must use the partial ciphertext. Storing
    /// both keeps verification self-contained in this ledger (immune to a deck
    /// rebuild after reconstruct) without weakening the proof binding.
    pub full_ciphertext: ElGamalCiphertext,
}

impl PartialHoleCard {
    /// Construct one lineage-bound owner-readable partial ciphertext.
    #[must_use]
    pub const fn new(
        encrypted_card_index: u8,
        ciphertext: ElGamalCiphertext,
        full_ciphertext: ElGamalCiphertext,
    ) -> Self {
        Self {
            encrypted_card_index,
            ciphertext,
            full_ciphertext,
        }
    }
}

/// The two fixed partial-ciphertext slots belonging to one seat.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct SeatPartialHoleCards {
    slots: [Option<PartialHoleCard>; HOLE_CARD_SLOTS],
}

impl Default for SeatPartialHoleCards {
    fn default() -> Self {
        Self {
            slots: [None; HOLE_CARD_SLOTS],
        }
    }
}

/// Fixed `(seat, hole_slot)` owner-readable ciphertext ledger.
///
/// This removes variable-length state, duplicate owner fields and insertion-order semantics from
/// the consensus representation. All iteration is canonical: ascending seat, then slot 0 -> 1.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PartialHoleCardLedger {
    seats: [SeatPartialHoleCards; MAX_SEATS as usize],
}

impl Default for PartialHoleCardLedger {
    fn default() -> Self {
        Self {
            seats: std::array::from_fn(|_| SeatPartialHoleCards::default()),
        }
    }
}

impl PartialHoleCardLedger {
    /// Borrow the partial at one exact owner/slot position.
    #[must_use]
    pub fn get(&self, seat_index: u8, card_slot: u8) -> Option<&PartialHoleCard> {
        self.seats
            .get(usize::from(seat_index))?
            .slots
            .get(usize::from(card_slot))?
            .as_ref()
    }

    /// Insert exactly one owner-readable partial, rejecting invalid positions, duplicate slots and
    /// duplicate deck lineage indices anywhere in the hand.
    pub fn insert(
        &mut self,
        seat_index: u8,
        card_slot: u8,
        card: PartialHoleCard,
    ) -> PokerL1Result<()> {
        if seat_index >= MAX_SEATS || usize::from(card_slot) >= HOLE_CARD_SLOTS {
            return Err(PokerL1Error::Serialization(format!(
                "Texas partial hole-card position is out of range: seat={seat_index}, slot={card_slot}"
            )));
        }
        if usize::from(card.encrypted_card_index) >= CIPHER_DECK_SIZE {
            return Err(PokerL1Error::Serialization(format!(
                "Texas partial hole card has out-of-range deck index {}",
                card.encrypted_card_index
            )));
        }
        if self
            .iter()
            .any(|(_, _, prior)| prior.encrypted_card_index == card.encrypted_card_index)
        {
            return Err(PokerL1Error::Serialization(format!(
                "Texas partial hole-card ledger duplicates deck index {}",
                card.encrypted_card_index
            )));
        }
        let slot = &mut self.seats[usize::from(seat_index)].slots[usize::from(card_slot)];
        if slot.is_some() {
            return Err(PokerL1Error::Serialization(format!(
                "Texas partial hole-card slot is already occupied: seat={seat_index}, slot={card_slot}"
            )));
        }
        *slot = Some(card);
        Ok(())
    }

    /// Remove one exact ledger position.
    pub fn remove(&mut self, seat_index: u8, card_slot: u8) -> PokerL1Result<PartialHoleCard> {
        let slot = self
            .seats
            .get_mut(usize::from(seat_index))
            .and_then(|seat| seat.slots.get_mut(usize::from(card_slot)))
            .ok_or_else(|| {
                PokerL1Error::Serialization(format!(
                    "Texas partial hole-card position is out of range: seat={seat_index}, slot={card_slot}"
                ))
            })?;
        slot.take().ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "Texas partial hole-card slot is empty: seat={seat_index}, slot={card_slot}"
            ))
        })
    }

    #[must_use]
    /// Iterate one seat's live partials in canonical slot order.
    pub fn iter_for_seat(&self, seat_index: u8) -> impl Iterator<Item = (u8, &PartialHoleCard)> {
        self.seats
            .get(usize::from(seat_index))
            .into_iter()
            .flat_map(|seat| seat.slots.iter())
            .enumerate()
            .filter_map(|(slot, card)| card.as_ref().map(|card| (slot as u8, card)))
    }

    #[must_use]
    /// Iterate every live partial in canonical seat/slot order.
    pub fn iter(&self) -> impl Iterator<Item = (u8, u8, &PartialHoleCard)> {
        self.seats
            .iter()
            .enumerate()
            .flat_map(|(seat_index, seat)| {
                seat.slots
                    .iter()
                    .enumerate()
                    .filter_map(move |(card_slot, card)| {
                        card.as_ref()
                            .map(|card| (seat_index as u8, card_slot as u8, card))
                    })
            })
    }

    #[must_use]
    /// Return whether every fixed ledger slot is empty.
    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Clear every owner/slot position.
    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

// ========== 牌组状态 ==========

/// Runtime and persisted representation of the encrypted deck.
///
/// A table either has no active encrypted deck, or has the complete canonical 52-card deck.
/// Encoding this as a tagged union prevents partial or oversized decks from entering the state
/// machine and removes a variable-length witness dimension from downstream AIR projections.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum CipherDeck {
    /// No encrypted deck exists for the current hand lifecycle.
    Absent,
    /// Complete encrypted deck for an active hand.
    Active(Box<[ElGamalCiphertext; CIPHER_DECK_SIZE]>),
}

impl CipherDeck {
    /// Borrow the active deck, or an empty slice when absent.
    #[must_use]
    pub fn as_slice(&self) -> &[ElGamalCiphertext] {
        match self {
            Self::Absent => &[],
            Self::Active(cards) => cards.as_slice(),
        }
    }

    /// Copy the deck into the variable-length form required by host-native crypto APIs.
    #[must_use]
    pub fn to_vec(&self) -> Vec<ElGamalCiphertext> {
        self.as_slice().to_vec()
    }

    /// Number of ciphertexts: always zero or [`CIPHER_DECK_SIZE`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the encrypted deck is absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// Remove the active deck.
    pub fn clear(&mut self) {
        *self = Self::Absent;
    }

    /// Borrow one ciphertext by canonical deck index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&ElGamalCiphertext> {
        self.as_slice().get(index)
    }

    /// Iterate over the active deck.
    pub fn iter(&self) -> std::slice::Iter<'_, ElGamalCiphertext> {
        self.as_slice().iter()
    }
}

impl Default for CipherDeck {
    fn default() -> Self {
        Self::Absent
    }
}

impl TryFrom<Vec<ElGamalCiphertext>> for CipherDeck {
    type Error = PokerL1Error;

    fn try_from(cards: Vec<ElGamalCiphertext>) -> Result<Self, Self::Error> {
        if cards.is_empty() {
            return Ok(Self::Absent);
        }
        let actual = cards.len();
        let cards = cards.into_boxed_slice().try_into().map_err(|_| {
            PokerL1Error::Serialization(format!(
                "Texas encrypted deck has {actual} cards, expected 0 or {CIPHER_DECK_SIZE}"
            ))
        })?;
        Ok(Self::Active(cards))
    }
}

impl From<[ElGamalCiphertext; CIPHER_DECK_SIZE]> for CipherDeck {
    fn from(cards: [ElGamalCiphertext; CIPHER_DECK_SIZE]) -> Self {
        Self::Active(Box::new(cards))
    }
}

impl Deref for CipherDeck {
    type Target = [ElGamalCiphertext];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for CipherDeck {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Absent => panic!("cannot mutably borrow an absent Texas encrypted deck"),
            Self::Active(cards) => cards.as_mut_slice(),
        }
    }
}

impl Index<usize> for CipherDeck {
    type Output = ElGamalCiphertext;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl IndexMut<usize> for CipherDeck {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match self {
            Self::Absent => panic!("cannot index an absent Texas encrypted deck"),
            Self::Active(cards) => &mut cards[index],
        }
    }
}

impl<'a> IntoIterator for &'a CipherDeck {
    type Item = &'a ElGamalCiphertext;
    type IntoIter = std::slice::Iter<'a, ElGamalCiphertext>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// 牌组状态（镜像 Move `DeckState`，table.move:211-217）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DeckState {
    /// 加密牌组（52 个 ElGamalCiphertext）。
    pub encrypted: CipherDeck,
    /// Seats whose public-key encryption layer is still present in the deck lineage.
    pub contributor_mask: SeatMask,
    /// 已从牌组发出的牌数量。
    pub cards_dealt: u8,
    /// Owner-private partial ciphertexts at canonical `(seat, hole_slot)` positions.
    pub owner_readable_hole_cards: PartialHoleCardLedger,
    /// 重构累加器（自 `ReconstructState` 迁入）：已验证
    /// contribution 逐次合入 canonical aggregate-key base deck 后的 52 张
    /// 密文。`None` 表示尚无玩家提交。材料统一由 deck 载体承载，HandPhase
    /// 不再内嵌变长大对象。
    pub reconstruct_accumulated: Option<Vec<ElGamalCiphertext>>,
}

impl Default for DeckState {
    fn default() -> Self {
        Self {
            encrypted: CipherDeck::Absent,
            contributor_mask: 0,
            cards_dealt: 0,
            owner_readable_hole_cards: PartialHoleCardLedger::default(),
            reconstruct_accumulated: None,
        }
    }
}

// ========== 桌台主结构 ==========

/// Canonical rules that define poker semantics but are not hand-local mutable state.
///
/// Keeping these facts in one value prevents flat-field drift and is the first migration step
/// toward storing the rules as a separately opened object bound by `rules_hash`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableRules {
    /// Maximum occupied seat capacity (`2..=9`).
    pub max_players: u8,
    /// Small blind amount.
    pub small_blind: u64,
    /// Big blind amount.
    pub big_blind: u64,
    /// Canonical timeout durations.
    pub timeout_config: TimeoutConfig,
    /// Ante mode (`NONE`, `NORMAL`, or `BBA`).
    pub ante_mode: u8,
    /// Ante debit per configured payer.
    pub ante_amount: u64,
    /// Rake mode (`NONE` or `PERCENTAGE`).
    pub rake_mode: u8,
    /// Rake rate in basis points.
    pub rake_bps: u16,
    /// Maximum rake charged for one hand.
    pub rake_cap: u64,
    /// Run-it-twice policy.
    pub rit_mode: u8,
}

/// Low-frequency display metadata stored as its own immutable ObjectDb object.
///
/// v34 起展示名不再进入共识热状态（`TexasPokerTable` 不携带 `name`）：
/// 本对象按 `table_metadata_object_id(table_id)` 寻址，仅供 events、RPC 与
/// create-table 验证路径之外的 UI/运营消费；hot state 不绑定其 digest。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableMetadata {
    /// Human-readable table name.
    pub name: String,
}

impl TableMetadata {
    /// Reject metadata that cannot be represented by the existing create-table ABI.
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        if self.name.len() > u32::MAX as usize {
            return Err(PokerL1Error::Serialization(
                "Texas table name exceeds canonical Borsh length".into(),
            ));
        }
        Ok(())
    }
}

/// Low-frequency administrator policy opened alongside the hot table state.
///
/// The current production ABI has exactly one administrator: the authenticated creator.  Keeping
/// it in a typed policy object establishes the correct hash/opening boundary without inventing an
/// unaudited multi-admin mutation path.  A future policy version can add a canonical admin set.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct GovernancePolicy {
    /// Address authorized for creator/admin commands in the current policy version.
    pub creator: Address,
}

impl GovernancePolicy {
    /// Return whether `caller` is authorized by this policy version.
    #[must_use]
    pub fn authorizes(&self, caller: &Address) -> bool {
        self.creator == *caller
    }

    /// Reject an uninitialized policy opening.
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        if self.creator == EMPTY_PLAYER {
            return Err(PokerL1Error::Serialization(
                "Texas governance creator is empty".into(),
            ));
        }
        Ok(())
    }
}

/// One immutable context object committed by the hot table state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableContextBinding {
    /// Deterministically derived ObjectDb ID of the opening.
    pub object_id: ObjectID,
    /// Domain-separated digest of `(table_id, opening)`.
    pub digest: [u8; 32],
}

/// The low-frequency openings committed by a hot table.
///
/// v35-hot 起 metadata（展示名）不再被热状态 digest 绑定：名字非共识，
/// 由独立 metadata 对象按 `table_metadata_object_id` 寻址，仅供热/UI 消费。
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableContextBindings {
    /// Poker rules binding.
    pub rules: TableContextBinding,
    /// Administrator policy binding.
    pub governance: TableContextBinding,
}

/// Resolved low-frequency values supplied when opening a hot table object.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TableContextOpenings {
    /// Poker rules opening.
    pub rules: TableRules,
    /// Administrator policy opening.
    pub governance: GovernancePolicy,
}

impl TableContextOpenings {
    /// Construct the openings represented by a resolved runtime table.
    #[must_use]
    pub fn from_table(table: &TexasPokerTable) -> Self {
        Self {
            rules: table.rules.clone(),
            governance: GovernancePolicy {
                creator: table.creator,
            },
        }
    }

    /// Validate every opening before hashing or hydrating runtime state.
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        self.rules.validate_canonical()?;
        self.governance.validate_canonical()
    }
}

impl TableRules {
    /// Construct the default optional rules around a validated seat/blind configuration.
    #[must_use]
    pub fn new(max_players: u8, small_blind: u64, big_blind: u64) -> Self {
        Self {
            max_players,
            small_blind,
            big_blind,
            timeout_config: TimeoutConfig::default(),
            ante_mode: super::constants::ANTE_MODE_NONE,
            ante_amount: 0,
            rake_mode: super::constants::RAKE_MODE_NONE,
            rake_bps: super::constants::DEFAULT_RAKE_BPS,
            rake_cap: super::constants::DEFAULT_RAKE_CAP,
            rit_mode: super::constants::RIT_MODE_DISABLED,
        }
    }

    /// Reject rule combinations that cannot define a canonical Texas table.
    pub fn validate_canonical(&self) -> PokerL1Result<()> {
        if !(2..=MAX_SEATS).contains(&self.max_players) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas max_players {} is outside 2..={MAX_SEATS}",
                self.max_players
            )));
        }
        if self.big_blind == 0 || self.small_blind > self.big_blind {
            return Err(PokerL1Error::Serialization(format!(
                "Texas blind configuration small={} big={} is not canonical",
                self.small_blind, self.big_blind
            )));
        }
        if !matches!(
            self.ante_mode,
            ANTE_MODE_NONE | ANTE_MODE_NORMAL | ANTE_MODE_BBA
        ) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas ante mode {} is not canonical",
                self.ante_mode
            )));
        }
        if !matches!(self.rake_mode, RAKE_MODE_NONE | RAKE_MODE_PERCENTAGE)
            || self.rake_bps > 10_000
        {
            return Err(PokerL1Error::Serialization(format!(
                "Texas rake configuration mode={} bps={} is not canonical",
                self.rake_mode, self.rake_bps
            )));
        }
        if !matches!(self.rit_mode, RIT_MODE_DISABLED | RIT_MODE_TWICE) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas RIT mode {} is not canonical",
                self.rit_mode
            )));
        }
        Ok(())
    }
}

/// Texas Poker 桌台（镜像 Move `Table` struct，table.move:270-304）。
///
/// 这是预编译合约的核心状态对象，borsh 编码后存入 ObjectDb，
/// ObjectID = `reserved::texas_poker_contract_id()`（`0xFF..02`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TexasPokerTable {
    /// 桌台 ObjectID（保留 `0xFF..02`）。
    pub id: ObjectID,
    /// 桌台创建者（管理类方法权限基准：start_hand/kick_player/force_fold）。
    ///
    /// P0-2：在 `dispatch_create_table` 时记录为 `context.caller`。
    /// 管理类方法在 dispatch 层校验 `caller == creator`，使权限可被
    /// `poker_texas_air` 电路约束（与同步电路目标契合）。
    /// 旧对象反序列化时若为 `EMPTY_PLAYER`，管理类校验会失败，需 governance 重设。
    pub creator: Address,
    /// Immutable/low-frequency poker semantics, physically separated from hand-local state.
    pub rules: TableRules,

    /// 座位列表（长度 = max_players）。
    /// 座位槽位（定宽，2026-09-10）：恒 9 槽，索引
    /// `[0, max_players)` 之外的槽位必须保持 `Vacant` 填充
    /// （`validate_state_schema` 强制）。此前为 `Vec<Seat>`，其长度恒等于
    /// `max_players`（不变式由本函数历史强制）；定宽后整表 borsh 序列化
    /// 长度不再随桌型配置漂移（AIR/trace 友好）。
    pub seats: [Seat; 9],
    /// 本轮已经完成行动的座位集合。
    pub acted_mask: SeatMask,
    /// 请求在本手结束后离场的座位集合。
    pub leave_after_hand_mask: SeatMask,
    /// 庄家位（button seat_index）。
    pub button: u8,

    /// 上一手大盲座位（dead button 盲注轮转轨道，`NO_SEAT` 表示尚无历史）。
    ///
    /// 完整实现 dead button 规则（Robert's Rules of Poker §4.2b）：大盲按
    /// 轮转归属——本手大盲 = 上一手大盲之后顺时针第一个参与座位；小盲 =
    /// 上一手大盲座位本身（单挑时为另一参与者），该座位空缺/离场/等待时
    /// 本手无小盲（dead small blind）。跨手持久，仅 `post_blinds` 更新。
    pub last_bb_seat: u8,

    /// 当前底池。
    pub pot: u64,
    /// 公共牌（最多 5 张：flop 3 + turn 1 + river 1）。
    pub community_cards: BoardCards,

    /// 唯一运行时手牌阶段；互斥 phase payload 与当前 deadline 只保存于 active variant。
    pub hand_phase: HandPhase,

    /// 加密牌组状态。
    pub deck_state: DeckState,

    /// 桌台实际锁仓的 ZCN 总额。
    ///
    /// 这是嵌入 Texas shared object 的 `TableVault.balance`。join/addon/rebuy 的生产
    /// precompile 路径必须先消费等额 native Coin UTXO 才能增加该值；任何退款/离场
    /// 创建 Coin 输出前必须先减少该值。
    pub chip_pool: u64,

    /// Current hand's two-runout state. Empty outside an active RIT hand.
    pub run_it_twice_state: RunItTwiceState,

    /// 当前手牌序号。
    ///
    /// 初始为 0；每当一次成功 dispatch 产生 `HandStarted` 事件时递增。
    /// 该值随桌台状态持久化，并写入 ProveTask 公开输入，避免跨手牌任务混淆。
    pub hand_id: u32,

    /// 成功改变桌台状态的 dispatch 序号。
    ///
    /// 初始为 0；每次成功且 `pre_table != post_table` 的 dispatch 严格递增一次。
    /// 无状态变化的 permissionless `tick` 不消耗序号，保证证明任务连续。
    pub call_seq: u32,
}

impl Deref for TexasPokerTable {
    type Target = TableRules;

    fn deref(&self) -> &Self::Target {
        &self.rules
    }
}

impl DerefMut for TexasPokerTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rules
    }
}

impl TexasPokerTable {
    /// 座位填充不变式：`max_players` 之外的槽位必须为 `Vacant`。
    #[must_use]
    pub fn padding_seats_are_vacant(&self) -> bool {
        self.seats[usize::from(self.max_players)..]
            .iter()
            .all(|seat| matches!(seat, Seat::Vacant { .. }))
    }

    /// Canonical betting street/outer round projection.
    #[must_use]
    pub const fn round_state(&self) -> u8 {
        match &self.hand_phase {
            HandPhase::Waiting => ROUND_WAITING,
            HandPhase::Shuffling { phase } => phase.street(),
            HandPhase::Revealing { street, .. }
            | HandPhase::Reconstructing { street, .. }
            | HandPhase::Redealing { street, .. }
            | HandPhase::Betting { street, .. } => *street,
            HandPhase::ShowdownDisplay { .. } => ROUND_SHOWDOWN,
        }
    }

    /// Canonical betting-round payload, if the active hand phase is betting.
    #[must_use]
    pub const fn betting_round(&self) -> Option<BettingRound> {
        match &self.hand_phase {
            HandPhase::Betting { round, .. } => Some(*round),
            _ => None,
        }
    }

    /// Canonical current betting actor or [`NO_SEAT`] outside an actionable betting phase.
    #[must_use]
    pub const fn current_turn(&self) -> u8 {
        match &self.hand_phase {
            HandPhase::Betting { current_turn, .. } => *current_turn,
            _ => NO_SEAT,
        }
    }

    /// Read-only projection of the active shuffle payload.
    #[must_use]
    pub fn shuffle_state(&self) -> Cow<'_, ShuffleState> {
        match &self.hand_phase {
            HandPhase::Shuffling { phase } => Cow::Borrowed(phase.state()),
            _ => Cow::Owned(ShuffleState::default()),
        }
    }

    /// Typed purpose of the active shuffle phase.
    #[must_use]
    pub const fn shuffling_purpose(&self) -> Option<ShufflingPurpose> {
        match &self.hand_phase {
            HandPhase::Shuffling { phase } => Some(phase.purpose()),
            _ => None,
        }
    }

    /// Legacy numeric shuffle-phase projection used by existing event/AIR schemas.
    #[must_use]
    pub const fn shuffle_phase(&self) -> u8 {
        match self.shuffling_purpose() {
            Some(purpose) => purpose.legacy_phase(),
            None => SHUFFLE_PHASE_NONE,
        }
    }

    /// Read-only projection of the active or reconstruction-suspended reveal payload.
    #[must_use]
    pub const fn reveal_token_state(&self) -> Option<&RevealTokenState> {
        match &self.hand_phase {
            HandPhase::Revealing { state, .. } => Some(state),
            HandPhase::Reconstructing {
                suspended_reveal, ..
            } => Some(suspended_reveal),
            HandPhase::Redealing { state, .. } => Some(state),
            HandPhase::Shuffling {
                phase:
                    ShufflingPhase::Reconstruct {
                        suspended_reveal, ..
                    },
            } => Some(suspended_reveal),
            _ => None,
        }
    }

    /// Stable numeric reveal phase used by current events and AIR public inputs.
    #[must_use]
    pub const fn reveal_phase(&self) -> u8 {
        match &self.hand_phase {
            HandPhase::Revealing { street, state, .. }
            | HandPhase::Reconstructing {
                street,
                suspended_reveal: state,
                ..
            }
            | HandPhase::Redealing { street, state, .. }
            | HandPhase::Shuffling {
                phase:
                    ShufflingPhase::Reconstruct {
                        street,
                        suspended_reveal: state,
                        ..
                    },
            } => state.purpose.legacy_phase(*street),
            _ => REVEAL_PHASE_NONE,
        }
    }

    /// Canonical reveal assignments, or an empty slice when no reveal is active or suspended.
    #[must_use]
    pub fn reveal_assignments(&self) -> &[RevealAssignment] {
        self.reveal_token_state()
            .map_or(&[], |state| state.assignments.as_slice())
    }

    /// Read-only compatibility projection of the active reconstruct payload.
    #[must_use]
    pub fn reconstruct_state(&self) -> Cow<'_, ReconstructState> {
        match &self.hand_phase {
            HandPhase::Reconstructing { state, .. } => Cow::Borrowed(state),
            _ => Cow::Owned(ReconstructState::default()),
        }
    }

    /// Whether reconstruction collection is the active hand phase.
    #[must_use]
    pub const fn is_reconstructing(&self) -> bool {
        matches!(self.hand_phase, HandPhase::Reconstructing { .. })
    }

    /// Legacy numeric reconstruction-phase projection used by the current AIR schema.
    #[must_use]
    pub const fn reconstruct_phase(&self) -> u8 {
        if self.is_reconstructing() {
            RECONSTRUCT_PHASE_COLLECTING
        } else {
            RECONSTRUCT_PHASE_NONE
        }
    }

    /// Mutable payload of the active shuffle variant.
    pub fn active_shuffle_state_mut(&mut self) -> PokerL1Result<&mut ShuffleState> {
        match &mut self.hand_phase {
            HandPhase::Shuffling { phase } => Ok(phase.state_mut()),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active shuffle phase".into(),
            )),
        }
    }

    /// Mutable payload of the active reveal variant.
    pub fn active_reveal_state_mut(&mut self) -> PokerL1Result<&mut RevealTokenState> {
        match &mut self.hand_phase {
            HandPhase::Revealing { state, .. } | HandPhase::Redealing { state, .. } => Ok(state),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active reveal phase".into(),
            )),
        }
    }

    /// Take the active or suspended reveal payload while performing an atomic phase transition.
    pub fn take_reveal_payload(&mut self) -> PokerL1Result<RevealTokenState> {
        let phase = std::mem::replace(&mut self.hand_phase, HandPhase::Waiting);
        match phase {
            HandPhase::Revealing { state, .. } => Ok(state),
            HandPhase::Reconstructing {
                suspended_reveal, ..
            } => Ok(suspended_reveal),
            HandPhase::Shuffling {
                phase:
                    ShufflingPhase::Reconstruct {
                        suspended_reveal, ..
                    },
            } => Ok(suspended_reveal),
            other => {
                self.hand_phase = other;
                Err(PokerL1Error::Serialization(
                    "Texas phase has no active or suspended reveal payload".into(),
                ))
            }
        }
    }

    /// Mutable payload of the active reconstruction variant.
    pub fn active_reconstruct_state_mut(&mut self) -> PokerL1Result<&mut ReconstructState> {
        match &mut self.hand_phase {
            HandPhase::Reconstructing { state, .. } => Ok(state),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active reconstruct phase".into(),
            )),
        }
    }

    /// Transcript epoch of the active reconstruction variant.
    #[must_use]
    pub const fn reconstruct_epoch_ms(&self) -> Option<u64> {
        match &self.hand_phase {
            HandPhase::Reconstructing { epoch_ms, .. } => Some(*epoch_ms),
            _ => None,
        }
    }

    /// Absolute deadline of the active reconstruction phase.
    pub fn reconstruct_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        match &self.hand_phase {
            HandPhase::Reconstructing {
                epoch_ms,
                deadline_ms,
                ..
            } => {
                let expected = canonical_absolute_deadline(
                    *epoch_ms,
                    self.timeout_config.reconstruct_timeout_ms,
                    "reconstruct",
                )?;
                if *deadline_ms != expected {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas reconstruct deadline mismatch: encoded={deadline_ms}, expected={expected}"
                    )));
                }
                Ok(Some(*deadline_ms))
            }
            _ => Ok(None),
        }
    }

    /// Arm the active reconstruction deadline from consensus time.
    pub fn arm_reconstruct_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        let deadline_ms = canonical_absolute_deadline(
            now_ms,
            self.timeout_config.reconstruct_timeout_ms,
            "reconstruct",
        )?;
        match &mut self.hand_phase {
            HandPhase::Reconstructing {
                epoch_ms,
                deadline_ms: stored,
                ..
            } => {
                *epoch_ms = now_ms;
                *stored = deadline_ms;
                Ok(deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot arm reconstruct deadline outside phase".into(),
            )),
        }
    }

    /// Absolute deadline of the active shuffle phase.
    pub fn shuffle_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        match &self.hand_phase {
            HandPhase::Shuffling { phase } => Ok(Some(phase.deadline_ms())),
            _ => Ok(None),
        }
    }

    /// Arm the active shuffle deadline from consensus time.
    pub fn arm_shuffle_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        let deadline_ms =
            canonical_absolute_deadline(now_ms, self.timeout_config.shuffle_timeout_ms, "shuffle")?;
        match &mut self.hand_phase {
            HandPhase::Shuffling { phase } => {
                *phase.deadline_ms_mut() = deadline_ms;
                Ok(deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot arm shuffle deadline outside phase".into(),
            )),
        }
    }

    /// Disarm the active shuffle deadline when its canonical actor changes.
    pub fn disarm_shuffle_deadline(&mut self) -> PokerL1Result<()> {
        match &mut self.hand_phase {
            HandPhase::Shuffling { phase } => {
                *phase.deadline_ms_mut() = 0;
                Ok(())
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot disarm shuffle deadline outside phase".into(),
            )),
        }
    }

    /// Absolute deadline of the active reveal phase.
    pub fn reveal_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        match &self.hand_phase {
            HandPhase::Revealing { deadline_ms, .. } | HandPhase::Redealing { deadline_ms, .. } => {
                Ok(Some(*deadline_ms))
            }
            _ => Ok(None),
        }
    }

    /// Arm the active reveal deadline from consensus time.
    pub fn arm_reveal_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.reveal_deadline_ms()?.is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot arm reveal deadline outside phase".into(),
            ));
        }
        let deadline_ms =
            canonical_absolute_deadline(now_ms, self.timeout_config.reveal_timeout_ms, "reveal")?;
        match &mut self.hand_phase {
            HandPhase::Revealing {
                deadline_ms: stored,
                ..
            } => {
                *stored = deadline_ms;
                Ok(deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot arm reveal deadline outside phase".into(),
            )),
        }
    }

    /// Absolute deadline of the active betting phase.
    pub fn betting_deadline_ms(&self) -> PokerL1Result<Option<u64>> {
        match &self.hand_phase {
            HandPhase::Betting { deadline_ms, .. } => Ok(Some(*deadline_ms)),
            _ => Ok(None),
        }
    }

    /// Arm the active betting deadline from consensus time.
    pub fn arm_betting_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        let deadline_ms =
            canonical_absolute_deadline(now_ms, self.timeout_config.betting_timeout_ms, "betting")?;
        match &mut self.hand_phase {
            HandPhase::Betting {
                deadline_ms: stored,
                ..
            } => {
                *stored = deadline_ms;
                Ok(deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot arm betting deadline outside phase".into(),
            )),
        }
    }

    /// Extend the active betting deadline after consuming time bank.
    pub fn extend_betting_deadline(&mut self, extension_ms: u64) -> PokerL1Result<u64> {
        match &mut self.hand_phase {
            HandPhase::Betting { deadline_ms, .. } if *deadline_ms != 0 => {
                *deadline_ms = deadline_ms.checked_add(extension_ms).ok_or_else(|| {
                    PokerL1Error::Serialization(
                        "Texas betting deadline extension overflows u64".into(),
                    )
                })?;
                Ok(*deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot extend an unarmed betting deadline".into(),
            )),
        }
    }

    /// Absolute showdown-display settlement deadline.
    #[must_use]
    pub const fn showdown_deadline_ms(&self) -> Option<u64> {
        match &self.hand_phase {
            HandPhase::ShowdownDisplay { deadline_ms } => Some(*deadline_ms),
            _ => None,
        }
    }

    /// Arm the showdown-display settlement deadline from consensus time.
    pub fn arm_showdown_deadline(&mut self, now_ms: u64) -> PokerL1Result<u64> {
        if self.showdown_deadline_ms().is_none() {
            return Err(PokerL1Error::Serialization(
                "cannot arm showdown deadline outside display phase".into(),
            ));
        }
        let deadline_ms = now_ms
            .checked_add(u64::from(self.timeout_config.showdown_display_ms))
            .ok_or_else(|| {
                PokerL1Error::Serialization("Texas showdown deadline overflows u64".into())
            })?;
        match &mut self.hand_phase {
            HandPhase::ShowdownDisplay {
                deadline_ms: stored,
            } => {
                *stored = deadline_ms;
                Ok(deadline_ms)
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot arm showdown deadline outside display phase".into(),
            )),
        }
    }

    /// Arm a newly-created or actor-rotated active phase before it can be committed.
    ///
    /// Business helpers may use zero as a dispatch-local placeholder while composing several
    /// deterministic transitions. `normalize_until_blocked` calls this method with the
    /// authenticated consensus timestamp before validating or exposing the resulting state.
    pub fn arm_active_deadline_if_needed(&mut self, now_ms: u64) -> PokerL1Result<bool> {
        if now_ms == 0 {
            return Err(PokerL1Error::Serialization(
                "Texas active phase requires a non-zero consensus timestamp".into(),
            ));
        }
        match &self.hand_phase {
            HandPhase::Waiting => Ok(false),
            HandPhase::Shuffling { phase } if phase.deadline_ms() == 0 => {
                self.arm_shuffle_deadline(now_ms)?;
                Ok(true)
            }
            HandPhase::Revealing { deadline_ms: 0, .. } => {
                self.arm_reveal_deadline(now_ms)?;
                Ok(true)
            }
            HandPhase::Reconstructing {
                epoch_ms: 0,
                deadline_ms: 0,
                ..
            } => {
                self.arm_reconstruct_deadline(now_ms)?;
                Ok(true)
            }
            HandPhase::Reconstructing {
                epoch_ms,
                deadline_ms,
                ..
            } if *epoch_ms == 0 || *deadline_ms == 0 => Err(PokerL1Error::Serialization(
                "Texas reconstruct epoch/deadline must both be zero or both be armed".into(),
            )),
            HandPhase::Betting { deadline_ms: 0, .. } => {
                self.arm_betting_deadline(now_ms)?;
                Ok(true)
            }
            HandPhase::ShowdownDisplay { deadline_ms: 0 } => {
                self.arm_showdown_deadline(now_ms)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Mutable payload of the active betting variant.
    pub fn active_betting_round_mut(&mut self) -> PokerL1Result<&mut BettingRound> {
        match &mut self.hand_phase {
            HandPhase::Betting { round, .. } => Ok(round),
            _ => Err(PokerL1Error::Serialization(
                "Texas table is not in an active betting phase".into(),
            )),
        }
    }

    /// Update the actor inside the current betting variant and disarm its deadline.
    pub fn set_betting_turn(&mut self, current_turn: u8) -> PokerL1Result<()> {
        if current_turn != NO_SEAT && current_turn >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas current turn {current_turn} is outside max_players {}",
                self.max_players
            )));
        }
        match &mut self.hand_phase {
            HandPhase::Betting {
                current_turn: stored,
                deadline_ms,
                ..
            } => {
                *stored = current_turn;
                *deadline_ms = 0;
                Ok(())
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot set current turn outside betting".into(),
            )),
        }
    }

    /// Disarm the current betting actor's deadline after an accepted action/turn change.
    pub fn disarm_betting_deadline(&mut self) -> PokerL1Result<()> {
        match &mut self.hand_phase {
            HandPhase::Betting { deadline_ms, .. } => {
                *deadline_ms = 0;
                Ok(())
            }
            _ => Err(PokerL1Error::Serialization(
                "cannot disarm betting deadline outside betting".into(),
            )),
        }
    }

    /// Remove one seat from the payload of the single active protocol variant.
    ///
    /// Betting has no protocol participant mask; reconstruction and reconstruct-shuffle also
    /// carry a suspended reveal payload whose pending bits must be scrubbed consistently.
    pub fn remove_seat_from_active_phase(&mut self, seat_index: u8) -> PokerL1Result<()> {
        if seat_index >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "cannot remove out-of-range seat {seat_index} from Texas phase"
            )));
        }
        match &mut self.hand_phase {
            HandPhase::Reconstructing {
                state,
                suspended_reveal,
                ..
            } => {
                seat_mask_remove(&mut state.pending_mask, seat_index);
                for assignment in &mut suspended_reveal.assignments {
                    seat_mask_remove(&mut assignment.pending_mask, seat_index);
                }
            }
            HandPhase::Shuffling { phase } => {
                let state = phase.state_mut();
                seat_mask_remove(&mut state.pending_mask, seat_index);
                seat_mask_remove(&mut state.completed_mask, seat_index);
                if let ShufflingPhase::Reconstruct {
                    suspended_reveal: reveal,
                    ..
                } = phase
                {
                    for assignment in &mut reveal.assignments {
                        seat_mask_remove(&mut assignment.pending_mask, seat_index);
                    }
                }
            }
            HandPhase::Revealing { state, .. } => {
                for assignment in &mut state.assignments {
                    seat_mask_remove(&mut assignment.pending_mask, seat_index);
                }
            }
            HandPhase::Redealing { state, .. } => {
                for assignment in &mut state.assignments {
                    seat_mask_remove(&mut assignment.pending_mask, seat_index);
                }
            }
            HandPhase::Waiting | HandPhase::Betting { .. } | HandPhase::ShowdownDisplay { .. } => {}
        }
        Ok(())
    }

    /// Atomically enter the idle phase.
    pub fn enter_waiting(&mut self) {
        self.hand_phase = HandPhase::Waiting;
    }

    /// Atomically enter the fresh per-hand shuffle phase.
    pub fn enter_initial_shuffling(
        &mut self,
        state: ShuffleState,
        started_at_ms: u64,
    ) -> PokerL1Result<()> {
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.shuffle_timeout_ms,
            "shuffle",
        )?;
        self.hand_phase = HandPhase::Shuffling {
            phase: ShufflingPhase::Initial { state, deadline_ms },
        };
        Ok(())
    }

    /// Atomically enter a reconstruct shuffle with the reveal that must resume afterwards.
    pub fn enter_reconstruct_shuffling(
        &mut self,
        street: u8,
        state: ShuffleState,
        suspended_reveal: RevealTokenState,
        started_at_ms: u64,
    ) -> PokerL1Result<()> {
        if !matches!(
            street,
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER | ROUND_SHOWDOWN
        ) {
            return Err(PokerL1Error::Serialization(
                "Texas reconstruct shuffle is outside a live street".into(),
            ));
        }
        suspended_reveal.validate_for_street(street)?;
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.shuffle_timeout_ms,
            "shuffle",
        )?;
        self.hand_phase = HandPhase::Shuffling {
            phase: ShufflingPhase::Reconstruct {
                street,
                state,
                suspended_reveal,
                deadline_ms,
            },
        };
        Ok(())
    }

    /// Atomically enter a reveal-token phase.
    pub fn enter_revealing(
        &mut self,
        street: u8,
        state: RevealTokenState,
        started_at_ms: u64,
    ) -> PokerL1Result<()> {
        state.validate_for_street(street)?;
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.reveal_timeout_ms,
            "reveal",
        )?;
        self.hand_phase = HandPhase::Revealing {
            street,
            state,
            deadline_ms,
        };
        Ok(())
    }

    /// Atomically suspend a reveal and enter reconstruction collection.
    pub fn enter_reconstructing(
        &mut self,
        street: u8,
        state: ReconstructState,
        suspended_reveal: RevealTokenState,
        epoch_ms: u64,
    ) -> PokerL1Result<()> {
        suspended_reveal.validate_for_street(street)?;
        let deadline_ms = canonical_absolute_deadline(
            epoch_ms,
            self.timeout_config.reconstruct_timeout_ms,
            "reconstruct",
        )?;
        self.hand_phase = HandPhase::Reconstructing {
            street,
            state,
            suspended_reveal,
            epoch_ms,
            deadline_ms,
        };
        Ok(())
    }

    /// Atomically suspend a betting round and enter a hole-card redeal token collection.
    ///
    /// `round`/`current_turn` are the betting-phase payloads being suspended; they are
    /// restored verbatim by the [`RevealPurpose::RedealHole`] completion transition, which
    /// hands them to [`Self::enter_betting`] for a fresh betting deadline.
    pub fn enter_redealing(
        &mut self,
        street: u8,
        round: BettingRound,
        current_turn: u8,
        state: RevealTokenState,
        started_at_ms: u64,
    ) -> PokerL1Result<()> {
        if !matches!(
            street,
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
        ) {
            return Err(PokerL1Error::Serialization(
                "Texas redeal is outside a live betting street".into(),
            ));
        }
        state.validate_for_street(street)?;
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.reveal_timeout_ms,
            "redeal",
        )?;
        self.hand_phase = HandPhase::Redealing {
            street,
            round,
            current_turn,
            state,
            deadline_ms,
        };
        Ok(())
    }

    /// Atomically enter an actionable betting round.
    pub fn enter_betting(
        &mut self,
        street: u8,
        round: BettingRound,
        current_turn: u8,
        started_at_ms: u64,
    ) -> PokerL1Result<()> {
        if current_turn != NO_SEAT && current_turn >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas current turn {current_turn} is outside max_players {}",
                self.max_players
            )));
        }
        let deadline_ms = canonical_absolute_deadline(
            started_at_ms,
            self.timeout_config.betting_timeout_ms,
            "betting",
        )?;
        self.hand_phase = HandPhase::Betting {
            street,
            round,
            current_turn,
            deadline_ms,
        };
        Ok(())
    }

    /// Atomically enter the showdown display wait after all hole cards are materialized.
    pub fn enter_showdown_display(&mut self, deadline_ms: u64) {
        self.hand_phase = HandPhase::ShowdownDisplay { deadline_ms };
    }

    fn aggregated_pk_for_contributor_mask(
        &self,
        contributor_mask: SeatMask,
    ) -> PokerL1Result<Option<ECPoint>> {
        if !seat_mask_is_canonical(contributor_mask, self.max_players) {
            return Err(PokerL1Error::Serialization(
                "Texas deck contributor mask contains out-of-range bits".into(),
            ));
        }
        let mut aggregate: Option<ECPoint> = None;
        for seat_index in 0..self.max_players {
            if !seat_mask_contains(contributor_mask, seat_index) {
                continue;
            }
            let seat = &self.seats[usize::from(seat_index)];
            let pk = seat.pk().ok_or_else(|| {
                PokerL1Error::Serialization(format!(
                    "Texas deck contributor seat {seat_index} has no live key"
                ))
            })?;
            if !seat.is_occupied() || super::utils::g1_is_identity(&pk.0) {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas deck contributor seat {seat_index} is empty, out, or has identity pk"
                )));
            }
            aggregate = Some(match aggregate {
                None => *pk,
                Some(current) => ECPoint(super::utils::g1_add(&current.0, &pk.0)),
            });
        }
        if aggregate
            .as_ref()
            .is_some_and(|point| super::utils::g1_is_identity(&point.0))
        {
            return Err(PokerL1Error::Serialization(
                "Texas non-empty contributor set has identity aggregate pk".into(),
            ));
        }
        Ok(aggregate)
    }

    /// Derive the aggregate deck key from the canonical contributor lineage.
    pub fn derived_aggregated_pk(&self) -> PokerL1Result<Option<ECPoint>> {
        self.aggregated_pk_for_contributor_mask(self.deck_state.contributor_mask)
    }

    /// Add a seat to the deck-key lineage after validating the derived aggregate.
    pub fn add_deck_contributor(&mut self, seat_index: u8) -> PokerL1Result<()> {
        if seat_index >= self.max_players {
            return Err(PokerL1Error::Serialization(format!(
                "Texas contributor seat {seat_index} is out of range"
            )));
        }
        let contributor_mask = self.deck_state.contributor_mask | seat_mask_bit(seat_index);
        let _ = self.aggregated_pk_for_contributor_mask(contributor_mask)?;
        self.deck_state.contributor_mask = contributor_mask;
        Ok(())
    }

    /// Remove a seat from the deck-key lineage after validating the derived aggregate.
    pub fn remove_deck_contributor(&mut self, seat_index: u8) -> PokerL1Result<()> {
        let mut contributor_mask = self.deck_state.contributor_mask;
        seat_mask_remove(&mut contributor_mask, seat_index);
        let _ = self.aggregated_pk_for_contributor_mask(contributor_mask)?;
        self.deck_state.contributor_mask = contributor_mask;
        Ok(())
    }

    /// 构造新桌台（空座位，WAITING 状态）。
    ///
    /// 展示名不属于共识状态（v34 起移除）；它由非共识 metadata 对象承载。
    #[must_use]
    pub fn new(
        id: ObjectID,
        creator: Address,
        max_players: u8,
        small_blind: u64,
        big_blind: u64,
    ) -> Self {
        assert!(
            max_players >= 2 && max_players <= 9,
            "max_players 必须 2..=9"
        );
        assert!(big_blind > 0, "big_blind 必须 > 0");
        assert!(small_blind <= big_blind, "small_blind 必须 <= big_blind");

        let seats = std::array::from_fn(|_| Seat::empty());

        Self {
            id,
            creator,
            rules: TableRules::new(max_players, small_blind, big_blind),
            seats,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            button: 0,
            last_bb_seat: NO_SEAT,
            pot: 0,
            community_cards: BoardCards::empty(),
            hand_phase: HandPhase::Waiting,
            deck_state: DeckState::default(),
            chip_pool: 0,
            run_it_twice_state: RunItTwiceState::default(),
            hand_id: 0,
            call_seq: 0,
        }
    }

    /// 统计活跃玩家数（未 fold 且未 left_during_hand）。
    #[must_use]
    pub fn active_count(&self) -> u8 {
        self.seats
            .iter()
            .filter(|s| s.is_occupied() && !s.is_folded())
            .count() as u8
    }

    /// 统计已入座玩家数（含 waiting）。
    #[must_use]
    pub fn occupied_count(&self) -> u8 {
        self.seats.iter().filter(|s| s.is_occupied()).count() as u8
    }

    /// 查找指定玩家的座位索引。
    #[must_use]
    pub fn find_seat(&self, player: &Address) -> Option<u8> {
        self.seats
            .iter()
            .position(|s| &s.player() == player)
            .map(|i| i as u8)
    }

    /// 按玩家地址查已登记的会话交易公钥（签名验证锚）。
    ///
    /// 未入座或座位未登记（fixture/哨兵）返回 None——`TableRuntime` 的
    /// 签名路径对此 fail-closed 拒绝。
    #[must_use]
    pub fn registered_tx_pk_of(
        &self,
        player: &Address,
    ) -> Option<&crate::signature::StarkTxPubkey> {
        self.seats
            .iter()
            .find(|s| &s.player() == player)
            .and_then(|s| s.registered_tx_pk())
    }

    /// 查找第一个空座位。
    #[must_use]
    pub fn find_empty_seat(&self) -> Option<u8> {
        self.seats
            .iter()
            .position(|s| matches!(s, Seat::Vacant { .. }))
            .map(|i| i as u8)
    }

    /// Whether `seat_index` has completed its current betting action.
    #[must_use]
    pub fn seat_acted_this_round(&self, seat_index: u8) -> bool {
        seat_mask_contains(self.acted_mask, seat_index)
    }

    /// Set or clear the current-round acted bit for one seat.
    pub fn set_seat_acted_this_round(&mut self, seat_index: u8, value: bool) {
        if value {
            debug_assert!(seat_index < self.max_players);
            self.acted_mask |= seat_mask_bit(seat_index);
        } else {
            seat_mask_remove(&mut self.acted_mask, seat_index);
        }
    }

    /// Whether `seat_index` requested removal after the current hand.
    #[must_use]
    pub fn seat_wants_leave(&self, seat_index: u8) -> bool {
        seat_mask_contains(self.leave_after_hand_mask, seat_index)
    }

    /// Set or clear the leave-after-hand bit for one seat.
    pub fn set_seat_wants_leave(&mut self, seat_index: u8, value: bool) {
        if value {
            debug_assert!(seat_index < self.max_players);
            self.leave_after_hand_mask |= seat_mask_bit(seat_index);
        } else {
            seat_mask_remove(&mut self.leave_after_hand_mask, seat_index);
        }
    }

    /// Decode the canonical current-turn sentinel.
    #[must_use]
    pub fn current_turn_option(&self) -> Option<u8> {
        let current_turn = self.current_turn();
        (current_turn != NO_SEAT).then_some(current_turn)
    }

    /// Clone the canonical runtime hand phase after fail-closed validation.
    pub fn canonical_hand_phase(&self) -> PokerL1Result<HandPhase> {
        self.validate_hand_phase()?;
        Ok(self.hand_phase.clone())
    }

    fn validate_hand_phase(&self) -> PokerL1Result<()> {
        let validate_deadline = |deadline_ms: u64, timeout_ms: u32, label: &str| {
            if deadline_ms == 0 {
                Err(PokerL1Error::Serialization(format!(
                    "Texas active {label} deadline is not armed"
                )))
            } else if deadline_ms < u64::from(timeout_ms) {
                Err(PokerL1Error::Serialization(format!(
                    "Texas {label} deadline {deadline_ms} is smaller than timeout {timeout_ms}"
                )))
            } else {
                Ok(())
            }
        };
        let validate_reveal = |street: u8, state: &RevealTokenState| {
            state.validate_for_street(street)?;
            for (assignment_index, assignment) in state.assignments.iter().enumerate() {
                if let RevealTarget::Hole { seat_index, .. } = assignment.target
                    && seat_index >= self.max_players
                {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas reveal assignment {assignment_index} targets out-of-range seat {seat_index}"
                    )));
                }
            }
            Ok(())
        };

        match &self.hand_phase {
            HandPhase::Waiting => Ok(()),
            HandPhase::Shuffling { phase } => {
                if let ShufflingPhase::Reconstruct {
                    street,
                    suspended_reveal,
                    ..
                } = phase
                {
                    if !matches!(
                        *street,
                        ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER | ROUND_SHOWDOWN
                    ) {
                        return Err(PokerL1Error::Serialization(
                            "Texas reconstruct shuffle is outside a live street".into(),
                        ));
                    }
                    validate_reveal(*street, suspended_reveal)?;
                }
                validate_deadline(
                    phase.deadline_ms(),
                    self.timeout_config.shuffle_timeout_ms,
                    "shuffle",
                )
            }
            HandPhase::Revealing {
                street,
                state,
                deadline_ms,
            } => {
                if !matches!(
                    *street,
                    ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER | ROUND_SHOWDOWN
                ) {
                    return Err(PokerL1Error::Serialization(
                        "Texas reveal phase is outside a live street".into(),
                    ));
                }
                validate_reveal(*street, state)?;
                validate_deadline(
                    *deadline_ms,
                    self.timeout_config.reveal_timeout_ms,
                    "reveal",
                )
            }
            HandPhase::Reconstructing {
                street,
                state: _,
                suspended_reveal,
                epoch_ms,
                deadline_ms,
            } => {
                if !matches!(
                    *street,
                    ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER | ROUND_SHOWDOWN
                ) {
                    return Err(PokerL1Error::Serialization(
                        "Texas reconstruct phase is not active on a live street".into(),
                    ));
                }
                validate_reveal(*street, suspended_reveal)?;
                if *epoch_ms == 0 || *deadline_ms == 0 {
                    return Err(PokerL1Error::Serialization(
                        "Texas active reconstruct epoch/deadline is not armed".into(),
                    ));
                }
                let expected = canonical_absolute_deadline(
                    *epoch_ms,
                    self.timeout_config.reconstruct_timeout_ms,
                    "reconstruct",
                )?;
                if *deadline_ms != expected {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas reconstruct deadline mismatch: encoded={deadline_ms}, expected={expected}"
                    )));
                }
                Ok(())
            }
            HandPhase::Betting {
                street,
                current_turn,
                deadline_ms,
                ..
            } => {
                if !matches!(
                    *street,
                    ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
                ) {
                    return Err(PokerL1Error::Serialization(
                        "Texas betting phase is outside a live street".into(),
                    ));
                }
                if *current_turn != NO_SEAT && *current_turn >= self.max_players {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas current_turn {current_turn} is outside max_players {}",
                        self.max_players
                    )));
                }
                validate_deadline(
                    *deadline_ms,
                    self.timeout_config.betting_timeout_ms,
                    "betting",
                )
            }
            HandPhase::Redealing {
                street,
                current_turn,
                state,
                deadline_ms,
                ..
            } => {
                if !matches!(
                    *street,
                    ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
                ) {
                    return Err(PokerL1Error::Serialization(
                        "Texas redeal phase is outside a live betting street".into(),
                    ));
                }
                if *current_turn != NO_SEAT && *current_turn >= self.max_players {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas suspended redeal turn {current_turn} is outside max_players {}",
                        self.max_players
                    )));
                }
                validate_reveal(*street, state)?;
                validate_deadline(
                    *deadline_ms,
                    self.timeout_config.reveal_timeout_ms,
                    "redeal",
                )
            }
            HandPhase::ShowdownDisplay { deadline_ms } => {
                if *deadline_ms == 0 {
                    Err(PokerL1Error::Serialization(
                        "Texas active showdown deadline is not armed".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Validate the complete canonical runtime state.
    ///
    /// Wire schema versions live exclusively in the resolved/hot codec envelopes; a runtime
    /// table cannot carry an independently mutable version fact.
    pub fn validate_state_schema(&self) -> PokerL1Result<()> {
        self.rules.validate_canonical()?;
        for (index, seat) in self
            .seats
            .iter()
            .enumerate()
            .skip(usize::from(self.max_players))
        {
            if !matches!(seat, Seat::Vacant { .. }) {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas seat padding beyond max_players must be vacant: seat {index}"
                )));
            }
        }
        if !seat_mask_is_canonical(self.acted_mask, self.max_players)
            || !seat_mask_is_canonical(self.leave_after_hand_mask, self.max_players)
        {
            return Err(PokerL1Error::Serialization(
                "Texas table contains out-of-range seat flag bits".into(),
            ));
        }
        if self.button >= self.max_players
            || (self.last_bb_seat != NO_SEAT && self.last_bb_seat >= self.max_players)
        {
            return Err(PokerL1Error::Serialization(
                "Texas table button/last_bb_seat is outside the seat domain".into(),
            ));
        }
        self.validate_hand_phase()?;
        for (seat_index, seat) in self.seats.iter().enumerate() {
            seat.validate_canonical()?;
            if seat.is_occupied()
                && self.seats[..seat_index]
                    .iter()
                    .any(|prior| prior.is_occupied() && prior.player() == seat.player())
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas player {:?} occupies more than one seat",
                    seat.player()
                )));
            }
            if matches!(seat, Seat::Vacant { .. })
                && (seat_mask_contains(self.acted_mask, seat_index as u8)
                    || seat_mask_contains(self.leave_after_hand_mask, seat_index as u8))
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas empty seat {seat_index} contains live table flags"
                )));
            }
        }
        let _ = self.derived_aggregated_pk()?;
        self.community_cards.validate_canonical().map_err(|error| {
            PokerL1Error::Serialization(format!("Texas first board is non-canonical: {error}"))
        })?;
        self.run_it_twice_state
            .validate_canonical(&self.community_cards)?;
        let mut seen_cards = [false; 52];
        for card in self
            .community_cards
            .iter()
            .chain(self.run_it_twice_state.second_board_suffix().iter())
            .chain(
                self.seats
                    .iter()
                    .flat_map(|seat| seat.hand().into_iter().flat_map(|hand| hand.iter())),
            )
        {
            let card_id = usize::from(card.to_index());
            if card_id >= seen_cards.len() || seen_cards[card_id] {
                return Err(PokerL1Error::Serialization(
                    "Texas table contains an invalid or duplicate materialized card".into(),
                ));
            }
            seen_cards[card_id] = true;
        }
        let mut seen_lineage = [false; CIPHER_DECK_SIZE];
        for (seat_index, card_slot, record) in self.deck_state.owner_readable_hole_cards.iter() {
            if usize::from(record.encrypted_card_index) >= 52 {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas partial hole card seat={seat_index} slot={card_slot} has out-of-range deck index {}",
                    record.encrypted_card_index
                )));
            }
            if seat_index >= self.max_players {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas partial hole-card ledger has out-of-range owner seat {seat_index}"
                )));
            }
            let lineage_index = usize::from(record.encrypted_card_index);
            if seen_lineage[lineage_index] {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas partial hole-card ledger contains duplicate deck index {}",
                    record.encrypted_card_index
                )));
            }
            seen_lineage[lineage_index] = true;
            if self.seats[usize::from(seat_index)]
                .hand()
                .is_some_and(|hand| usize::from(card_slot) < hand.len())
            {
                return Err(PokerL1Error::Serialization(format!(
                    "Texas partial hole-card ledger overlaps materialized hand: seat={seat_index}, slot={card_slot}"
                )));
            }
        }
        let validate_mask = |mask: SeatMask, label: &str| -> PokerL1Result<()> {
            if seat_mask_is_canonical(mask, self.max_players) {
                Ok(())
            } else {
                Err(PokerL1Error::Serialization(format!(
                    "Texas {label} contains out-of-range seat bits"
                )))
            }
        };
        let shuffle_state = self.shuffle_state();
        validate_mask(shuffle_state.pending_mask, "shuffle pending mask")?;
        validate_mask(shuffle_state.completed_mask, "shuffle completed mask")?;
        if shuffle_state.pending_mask & shuffle_state.completed_mask != 0 {
            return Err(PokerL1Error::Serialization(
                "Texas shuffle pending/completed masks overlap".into(),
            ));
        }
        for assignment in self.reveal_assignments() {
            validate_mask(assignment.pending_mask(), "reveal pending mask")?;
            validate_mask(assignment.submitted_mask, "reveal submitted mask")?;
            if assignment.pending_mask & assignment.submitted_mask != 0 {
                return Err(PokerL1Error::Serialization(
                    "Texas reveal pending/submitted masks overlap".into(),
                ));
            }
            if assignment.submitted_mask.count_ones() as usize != assignment.reveal_tokens.len() {
                return Err(PokerL1Error::Serialization(
                    "Texas reveal submitted mask/token vector length mismatch".into(),
                ));
            }
        }
        let reconstruct_state = self.reconstruct_state();
        validate_mask(reconstruct_state.pending_mask, "reconstruct pending mask")?;
        match &self.deck_state.reconstruct_accumulated {
            Some(deck) => {
                if deck.len() != 52 {
                    return Err(PokerL1Error::Serialization(format!(
                        "Texas reconstruct accumulator has {} cards, expected 52",
                        deck.len()
                    )));
                }
            }
            None => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用"已登记"会话交易公钥（base_g 压缩点，非恒等元）。
    fn registered_tx_pk_fixture() -> crate::signature::TaggedPubkey {
        use poker_protocol::crypto::curve::CurvePoint;
        crate::signature::TaggedPubkey {
            tag: crate::signature::encode_tag(
                crate::signature::SignatureScheme::Stark,
                crate::signature::CURRENT_VERSION,
            ),
            raw: g1_generator().compress().as_ref().to_vec(),
        }
    }

    fn dummy_table_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    fn partial_hole_card(deck_index: u8) -> PartialHoleCard {
        PartialHoleCard::new(
            deck_index,
            ElGamalCiphertext {
                c1: g1_generator(),
                c2: g1_generator(),
            },
            ElGamalCiphertext {
                c1: g1_generator(),
                c2: g1_generator(),
            },
        )
    }

    #[test]
    fn partial_hole_ledger_is_fixed_and_iterates_by_seat_then_slot() {
        let mut ledger = PartialHoleCardLedger::default();
        ledger.insert(2, 1, partial_hole_card(19)).unwrap();
        ledger.insert(0, 1, partial_hole_card(7)).unwrap();
        ledger.insert(0, 0, partial_hole_card(11)).unwrap();

        assert_eq!(
            ledger
                .iter()
                .map(|(seat, slot, card)| (seat, slot, card.encrypted_card_index))
                .collect::<Vec<_>>(),
            vec![(0, 0, 11), (0, 1, 7), (2, 1, 19)]
        );
        assert_eq!(
            ledger
                .iter_for_seat(0)
                .map(|(slot, card)| (slot, card.encrypted_card_index))
                .collect::<Vec<_>>(),
            vec![(0, 11), (1, 7)]
        );
        assert_eq!(ledger.remove(0, 0).unwrap().encrypted_card_index, 11);
        assert!(ledger.get(0, 0).is_none());
    }

    #[test]
    fn partial_hole_ledger_rejects_duplicate_slots_lineage_and_bounds() {
        let mut ledger = PartialHoleCardLedger::default();
        ledger.insert(0, 0, partial_hole_card(3)).unwrap();

        assert!(ledger.insert(0, 0, partial_hole_card(4)).is_err());
        assert!(ledger.insert(1, 1, partial_hole_card(3)).is_err());
        assert!(ledger.insert(MAX_SEATS, 0, partial_hole_card(5)).is_err());
        assert!(ledger.insert(0, 2, partial_hole_card(6)).is_err());
        assert!(
            ledger
                .insert(0, 1, partial_hole_card(CIPHER_DECK_SIZE as u8))
                .is_err()
        );
    }

    #[test]
    fn table_schema_rejects_partial_slots_outside_table_and_materialized_overlap() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 2, 50, 100);
        table
            .deck_state
            .owner_readable_hole_cards
            .insert(2, 0, partial_hole_card(3))
            .unwrap();
        assert!(
            table
                .validate_state_schema()
                .unwrap_err()
                .to_string()
                .contains("out-of-range owner seat 2")
        );

        table.deck_state.owner_readable_hole_cards.clear();
        table.seats[0].fixture_set_player([0xAB; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        let mut hand = HoleCards::empty();
        hand.try_push(Card::from_index(1)).unwrap();
        table.seats[0].fixture_set_hand(hand);
        table
            .deck_state
            .owner_readable_hole_cards
            .insert(0, 0, partial_hole_card(3))
            .unwrap();
        assert!(
            table
                .validate_state_schema()
                .unwrap_err()
                .to_string()
                .contains("overlaps materialized hand")
        );
    }

    #[test]
    fn test_table_new() {
        let table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        assert_eq!(table.max_players, 6);
        assert_eq!(table.seats.len(), 9); // 定宽槽位
        assert!(table.padding_seats_are_vacant());
        assert_eq!(table.small_blind, 50);
        assert_eq!(table.big_blind, 100);
        assert_eq!(table.round_state(), super::super::constants::ROUND_WAITING);
        assert_eq!(table.active_count(), 0);
        assert_eq!(table.occupied_count(), 0);
        assert_eq!(
            table.canonical_hand_phase().unwrap().tag(),
            HandPhaseTag::Waiting
        );
    }

    #[test]
    fn canonical_hand_phase_variant_replaces_incompatible_payload() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        table
            .enter_revealing(
                ROUND_FLOP,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                0,
            )
            .unwrap();
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 1, 0)
            .unwrap();

        assert!(matches!(table.hand_phase, HandPhase::Betting { .. }));
        assert!(table.reveal_token_state().is_none());
    }

    #[test]
    fn enter_revealing_rejects_purpose_street_mismatch_atomically() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        let before = table.hand_phase.clone();
        let error = table
            .enter_revealing(
                ROUND_PREFLOP,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                1,
            )
            .unwrap_err();

        assert!(error.to_string().contains("incompatible with street"));
        assert_eq!(table.hand_phase, before);
    }

    #[test]
    fn enter_revealing_rejects_purpose_target_mismatch_atomically() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        let before = table.hand_phase.clone();
        let error = table
            .enter_revealing(
                ROUND_FLOP,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Hole {
                            seat_index: 0,
                            card_slot: 0,
                        },
                        pending_mask: 0,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                1,
            )
            .unwrap_err();

        assert!(error.to_string().contains("incompatible with purpose"));
        assert_eq!(table.hand_phase, before);
    }

    #[test]
    fn canonical_hand_phase_carries_suspended_reveal_during_reconstruct() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        table
            .enter_reconstructing(
                ROUND_TURN,
                ReconstructState::default(),
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                1,
            )
            .unwrap();

        let phase = table.canonical_hand_phase().unwrap();
        assert_eq!(phase.tag(), HandPhaseTag::Reconstructing);
        assert!(matches!(
            phase,
            HandPhase::Reconstructing {
                street: ROUND_TURN,
                suspended_reveal: RevealTokenState {
                    purpose: RevealPurpose::Board,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn shuffle_sub_union_separates_initial_and_reconstruct_payloads() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0b11,
                    completed_mask: 0,
                },
                1_000,
            )
            .unwrap();
        assert!(matches!(
            table.hand_phase,
            HandPhase::Shuffling {
                phase: ShufflingPhase::Initial { .. }
            }
        ));
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert_eq!(table.shuffling_purpose(), Some(ShufflingPurpose::Initial));

        let reveal = RevealTokenState {
            purpose: RevealPurpose::Board,
            assignments: vec![],
        };
        table
            .enter_reconstruct_shuffling(
                ROUND_TURN,
                ShuffleState {
                    pending_mask: 0b10,
                    completed_mask: 0b01,
                },
                reveal.clone(),
                2_000,
            )
            .unwrap();
        assert!(matches!(
            &table.hand_phase,
            HandPhase::Shuffling {
                phase: ShufflingPhase::Reconstruct {
                    street: ROUND_TURN,
                    suspended_reveal,
                    ..
                }
            } if suspended_reveal == &reveal
        ));
        assert_eq!(table.round_state(), ROUND_TURN);
        assert_eq!(
            table.shuffling_purpose(),
            Some(ShufflingPurpose::Reconstruct)
        );
    }

    #[test]
    fn phase_helpers_clear_incompatible_payloads_and_deadline_overflow_is_atomic() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 100);
        table
            .enter_revealing(
                ROUND_FLOP,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                0,
            )
            .unwrap();
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 1, 1)
            .unwrap();

        assert!(table.reveal_token_state().is_none());
        assert_eq!(table.shuffle_state().as_ref(), &ShuffleState::default());
        assert_eq!(
            table.reconstruct_state().as_ref(),
            &ReconstructState::default()
        );
        assert_eq!(
            table.canonical_hand_phase().unwrap().tag(),
            HandPhaseTag::Betting
        );

        table.timeout_config.betting_timeout_ms = 10;
        let before = table.clone();
        assert!(table.arm_betting_deadline(u64::MAX - 5).is_err());
        assert_eq!(table, before);
    }

    #[test]
    fn test_table_new_invalid_params() {
        // max_players < 2
        let result = std::panic::catch_unwind(|| {
            let _ = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 1, 50, 100);
        });
        assert!(result.is_err());

        // max_players > 9
        let result = std::panic::catch_unwind(|| {
            let _ = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 10, 50, 100);
        });
        assert!(result.is_err());

        // big_blind = 0
        let result = std::panic::catch_unwind(|| {
            let _ = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 50, 0);
        });
        assert!(result.is_err());

        // small_blind > big_blind
        let result = std::panic::catch_unwind(|| {
            let _ = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 6, 200, 100);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_seat_empty() {
        let seat = Seat::empty();
        assert_eq!(seat.player(), EMPTY_PLAYER);
        assert_eq!(seat.stack(), 0);
        assert!(!seat.is_occupied());
        assert_eq!(seat.status(), SeatStatus::Empty);
    }

    #[test]
    fn test_seat_status_transitions() {
        let mut seat = Seat::empty();
        seat.fixture_set_player([0xAB; 20]);
        seat.set_stack(1000).unwrap();
        seat.set_status(SeatStatus::Active);
        assert_eq!(seat.status(), SeatStatus::Active);

        seat.set_status(SeatStatus::Folded);
        assert_eq!(seat.status(), SeatStatus::Folded);

        seat.set_status(SeatStatus::AllIn);
        assert_eq!(seat.status(), SeatStatus::AllIn);

        seat.set_status(SeatStatus::Waiting);
        assert_eq!(seat.status(), SeatStatus::Waiting);

        seat.set_status(SeatStatus::Out);
        assert_eq!(seat.status(), SeatStatus::Out);
    }

    #[test]
    fn seat_variant_mutations_preserve_tagged_payload_invariants() {
        let player = [0xAB; 20];
        let pk = ECPoint(g1_generator());
        let mut seat = Seat::occupied(
            player,
            1_000,
            pk,
            registered_tx_pk_fixture(),
            SeatStatus::Active,
        )
        .unwrap();
        assert!(seat.validate_canonical().is_ok());

        seat.fixture_set_bet(100);
        seat.fixture_set_total_bet(250);
        seat.hand_mut()
            .unwrap()
            .try_push(Card::from_index(7))
            .unwrap();
        seat.set_pending_addon(400).unwrap();
        seat.depart_this_hand().unwrap();
        assert_eq!(seat.player(), player);
        assert_eq!(seat.total_bet(), 250);
        assert!(seat.has_left_hand());
        assert!(seat.validate_canonical().is_ok());

        // Reset must not resurrect a departed player without a live key or stack.
        seat.prepare_next_hand();
        assert!(seat.has_left_hand());
        assert!(seat.validate_canonical().is_ok());

        seat.vacate();
        assert_eq!(seat, Seat::empty());
        assert!(seat.validate_canonical().is_ok());
    }

    #[test]
    fn test_table_find_seat() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[2].fixture_set_player([0x02; 20]);

        assert_eq!(table.find_seat(&[0x01; 20]), Some(0));
        assert_eq!(table.find_seat(&[0x02; 20]), Some(2));
        assert_eq!(table.find_seat(&[0x03; 20]), None);
    }

    #[test]
    fn test_table_find_empty_seat() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[1].fixture_set_player([0x02; 20]);

        assert_eq!(table.find_empty_seat(), Some(2));
    }

    #[test]
    fn test_table_active_count() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[2].fixture_set_player([0x03; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].set_status(SeatStatus::Active);
        table.seats[2].set_status(SeatStatus::Active);
        assert_eq!(table.active_count(), 3);

        table.seats[1].set_status(SeatStatus::Folded);
        assert_eq!(table.active_count(), 2);
    }

    #[test]
    fn test_table_borsh_roundtrip() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        table.seats[0].fixture_set_player([0xAB; 20]);
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[0].set_stack(1_000_000).unwrap();
        table.pot = 200;
        table.community_cards.try_push(Card::new(0, 14)).unwrap(); // A♠
        table.call_seq = 42;

        let bytes = borsh::to_vec(&table).unwrap();
        let recovered: TexasPokerTable = borsh::from_slice(&bytes).unwrap();
        assert_eq!(table, recovered);
    }

    #[test]
    fn canonical_table_rejects_one_player_occupying_multiple_seats() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        for seat_index in [0usize, 2] {
            table.seats[seat_index].fixture_set_player([0xAB; 20]);
            table.seats[seat_index].set_status(SeatStatus::Active);
        }

        let error = table.validate_state_schema().unwrap_err();
        assert!(error.to_string().contains("occupies more than one seat"));
    }

    #[test]
    fn test_shuffle_state_default() {
        assert_eq!(NO_SEAT, 0x0f);
        let state = ShuffleState::default();
        assert_eq!(state.derived_current_shuffler(), NO_SEAT);
        assert_eq!(state.pending_mask, 0);
        assert_eq!(state.completed_mask, 0);
    }

    #[test]
    fn betting_turn_accepts_only_a_live_seat_or_the_four_bit_sentinel() {
        let mut table = TexasPokerTable::new(dummy_table_id(), EMPTY_PLAYER, 4, 50, 100);
        assert!(
            table
                .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 0), u8::MAX, 1)
                .is_err()
        );
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 0), NO_SEAT, 1)
            .unwrap();
        assert!(table.current_turn_option().is_none());
        assert!(table.set_betting_turn(3).is_ok());
        assert!(table.set_betting_turn(4).is_err());
        assert!(table.set_betting_turn(9).is_err());
        assert!(table.set_betting_turn(u8::MAX).is_err());
        assert!(table.set_betting_turn(NO_SEAT).is_ok());
    }

    #[test]
    fn reveal_purpose_projects_only_on_compatible_streets() {
        assert_eq!(
            RevealPurpose::DealHole.legacy_phase(ROUND_PREFLOP),
            REVEAL_PHASE_PREFLOP
        );
        assert_eq!(
            RevealPurpose::Board.legacy_phase(ROUND_TURN),
            REVEAL_PHASE_TURN
        );
        assert_eq!(
            RevealPurpose::ShowdownOwner.legacy_phase(ROUND_SHOWDOWN),
            REVEAL_PHASE_SHOWDOWN
        );
        assert_eq!(
            RevealPurpose::Board.legacy_phase(ROUND_PREFLOP),
            REVEAL_PHASE_NONE
        );
    }

    #[test]
    fn test_reconstruct_state_default() {
        let state = ReconstructState::default();
        assert_eq!(state.pending_mask, 0);
        // 累加器已迁 DeckState：DeckState::default 的累加器恒 None。
        assert!(DeckState::default().reconstruct_accumulated.is_none());
    }

    #[test]
    fn test_timeout_config_defaults_match_move() {
        let cfg = TimeoutConfig::default();
        assert_eq!(cfg.shuffle_timeout_ms, 10_000);
        assert_eq!(cfg.reveal_timeout_ms, 10_000);
        assert_eq!(cfg.betting_timeout_ms, 30_000);
        assert_eq!(cfg.reconstruct_timeout_ms, 10_000);
        assert_eq!(cfg.showdown_display_ms, 3_000);
    }

    #[test]
    fn test_seat_borsh_roundtrip() {
        let mut seat = Seat::occupied(
            [0xCD; 20],
            5_000,
            ECPoint(g1_generator()),
            registered_tx_pk_fixture(),
            SeatStatus::Active,
        )
        .unwrap();
        seat.fixture_set_hand([Card::new(0, 14), Card::new(1, 13)].into());
        seat.fixture_set_bet(100);
        seat.fixture_set_total_bet(250);
        let bytes = borsh::to_vec(&seat).unwrap();
        let recovered: Seat = borsh::from_slice(&bytes).unwrap();
        assert_eq!(seat, recovered);
    }

    // ========== 定宽记录 Borsh ==========

    #[test]
    fn seat_record_encoding_is_constant_width() {
        use super::super::constants::DEFAULT_TIME_BANK_MS;
        let seats = [
            Seat::Vacant {
                time_bank_ms: DEFAULT_TIME_BANK_MS,
            },
            Seat::Waiting {
                occupied: test_occupied(),
            },
            Seat::Playing {
                playing: PlayingSeat {
                    occupied: test_occupied(),
                    hand: HoleCards::empty(),
                    bet: 100,
                    total_bet: 200,
                    status: PlayingSeatStatus::Active,
                },
            },
            Seat::DepartedThisHand {
                player: [9; 20],
                total_bet: 55,
                time_bank_ms: 1,
            },
        ];
        let encoded: Vec<Vec<u8>> = seats.iter().map(|s| borsh::to_vec(s).unwrap()).collect();
        for bytes in &encoded {
            // len(u32) 计入 width 预算：总长恒等于记录宽度。
            assert_eq!(bytes.len(), SEAT_RECORD_WIDTH);
        }
        // 全部变体等长 → 跨变体替换不改变表长度。
        for other in encoded.iter().skip(1) {
            assert_eq!(other.len(), encoded[0].len());
        }
    }

    #[test]
    fn seat_record_rejects_noncanonical_padding() {
        let seat = Seat::Vacant { time_bank_ms: 7 };
        let clean = borsh::to_vec(&seat).unwrap();
        let mut bytes = clean.clone();
        *bytes.last_mut().unwrap() = 1; // 污染填充 → 非规范编码必须拒绝
        assert!(borsh::from_slice::<Seat>(&bytes).is_err());
        *bytes.last_mut().unwrap() = 0;
        assert_eq!(borsh::from_slice::<Seat>(&bytes).unwrap(), seat);
    }

    fn test_occupied() -> OccupiedSeat {
        OccupiedSeat {
            player: [3; 20],
            stack: 1_000,
            pk: ECPoint(crate::contracts::texas_poker::utils::g1_generator()),
            tx_pk: unregistered_tx_pk(),
            pending_addon: 0,
            time_bank_ms: 30_000,
        }
    }

    #[test]
    fn hand_phase_record_encoding_is_constant_width() {
        let phases = [
            HandPhase::Waiting,
            HandPhase::Shuffling {
                phase: ShufflingPhase::Initial {
                    state: ShuffleState {
                        pending_mask: 0b11,
                        completed_mask: 0,
                    },
                    deadline_ms: 1_000,
                },
            },
            HandPhase::Revealing {
                street: ROUND_PREFLOP,
                state: RevealTokenState {
                    purpose: RevealPurpose::DealHole,
                    assignments: Vec::new(),
                },
                deadline_ms: 2_000,
            },
            HandPhase::Reconstructing {
                street: ROUND_FLOP,
                state: ReconstructState::default(),
                suspended_reveal: RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: Vec::new(),
                },
                epoch_ms: 3_000,
                deadline_ms: 4_000,
            },
            HandPhase::Betting {
                street: ROUND_PREFLOP,
                round: BettingRound::new(100, 100),
                current_turn: 0,
                deadline_ms: 5_000,
            },
            HandPhase::ShowdownDisplay { deadline_ms: 6_000 },
        ];
        let encoded: Vec<Vec<u8>> = phases.iter().map(|p| borsh::to_vec(p).unwrap()).collect();
        for bytes in &encoded {
            assert_eq!(bytes.len(), HAND_PHASE_RECORD_WIDTH);
        }
        // 逐变体 roundtrip。
        for (phase, bytes) in phases.iter().zip(&encoded) {
            assert_eq!(phase, &borsh::from_slice::<HandPhase>(bytes).unwrap());
        }
    }
}
