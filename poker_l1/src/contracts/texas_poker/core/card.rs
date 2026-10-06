//! Texas Poker 牌的数据结构。
//!
//! 全仓库统一一套花色编码：CLUBS=0, DIAMONDS=1, HEARTS=2, SPADES=3
//! （与客户端 Mental Poker `PlayingCard` 的 `id()` 一致，canonical id 的
//! 高位即花色：`suit = id / 13`，`rank = id % 13 + 2`）。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

// ===== Card 花色常量 =====

/// 梅花（编码 0）。
pub const CLUBS: u8 = 0;
/// 方块（编码 1）。
pub const DIAMONDS: u8 = 1;
/// 红心（编码 2）。
pub const HEARTS: u8 = 2;
/// 黑桃（编码 3）。
pub const SPADES: u8 = 3;
/// 合法花色上界（0-3）。
pub const MAX_SUIT: u8 = 3;

// ===== Card 点数常量 =====

/// 点数 2。
pub const TWO: u8 = 2;
/// 点数 3。
pub const THREE: u8 = 3;
/// 点数 4。
pub const FOUR: u8 = 4;
/// 点数 5。
pub const FIVE: u8 = 5;
/// 点数 6。
pub const SIX: u8 = 6;
/// 点数 7。
pub const SEVEN: u8 = 7;
/// 点数 8。
pub const EIGHT: u8 = 8;
/// 点数 9。
pub const NINE: u8 = 9;
/// 点数 10。
pub const TEN: u8 = 10;
/// 点数 J（11）。
pub const JACK: u8 = 11;
/// 点数 Q（12）。
pub const QUEEN: u8 = 12;
/// 点数 K（13）。
pub const KING: u8 = 13;
/// 点数 A（14，最大）。
pub const ACE: u8 = 14;

/// Canonical card identifier (`0..=51`).
///
/// The persisted representation is exactly one byte. Suit and rank are deterministic views:
/// `suit = id / 13`, `rank = id % 13 + 2`. Values outside `0..52` are transient invalid
/// sentinels and are rejected by canonical table validation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[serde(transparent)]
pub struct Card(u8);

impl Card {
    /// Canonical padding value used by fixed-capacity card containers.
    pub const PADDING: Self = Self(u8::MAX);

    /// 构造新牌。
    #[must_use]
    pub const fn new(suit: u8, rank: u8) -> Self {
        if suit <= MAX_SUIT && rank >= TWO && rank <= ACE {
            Self(suit * 13 + (rank - TWO))
        } else if suit <= MAX_SUIT && rank == 0 {
            // Transient evaluator-only padding. Canonical state rejects these values.
            Self(52 + suit)
        } else {
            Self::PADDING
        }
    }

    /// 校验牌的合法性。
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 < 52
    }

    /// 转为 0..51 索引（suit * 13 + (rank - 2)）。
    #[must_use]
    pub const fn to_index(self) -> u8 {
        self.0
    }

    /// 从 0..51 索引构造牌。
    #[must_use]
    pub const fn from_index(idx: u8) -> Self {
        Self(idx)
    }

    /// Return the suit (`0..=3`) or `u8::MAX` for a generic invalid sentinel.
    #[must_use]
    pub const fn suit(self) -> u8 {
        if self.0 < 52 {
            self.0 / 13
        } else if self.0 < 56 {
            self.0 - 52
        } else {
            u8::MAX
        }
    }

    /// Return the rank (`2..=14`) or zero for a transient invalid/padding card.
    #[must_use]
    pub const fn rank(self) -> u8 {
        if self.0 < 52 { (self.0 % 13) + TWO } else { 0 }
    }

    /// 花色名称。
    #[must_use]
    pub fn suit_name(&self) -> &'static str {
        match self.suit() {
            SPADES => "♠",
            HEARTS => "♥",
            DIAMONDS => "♦",
            CLUBS => "♣",
            _ => "?",
        }
    }

    /// 点数名称。
    #[must_use]
    pub fn rank_name(&self) -> &'static str {
        match self.rank() {
            TWO => "2",
            THREE => "3",
            FOUR => "4",
            FIVE => "5",
            SIX => "6",
            SEVEN => "7",
            EIGHT => "8",
            NINE => "9",
            TEN => "10",
            JACK => "J",
            QUEEN => "Q",
            KING => "K",
            ACE => "A",
            _ => "?",
        }
    }

    /// 显示字符串（如 "A♠"）。
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}{}", self.rank_name(), self.suit_name())
    }
}

impl Default for Card {
    fn default() -> Self {
        Self::PADDING
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

/// Fixed-capacity canonical two-card hand.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HoleCards {
    len: u8,
    cards: [Card; 2],
}

impl HoleCards {
    /// Empty hand with canonical padding.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            len: 0,
            cards: [Card::PADDING; 2],
        }
    }

    /// Number of live cards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the hand is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Live cards in dealing order.
    #[must_use]
    pub fn as_slice(&self) -> &[Card] {
        &self.cards[..self.len()]
    }

    /// Append one valid card, rejecting a third card.
    pub fn try_push(&mut self, card: Card) -> Result<(), &'static str> {
        if !card.is_valid() {
            return Err("hole card id is outside 0..52");
        }
        if self.len() >= self.cards.len() {
            return Err("hole cards exceed capacity 2");
        }
        self.cards[self.len()] = card;
        self.len += 1;
        Ok(())
    }

    /// Remove all cards and restore canonical padding.
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Validate length, cards and unused padding.
    pub fn validate_canonical(&self) -> Result<(), &'static str> {
        if self.len() > self.cards.len() {
            return Err("hole-card length exceeds capacity 2");
        }
        if self.as_slice().iter().any(|card| !card.is_valid()) {
            return Err("hole cards contain an invalid card id");
        }
        if self.cards[self.len()..]
            .iter()
            .any(|card| *card != Card::PADDING)
        {
            return Err("hole cards contain non-canonical padding");
        }
        Ok(())
    }
}

impl Default for HoleCards {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for HoleCards {
    type Target = [Card];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a HoleCards {
    type Item = &'a Card;
    type IntoIter = std::slice::Iter<'a, Card>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl TryFrom<Vec<Card>> for HoleCards {
    type Error = &'static str;

    fn try_from(cards: Vec<Card>) -> Result<Self, Self::Error> {
        let mut result = Self::empty();
        for card in cards {
            result.try_push(card)?;
        }
        Ok(result)
    }
}

impl From<[Card; 2]> for HoleCards {
    fn from(cards: [Card; 2]) -> Self {
        Self { len: 2, cards }
    }
}

impl PartialEq<Vec<Card>> for HoleCards {
    fn eq(&self, other: &Vec<Card>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Fixed-capacity canonical public-board or runout-suffix cards.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BoardCards {
    len: u8,
    cards: [Card; 5],
}

impl BoardCards {
    /// Empty board with canonical padding.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            len: 0,
            cards: [Card::PADDING; 5],
        }
    }

    /// Number of live cards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the board is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Live cards in dealing order.
    #[must_use]
    pub fn as_slice(&self) -> &[Card] {
        &self.cards[..self.len()]
    }

    /// Append one valid card, rejecting a sixth card.
    pub fn try_push(&mut self, card: Card) -> Result<(), &'static str> {
        if !card.is_valid() {
            return Err("board card id is outside 0..52");
        }
        if self.len() >= self.cards.len() {
            return Err("board cards exceed capacity 5");
        }
        self.cards[self.len()] = card;
        self.len += 1;
        Ok(())
    }

    /// Remove all cards and restore canonical padding.
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Convert the live prefix to a vector for event and settlement boundaries.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Card> {
        self.as_slice().to_vec()
    }

    /// Validate length, cards and unused padding.
    pub fn validate_canonical(&self) -> Result<(), &'static str> {
        if self.len() > self.cards.len() {
            return Err("board length exceeds capacity 5");
        }
        if self.as_slice().iter().any(|card| !card.is_valid()) {
            return Err("board contains an invalid card id");
        }
        if self.cards[self.len()..]
            .iter()
            .any(|card| *card != Card::PADDING)
        {
            return Err("board contains non-canonical padding");
        }
        Ok(())
    }
}

impl Default for BoardCards {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for BoardCards {
    type Target = [Card];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a BoardCards {
    type Item = &'a Card;
    type IntoIter = std::slice::Iter<'a, Card>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl TryFrom<Vec<Card>> for BoardCards {
    type Error = &'static str;

    fn try_from(cards: Vec<Card>) -> Result<Self, Self::Error> {
        let mut result = Self::empty();
        for card in cards {
            result.try_push(card)?;
        }
        Ok(result)
    }
}

impl PartialEq<Vec<Card>> for BoardCards {
    fn eq(&self, other: &Vec<Card>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_valid() {
        assert!(Card::new(SPADES, ACE).is_valid());
        assert!(Card::new(CLUBS, TWO).is_valid());
        assert!(!Card::new(4, ACE).is_valid()); // 非法花色
        assert!(!Card::new(SPADES, 1).is_valid()); // 非法点数
        assert!(!Card::new(SPADES, 15).is_valid()); // 非法点数
    }

    #[test]
    fn test_card_index_roundtrip() {
        for idx in 0..52 {
            let card = Card::from_index(idx);
            assert_eq!(card.to_index(), idx);
            assert!(card.is_valid());
        }
    }

    #[test]
    fn test_card_display() {
        assert_eq!(Card::new(SPADES, ACE).display(), "A♠");
        assert_eq!(Card::new(HEARTS, KING).display(), "K♥");
        assert_eq!(Card::new(DIAMONDS, TEN).display(), "10♦");
        assert_eq!(Card::new(CLUBS, TWO).display(), "2♣");
    }

    // ===== 定容容器（持久化 canonical 表示的第一道防线）=====

    #[test]
    fn test_hole_cards_capacity_and_validity() {
        let mut hole = HoleCards::empty();
        assert!(hole.is_empty());
        assert!(hole.try_push(Card::from_index(0)).is_ok());
        assert!(hole.try_push(Card::from_index(51)).is_ok());
        assert_eq!(hole.len(), 2);
        // 第三张必须拒绝。
        let err = hole.try_push(Card::from_index(7)).unwrap_err();
        assert_eq!(err, "hole cards exceed capacity 2");
        // 非法 id 必须拒绝（既不写入也不改变长度）。
        assert!(hole.try_push(Card::PADDING).is_err());
        assert_eq!(hole.len(), 2);
        assert!(hole.validate_canonical().is_ok());
        // clear 恢复 canonical padding。
        hole.clear();
        assert!(hole.is_empty());
        assert!(hole.validate_canonical().is_ok());
    }

    #[test]
    fn test_hole_cards_try_from_vec_overflow() {
        let three = vec![Card::from_index(0), Card::from_index(1), Card::from_index(2)];
        assert_eq!(
            HoleCards::try_from(three).unwrap_err(),
            "hole cards exceed capacity 2"
        );
        // From<[Card;2]> 与 Vec 相等性（事件/结算边界互转）。
        let pair = [Card::from_index(4), Card::from_index(9)];
        let hole = HoleCards::from(pair);
        assert!(hole == pair.to_vec());
    }

    #[test]
    fn test_hole_cards_borsh_rejects_dirty_padding() {
        use borsh::BorshDeserialize;
        // 坏持久化字节：len=1 但空位不是 PADDING → validate_canonical 拒绝。
        let dirty = HoleCards::try_from_slice(&[1, 5, 99]).expect("decode");
        assert_eq!(
            dirty.validate_canonical().unwrap_err(),
            "hole cards contain non-canonical padding"
        );
        // 活牌位是非法 id → 拒绝。
        let invalid = HoleCards::try_from_slice(&[2, 5, 99]).expect("decode");
        assert_eq!(
            invalid.validate_canonical().unwrap_err(),
            "hole cards contain an invalid card id"
        );
        // 合法编码：2 张活牌（定容 [Card;2] 序列化为 len + 2 字节，无尾巴）。
        let ok = HoleCards::try_from_slice(&[2, 0, 51]).expect("decode");
        assert!(ok.validate_canonical().is_ok());
    }

    #[test]
    fn test_board_cards_capacity_and_validity() {
        let mut board = BoardCards::empty();
        for i in 0..5 {
            assert!(board.try_push(Card::from_index(i)).is_ok());
        }
        assert_eq!(
            board.try_push(Card::from_index(9)).unwrap_err(),
            "board cards exceed capacity 5"
        );
        assert!(board.try_push(Card::PADDING).is_err());
        assert_eq!(board.len(), 5);
        assert!(board.validate_canonical().is_ok());
        assert_eq!(board.to_vec().len(), 5);
        board.clear();
        assert!(board.is_empty() && board.validate_canonical().is_ok());
    }

    #[test]
    fn test_board_cards_borsh_rejects_dirty_padding() {
        use borsh::BorshDeserialize;
        // len=3、空位含非 PADDING 字节 → 拒绝（BoardCards = len + [Card;5]，共 6 字节）。
        let dirty = BoardCards::try_from_slice(&[3, 0, 1, 2, 7, 7]).expect("decode");
        assert_eq!(
            dirty.validate_canonical().unwrap_err(),
            "board contains non-canonical padding"
        );
        let ok = BoardCards::try_from_slice(&[3, 0, 1, 2, 0xFF, 0xFF]).expect("decode");
        assert!(ok.validate_canonical().is_ok());
        assert_eq!(ok.len(), 3);
    }
}
