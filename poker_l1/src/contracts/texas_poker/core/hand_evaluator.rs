//! Texas Poker 手牌评估（7 选 5 最佳手牌）。
//!
//! # AIR/Trace 友好设计（原"电路友好"，SNARK → Stwo 迁移后重述）
//!
//! - [`HandRank`] 用定长 `kickers: [u8; 5]`（非 Vec），trace 里是固定 5 列。
//! - 直接实现 `Ord`（category 优先，kickers 字典序），删除 Move 风格的
//!   `compare`/`compare_kickers` 三态转换；AIR 中比较即 limb 借位链，
//!   少一层三态转换就少一组 gadget。
//! - `evaluate_best` 统一处理 5..=7 张牌（C(n,5) 组合枚举），<5 张用 0 填充。
//!   删除占位牌补齐路径（避免重复牌污染评估）。定长组合枚举在 AIR 中仍是
//!   合理基线；实现 hand-rank AIR 时可再评估 lookup（logUp）直方图方案。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::card::Card;

// ===== 牌型常量 =====

/// 高牌（无任何成牌，按最大点数比较）。
pub const HIGH_CARD: u8 = 0;
/// 一对。
pub const ONE_PAIR: u8 = 1;
/// 两对。
pub const TWO_PAIR: u8 = 2;
/// 三条。
pub const THREE_OF_A_KIND: u8 = 3;
/// 顺子（五张连续点数）。
pub const STRAIGHT: u8 = 4;
/// 同花（五张同花色）。
pub const FLUSH: u8 = 5;
/// 葫芦（三条 + 一对）。
pub const FULL_HOUSE: u8 = 6;
/// 四条。
pub const FOUR_OF_A_KIND: u8 = 7;
/// 同花顺。
pub const STRAIGHT_FLUSH: u8 = 8;
/// 皇家同花顺（A 高同花顺）。
pub const ROYAL_FLUSH: u8 = 9;

/// 手牌评估结果。
///
/// - `category`: 牌型（0-9）
/// - `kickers`: tiebreaker 点数列表（定长 5，降序，不足位补 0）
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
pub struct HandRank {
    /// 牌型类别（0-9，见上方 `HIGH_CARD`..`ROYAL_FLUSH` 常量）。
    pub category: u8,
    /// 决胜点数（定长 5、降序，不足位补 0；同一 category 下按位比较）。
    pub kickers: [u8; 5],
}

impl HandRank {
    /// 构造新 HandRank，kickers 不足 5 位用 0 填充。
    #[must_use]
    pub fn new(category: u8, kickers: &[u8]) -> Self {
        let mut k = [0u8; 5];
        for (i, &val) in kickers.iter().take(5).enumerate() {
            k[i] = val;
        }
        Self {
            category,
            kickers: k,
        }
    }

    /// 牌型名称。
    #[must_use]
    pub fn category_name(&self) -> &'static str {
        match self.category {
            HIGH_CARD => "High Card",
            ONE_PAIR => "One Pair",
            TWO_PAIR => "Two Pair",
            THREE_OF_A_KIND => "Three of a Kind",
            STRAIGHT => "Straight",
            FLUSH => "Flush",
            FULL_HOUSE => "Full House",
            FOUR_OF_A_KIND => "Four of a Kind",
            STRAIGHT_FLUSH => "Straight Flush",
            ROYAL_FLUSH => "Royal Flush",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for HandRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.category_name())
    }
}

/// 直接字典序比较：category 优先，其次 kickers 降序逐位比较。
///
/// kickers 已保证降序排列（由 evaluate_five 保证），故 `[u8;5]` 的自然 Ord
/// 恰好对应"降序逐位比较"，无需自定义 compare_kickers。
impl Ord for HandRank {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category
            .cmp(&other.category)
            .then_with(|| self.kickers.cmp(&other.kickers))
    }
}

impl PartialOrd for HandRank {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 从 n 张牌（5..=7）中选出最佳 5 张组合；<5 张时先 0 填充到 5 张再评估。
///
/// - 7 张：枚举 C(7,5)=21 种组合。
/// - 5/6 张：枚举 C(n,5) 组合。
/// - <5 张：用点数 0、最少出现花色的占位牌填充（不影响牌型判定）。
#[must_use]
pub fn evaluate_best(cards: &[Card]) -> HandRank {
    if cards.len() < 5 {
        // 不足 5 张：用 rank=0（不计入 counts）、花色按当前出现次数最少的花色填充。
        // rank=0 保证不构成对子/顺子；每次补入最少出现的花色，
        // 保证任何花色总数不会达到 5（例如 4 张同花色真实牌不会被补成同花）。
        let mut padded = cards.to_vec();
        while padded.len() < 5 {
            let mut suit_counts = [0u8; 4];
            for card in &padded {
                if (card.suit() as usize) < 4 {
                    suit_counts[card.suit() as usize] += 1;
                }
            }
            let min_suit = (0..4u8)
                .min_by_key(|&s| suit_counts[usize::from(s)])
                .unwrap_or(0);
            padded.push(Card::new(min_suit, 0));
        }
        return evaluate_five(&[padded[0], padded[1], padded[2], padded[3], padded[4]]);
    }
    let n = cards.len();
    let mut best = HandRank::new(HIGH_CARD, &[0; 5]);
    // 枚举所有 C(n,5) 组合。n==7 时为 21 组（电路里硬编码展开）。
    for i in 0..n {
        for j in (i + 1)..n {
            for k in (j + 1)..n {
                for l in (k + 1)..n {
                    for m in (l + 1)..n {
                        let five = [cards[i], cards[j], cards[k], cards[l], cards[m]];
                        let rank = evaluate_five(&five);
                        if rank > best {
                            best = rank;
                        }
                    }
                }
            }
        }
    }
    best
}

fn evaluate_five(cards: &[Card; 5]) -> HandRank {
    let c0 = cards[0];
    let c1 = cards[1];
    let c2 = cards[2];
    let c3 = cards[3];
    let c4 = cards[4];
    let all = [c0, c1, c2, c3, c4];

    // 1. counts[13]（索引 0=点数2, 12=点数14）
    let mut counts = [0u8; 13];
    for c in &all {
        if c.rank() >= 2 && c.rank() <= 14 {
            counts[(c.rank() - 2) as usize] += 1;
        }
    }

    // 2. 同花检测
    let is_flush = c0.suit() == c1.suit()
        && c1.suit() == c2.suit()
        && c2.suit() == c3.suit()
        && c3.suit() == c4.suit();

    // 3. 点数降序排序——固定邻接交换网络（10 比较器，控制流与牌值无关）。
    let mut ranks = [c0.rank(), c1.rank(), c2.rank(), c3.rank(), c4.rank()];
    sort_five_desc(&mut ranks);

    // 4. 顺子检测（返回顺子最高点数）
    let straight = straight_high(&ranks);

    // 5. 相同点数组：13 槽直方图直接映入 16 槽 (count, rank) 组，Batcher
    //    odd-even 定宽网络降序（零计数组 count=0 天然沉底；条件分支只读
    //    前 5 槽且均由 count 谓词把守，等价旧"过滤 + 排序 + (0,0) 填充"）。
    let mut groups = [(0u8, 0u8); 16];
    for (slot, &count) in counts.iter().enumerate() {
        groups[slot] = (count, slot as u8 + 2);
    }
    sort_groups_desc(&mut groups);

    // 6. 优先级判断（从高到低）

    // 同花顺 / 皇家同花顺
    if is_flush {
        if let Some(high) = straight {
            if high == 14 {
                return HandRank::new(ROYAL_FLUSH, &[14]);
            }
            return HandRank::new(STRAIGHT_FLUSH, &[high]);
        }
    }

    // 四条
    if groups[0].0 == 4 {
        return HandRank::new(FOUR_OF_A_KIND, &[groups[0].1, groups[1].1]);
    }

    // 葫芦
    if groups[0].0 == 3 && groups[1].0 >= 2 {
        return HandRank::new(FULL_HOUSE, &[groups[0].1, groups[1].1]);
    }

    // 同花
    if is_flush {
        return HandRank::new(FLUSH, &ranks);
    }

    // 顺子
    if let Some(high) = straight {
        return HandRank::new(STRAIGHT, &[high]);
    }

    // 三条
    if groups[0].0 == 3 {
        // groups[1..] 已按 (count,rank) 降序，rank 天然降序，直接取前 2
        let k = [groups[0].1, groups[1].1, groups[2].1];
        return HandRank::new(THREE_OF_A_KIND, &k);
    }

    // 两对
    if groups[0].0 == 2 && groups[1].0 == 2 {
        let (hi, lo) = if groups[0].1 > groups[1].1 {
            (groups[0].1, groups[1].1)
        } else {
            (groups[1].1, groups[0].1)
        };
        return HandRank::new(TWO_PAIR, &[hi, lo, groups[2].1]);
    }

    // 一对
    if groups[0].0 == 2 {
        // groups[1..] rank 已降序，取前 3 作为 kicker
        let k = [groups[0].1, groups[1].1, groups[2].1, groups[3].1];
        return HandRank::new(ONE_PAIR, &k);
    }

    // 高牌
    HandRank::new(HIGH_CARD, &ranks)
}

/// 5 元素降序固定比较交换网络（邻接插入序，10 比较器）。
///
/// 控制流与牌值无关：索引序列恒定，AIR 端即 10 个定界 min/max/交换门
/// （#40③：替代 `sort_unstable_by`）。
fn sort_five_desc(ranks: &mut [u8; 5]) {
    for j in 1..5 {
        for i in (0..j).rev() {
            if ranks[i] < ranks[i + 1] {
                ranks.swap(i, i + 1);
            }
        }
    }
}

/// 16 槽 (count, rank) 组降序固定网络：Batcher odd-even mergesort
/// （63 比较器，n=16 恒定，无数据依赖控制流；#40③）。
///
/// 比较器语义：前项 < 后项则交换 → 大者落低位索引 = 降序输出。
fn sort_groups_desc(groups: &mut [(u8, u8); 16]) {
    sort_network_range(groups, 0, 16);
}

fn sort_network_range(a: &mut [(u8, u8); 16], lo: usize, n: usize) {
    if n <= 1 {
        return;
    }
    let mid = n / 2;
    sort_network_range(a, lo, mid);
    sort_network_range(a, lo + mid, mid);
    odd_even_merge(a, lo, n, 1);
}

fn odd_even_merge(a: &mut [(u8, u8); 16], lo: usize, n: usize, r: usize) {
    let step = r * 2;
    if step < n {
        odd_even_merge(a, lo, n, step);
        odd_even_merge(a, lo + r, n, step);
        let mut i = lo + r;
        while i + r < lo + n {
            if a[i] < a[i + r] {
                a.swap(i, i + r);
            }
            i += step;
        }
    } else if a[lo] < a[lo + r] {
        a.swap(lo, lo + r);
    }
}

/// 检测顺子，返回最高点数（A-2-3-4-5 wheel 返回 5）。非顺子返回 None。
fn straight_high(ranks_desc: &[u8; 5]) -> Option<u8> {
    // wheel: A-2-3-4-5（排序后 [14,5,4,3,2]）
    if *ranks_desc == [14, 5, 4, 3, 2] {
        return Some(5);
    }
    // 普通顺子：5 张连续递减
    let consecutive = (0..4).all(|i| ranks_desc[i] == ranks_desc[i + 1] + 1);
    if consecutive {
        Some(ranks_desc[0])
    } else {
        None
    }
}

/// 从多个玩家中找出赢家（返回 seat_index 列表，平局多人）。
#[must_use]
pub fn find_winners(hands: &[(u8, Vec<Card>)]) -> Vec<u8> {
    assert!(!hands.is_empty(), "find_winners 要求至少 1 个玩家");
    let mut best_rank = HandRank::new(HIGH_CARD, &[0; 5]);
    let mut best_seats: Vec<u8> = Vec::new();

    for (seat, cards) in hands {
        let rank = evaluate_best(cards);
        match rank.cmp(&best_rank) {
            std::cmp::Ordering::Greater => {
                best_rank = rank;
                best_seats.clear();
                best_seats.push(*seat);
            }
            std::cmp::Ordering::Equal => {
                best_seats.push(*seat);
            }
            std::cmp::Ordering::Less => {}
        }
    }
    best_seats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::texas_poker::card::*;

    fn card(suit: u8, rank: u8) -> Card {
        Card::new(suit, rank)
    }

    // ---- 固定比较交换网络正确性（#40③） ----

    #[test]
    fn five_element_network_sorts_desc_exhaustively() {
        // 1..=5 全排列（120 个）+ 含重复的边界模式，与参照排序逐一对比。
        let mut perm = [1u8, 2, 3, 4, 5];
        for _ in 0..120 {
            let mut got = perm;
            sort_five_desc(&mut got);
            let mut want = perm;
            want.sort_unstable_by(|a, b| b.cmp(a));
            assert_eq!(got, want, "divergence on permutation {perm:?}");
            // 下一个排列（字典序 next_permutation）。
            let pivot = (0..4).rev().find(|&i| perm[i] < perm[i + 1]);
            let Some(pivot) = pivot else { break };
            let succ = (pivot + 1..5).rev().find(|&i| perm[i] > perm[pivot]).unwrap();
            perm.swap(pivot, succ);
            perm[pivot + 1..].reverse();
        }
        for seed in 0..64u8 {
            let mut got = [seed.wrapping_mul(7), seed.wrapping_mul(3), seed / 2, seed % 5, seed];
            sort_five_desc(&mut got);
            let mut want = got;
            want.sort_unstable_by(|a, b| b.cmp(a));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn sixteen_slot_network_matches_reference_sort() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut check = |groups: [(u8, u8); 16]| {
            let mut got = groups;
            sort_groups_desc(&mut got);
            let mut want = groups.to_vec();
            want.sort_unstable_by(|a, b| b.cmp(a));
            assert_eq!(got.to_vec(), want, "divergence on {groups:?}");
        };
        for _ in 0..4_000 {
            check((0..16).map(|_| (next() as u8 % 5, (next() as u8 % 13) + 2)).collect::<Vec<_>>().try_into().unwrap());
        }
        // 结构化边界：全同、全零、直方图真实形态（5 张牌 counts ≤ 5）。
        check([(&1u8, &2u8); 16].map(|(c, r)| (*c, *r)));
        check([(0u8, 0u8); 16]);
        check(std::array::from_fn(|slot| {
            if slot < 13 { (1, slot as u8 + 2) } else { (0, 0) }
        }));
    }

    fn make_seven(cards: [Card; 7]) -> Vec<Card> {
        cards.to_vec()
    }

    #[test]
    fn test_royal_flush() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, QUEEN),
            card(SPADES, JACK),
            card(SPADES, TEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, ROYAL_FLUSH);
        assert_eq!(rank.kickers, [14, 0, 0, 0, 0]);
    }

    #[test]
    fn test_straight_flush_wheel() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, TWO),
            card(SPADES, THREE),
            card(SPADES, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT_FLUSH);
        assert_eq!(rank.kickers, [5, 0, 0, 0, 0]);
    }

    #[test]
    fn test_four_of_a_kind() {
        let seven = make_seven([
            card(SPADES, KING),
            card(HEARTS, KING),
            card(DIAMONDS, KING),
            card(CLUBS, KING),
            card(SPADES, TWO),
            card(HEARTS, THREE),
            card(CLUBS, FOUR),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FOUR_OF_A_KIND);
        assert_eq!(rank.kickers, [13, 4, 0, 0, 0]);
    }

    #[test]
    fn test_full_house() {
        let seven = make_seven([
            card(SPADES, QUEEN),
            card(HEARTS, QUEEN),
            card(DIAMONDS, QUEEN),
            card(CLUBS, JACK),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FULL_HOUSE);
        assert_eq!(rank.kickers, [12, 11, 0, 0, 0]);
    }

    #[test]
    fn test_flush() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, JACK),
            card(SPADES, NINE),
            card(SPADES, SEVEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FLUSH);
    }

    #[test]
    fn test_straight() {
        let seven = make_seven([
            card(SPADES, TEN),
            card(HEARTS, NINE),
            card(DIAMONDS, EIGHT),
            card(CLUBS, SEVEN),
            card(SPADES, SIX),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, [10, 0, 0, 0, 0]);
    }

    #[test]
    fn test_straight_wheel() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(DIAMONDS, THREE),
            card(CLUBS, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, [5, 0, 0, 0, 0]);
    }

    #[test]
    fn test_three_of_a_kind() {
        let seven = make_seven([
            card(SPADES, SEVEN),
            card(HEARTS, SEVEN),
            card(DIAMONDS, SEVEN),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, THREE_OF_A_KIND);
        assert_eq!(rank.kickers, [7, 13, 12, 0, 0]);
    }

    #[test]
    fn test_two_pair() {
        let seven = make_seven([
            card(SPADES, JACK),
            card(HEARTS, JACK),
            card(DIAMONDS, FOUR),
            card(CLUBS, FOUR),
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, TWO_PAIR);
        assert_eq!(rank.kickers, [11, 4, 14, 0, 0]);
    }

    #[test]
    fn test_one_pair() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, ACE),
            card(DIAMONDS, KING),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, ONE_PAIR);
        assert_eq!(rank.kickers, [14, 13, 12, 11, 0]);
    }

    #[test]
    fn test_high_card() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, JACK),
            card(CLUBS, NINE),
            card(SPADES, FIVE),
            card(HEARTS, THREE),
            card(CLUBS, TWO),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, HIGH_CARD);
    }

    #[test]
    fn test_compare() {
        let pair = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
        let two_pair = HandRank::new(TWO_PAIR, &[11, 4, 14]);

        assert!(two_pair > pair);
        assert!(pair < two_pair);
        assert_eq!(pair, HandRank::new(ONE_PAIR, &[14, 13, 12, 11]));

        // 同 category 比较 kickers
        let pair_high = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
        let pair_low = HandRank::new(ONE_PAIR, &[13, 12, 11, 10]);
        assert!(pair_high > pair_low);
    }

    #[test]
    fn test_find_winners_single() {
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(SPADES, KING),
                card(SPADES, QUEEN),
                card(SPADES, JACK),
                card(SPADES, TEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(HEARTS, TWO),
                card(HEARTS, THREE),
                card(HEARTS, FOUR),
                card(HEARTS, FIVE),
                card(HEARTS, SIX),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners, vec![0]);
    }

    #[test]
    fn test_find_winners_tie() {
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(HEARTS, ACE),
                card(DIAMONDS, KING),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(DIAMONDS, ACE),
                card(CLUBS, ACE),
                card(SPADES, KING),
                card(HEARTS, KING),
                card(DIAMONDS, QUEEN),
                card(CLUBS, TWO),
                card(SPADES, THREE),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
    }

    #[test]
    fn test_evaluate_best_partial_fewer_cards() {
        // 2 张牌：HIGH_CARD
        let two = vec![card(SPADES, ACE), card(HEARTS, KING)];
        let rank = evaluate_best(&two);
        assert_eq!(rank.category, HIGH_CARD);
        assert_eq!(rank.kickers[0], 14);

        // 0 张牌：HIGH_CARD，kickers 全 0
        let none: Vec<Card> = vec![];
        let rank = evaluate_best(&none);
        assert_eq!(rank.category, HIGH_CARD);
    }

    #[test]
    fn test_evaluate_best_partial_four_same_suit_not_flush() {
        // 4 张黑桃占位后不能被判为同花（回归：占位牌花色从 0 开始导致误判）。
        let four_spades = vec![
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, QUEEN),
            card(SPADES, JACK),
        ];
        let rank = evaluate_best(&four_spades);
        assert_eq!(rank.category, HIGH_CARD);
        assert_eq!(rank.kickers, [14, 13, 12, 11, 0]);

        // 4 张红心同样不得误判。
        let four_hearts = vec![
            card(HEARTS, ACE),
            card(HEARTS, KING),
            card(HEARTS, QUEEN),
            card(HEARTS, JACK),
        ];
        let rank = evaluate_best(&four_hearts);
        assert_eq!(rank.category, HIGH_CARD);

        // 3 张同花色也不得误判。
        let three_spades = vec![card(SPADES, ACE), card(SPADES, KING), card(SPADES, QUEEN)];
        let rank = evaluate_best(&three_spades);
        assert_eq!(rank.category, HIGH_CARD);

        // 4 张覆盖 4 种花色时补位也不得构成同花。
        let rainbow = vec![
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, QUEEN),
            card(CLUBS, JACK),
        ];
        let rank = evaluate_best(&rainbow);
        assert_eq!(rank.category, HIGH_CARD);
    }

    // ===== 6 张牌路径（C(6,5)=6 组合枚举；此前只有 7 张与 <5 张覆盖）=====

    #[test]
    fn test_six_card_best_five_drops_sixth() {
        // 两对 + 三张散牌：最佳 5 张 = 两对 + 最大 kicker（丢掉最小散牌）。
        let six = vec![
            card(SPADES, KING),
            card(HEARTS, KING),
            card(DIAMONDS, EIGHT),
            card(CLUBS, EIGHT),
            card(SPADES, ACE),
            card(HEARTS, THREE),
        ];
        let rank = evaluate_best(&six);
        assert_eq!(rank.category, TWO_PAIR);
        // kicker = A（丢掉 3）
        assert_eq!(rank.kickers, [13, 8, 14, 0, 0]);
    }

    #[test]
    fn test_six_card_upgrade_to_full_house() {
        // 两对 + 第 6 张把小对升成葫芦：K-K-8-8 + 8 → 8 葫芦带 K。
        let six = vec![
            card(SPADES, KING),
            card(HEARTS, KING),
            card(DIAMONDS, EIGHT),
            card(CLUBS, EIGHT),
            card(SPADES, EIGHT),
            card(HEARTS, TWO),
        ];
        let rank = evaluate_best(&six);
        assert_eq!(rank.category, FULL_HOUSE);
        assert_eq!(rank.kickers, [8, 13, 0, 0, 0]);
    }

    #[test]
    fn test_six_card_pair_plus_flush_draw_not_flush() {
        // 4 张同花 + 一对：6 张里任何 5 张都无法凑满 5 张同花 → 两对/一对。
        let six = vec![
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, QUEEN),
            card(SPADES, JACK),
            card(HEARTS, NINE),
            card(DIAMONDS, NINE),
        ];
        let rank = evaluate_best(&six);
        assert_eq!(rank.category, ONE_PAIR);
        assert_eq!(rank.kickers[0], 9);
    }

    // ===== 同牌型 kicker 决胜（AIR classify 镜像最易漂移的字段）=====

    #[test]
    fn test_same_category_kicker_duels() {
        // 顺子高牌决胜：T-high 击败 9-high。
        let ten_high = vec![
            card(SPADES, TEN),
            card(HEARTS, NINE),
            card(DIAMONDS, EIGHT),
            card(CLUBS, SEVEN),
            card(SPADES, SIX),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        let nine_high = vec![
            card(SPADES, NINE),
            card(HEARTS, EIGHT),
            card(DIAMONDS, SEVEN),
            card(CLUBS, SIX),
            card(SPADES, FIVE),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        assert!(evaluate_best(&ten_high) > evaluate_best(&nine_high));

        // 同花逐位 kicker：A-K-9 击败 A-K-8（第 3 位分胜负）。
        let flush_high = vec![
            card(HEARTS, ACE),
            card(HEARTS, KING),
            card(HEARTS, NINE),
            card(HEARTS, FIVE),
            card(HEARTS, THREE),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
        ];
        let flush_low = vec![
            card(DIAMONDS, ACE),
            card(DIAMONDS, KING),
            card(DIAMONDS, EIGHT),
            card(DIAMONDS, FIVE),
            card(DIAMONDS, THREE),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
        ];
        assert!(evaluate_best(&flush_high) > evaluate_best(&flush_low));

        // 葫芦同三条不同对子：Q over K 击败 Q over J。
        let fh_high_pair = vec![
            card(SPADES, QUEEN),
            card(HEARTS, QUEEN),
            card(DIAMONDS, QUEEN),
            card(CLUBS, KING),
            card(SPADES, KING),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        let fh_low_pair = vec![
            card(SPADES, QUEEN),
            card(HEARTS, QUEEN),
            card(DIAMONDS, QUEEN),
            card(CLUBS, JACK),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        assert!(evaluate_best(&fh_high_pair) > evaluate_best(&fh_low_pair));

        // 高牌逐位：A-K-J-9 击败 A-K-T-9（注意别凑出 A-2-3-4-5 轮子顺）。
        let hc_high = vec![
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, JACK),
            card(CLUBS, NINE),
            card(SPADES, SEVEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        let hc_low = vec![
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, TEN),
            card(CLUBS, NINE),
            card(SPADES, SEVEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ];
        assert!(evaluate_best(&hc_high) > evaluate_best(&hc_low));
    }

    #[test]
    fn test_find_winners_single_player_and_kicker_sweep() {
        // 单人：自己就是赢家。
        let winners = find_winners(&[(
            3u8,
            vec![
                card(SPADES, TWO),
                card(HEARTS, SEVEN),
                card(DIAMONDS, NINE),
                card(CLUBS, JACK),
                card(SPADES, KING),
            ],
        )]);
        assert_eq!(winners, vec![3]);

        // kicker 决胜横扫：T-high 顺子同时击败两个 9-high。
        let table = vec![
            (
                0u8,
                vec![
                    card(SPADES, TEN),
                    card(HEARTS, NINE),
                    card(DIAMONDS, EIGHT),
                    card(CLUBS, SEVEN),
                    card(SPADES, SIX),
                    card(HEARTS, TWO),
                    card(CLUBS, THREE),
                ],
            ),
            (
                1u8,
                vec![
                    card(HEARTS, NINE),
                    card(DIAMONDS, EIGHT),
                    card(CLUBS, SEVEN),
                    card(SPADES, SIX),
                    card(HEARTS, FIVE),
                    card(CLUBS, TWO),
                    card(SPADES, THREE),
                ],
            ),
            (
                2u8,
                vec![
                    card(CLUBS, NINE),
                    card(SPADES, EIGHT),
                    card(HEARTS, SEVEN),
                    card(DIAMONDS, SIX),
                    card(CLUBS, FIVE),
                    card(SPADES, TWO),
                    card(HEARTS, THREE),
                ],
            ),
        ];
        assert_eq!(find_winners(&table), vec![0]);
    }

    #[test]
    #[should_panic(expected = "find_winners")]
    fn test_find_winners_empty_panics() {
        // 坏状态（无玩家）必须 panic 而不是返回空——锁定该契约。
        let _ = find_winners(&[]);
    }
}
