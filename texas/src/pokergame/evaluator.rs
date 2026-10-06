use itertools::Itertools;
use crate::pokergame::hand_rank::{EvalCard, HandRank, Rank};

pub fn evaluate_five(cards: &[EvalCard; 5]) -> HandRank {
    let mut ranks: Vec<Rank> = cards.iter().map(|c| c.rank).collect();
    ranks.sort_unstable_by(|a, b| b.cmp(a));
    let is_flush = cards.iter().all(|c| c.suit == cards[0].suit);
    let is_straight = is_straight_high(&ranks);
    let is_wheel = is_wheel(&ranks);

    let mut counts: Vec<(Rank, usize)> = Vec::new();
    for &r in &ranks {
        if let Some(entry) = counts.iter_mut().find(|(rank, _)| *rank == r) {
            entry.1 += 1;
        } else {
            counts.push((r, 1));
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.cmp(&a.0)));
    let count_pattern: Vec<usize> = counts.iter().map(|(_, c)| *c).collect();

    if is_flush && is_straight && ranks[0] == Rank::Ace && ranks[4] == Rank::Ten {
        return HandRank::RoyalFlush;
    }
    if is_flush && is_straight {
        return HandRank::StraightFlush(ranks[0]);
    }
    if is_flush && is_wheel {
        return HandRank::StraightFlush(Rank::Five);
    }
    if count_pattern == [4, 1] {
        return HandRank::FourOfAKind(counts[0].0, counts[1].0);
    }
    if count_pattern == [3, 2] {
        return HandRank::FullHouse(counts[0].0, counts[1].0);
    }
    if is_flush {
        return HandRank::Flush([ranks[0], ranks[1], ranks[2], ranks[3], ranks[4]]);
    }
    if is_straight {
        return HandRank::Straight(ranks[0]);
    }
    if is_wheel {
        return HandRank::Straight(Rank::Five);
    }
    if count_pattern == [3, 1, 1] {
        let kickers: Vec<Rank> = counts.iter().skip(1).map(|(r, _)| *r).collect();
        return HandRank::ThreeOfAKind(counts[0].0, [kickers[0], kickers[1]]);
    }
    if count_pattern == [2, 2, 1] {
        return HandRank::TwoPair(counts[0].0, counts[1].0, counts[2].0);
    }
    if count_pattern == [2, 1, 1, 1] {
        let kickers: Vec<Rank> = counts.iter().skip(1).map(|(r, _)| *r).collect();
        return HandRank::OnePair(counts[0].0, [kickers[0], kickers[1], kickers[2]]);
    }
    HandRank::HighCard([ranks[0], ranks[1], ranks[2], ranks[3], ranks[4]])
}

pub fn best_hand(cards: &[EvalCard]) -> Option<(HandRank, Vec<EvalCard>)> {
    if cards.len() < 5 {
        return None;
    }
    let mut best_rank: Option<HandRank> = None;
    let mut best_cards: Vec<EvalCard> = Vec::new();
    for combo in cards.iter().combinations(5) {
        let five: [EvalCard; 5] = [*combo[0], *combo[1], *combo[2], *combo[3], *combo[4]];
        let rank = evaluate_five(&five);
        if best_rank.as_ref().is_none_or(|br| rank > *br) {
            best_rank = Some(rank);
            best_cards = five.to_vec();
        }
    }
    best_rank.map(|rank| (rank, best_cards))
}

fn is_straight_high(ranks: &[Rank]) -> bool {
    if ranks.len() != 5 {
        return false;
    }
    for i in 0..4 {
        if ranks[i].value() != ranks[i + 1].value() + 1 {
            return false;
        }
    }
    true
}

fn is_wheel(ranks: &[Rank]) -> bool {
    ranks.len() == 5
        && ranks[0] == Rank::Ace
        && ranks[1] == Rank::Five
        && ranks[2] == Rank::Four
        && ranks[3] == Rank::Three
        && ranks[4] == Rank::Two
}
