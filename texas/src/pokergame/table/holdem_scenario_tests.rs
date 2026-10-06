//! 德州扑克规则全面场景测试（2026-09-15：逻辑正确性验收）。
//!
//! 三层覆盖，与既有测试的分工：
//! - `rules_tests.rs`：下注合法性矩阵 / 轮次完成 / 超时 / reveal 级联 /
//!   座位管理的行为钉板（纯表状态）；
//! - `pot.rs::side_pot_tests`：边池**分层金额**；
//! - 本文件：
//!   1. **牌型评估矩阵**（evaluator/hand_rank 此前零测试）——十类牌型
//!      识别、类别排序链、kicker 逐级比较、wheel/Broadway、7 选 5、
//!      牌面 playing-the-board、公共牌四条 kicker 战；
//!   2. **摊牌结算端到端**（注入明牌 → `evaluate_player_hands` →
//!      `settle_hand`：主池/边池逐层派奖、平分池、抽水扣减、零和
//!      守恒、不足 5 张公共牌的 F5 平分）；
//!   3. **盲注定位与下注序列**（三人首手/跨手 dead-button 轨道、
//!      dead small blind 的前驱补位语义、min-raise 链、fold-win 翻前不抽水/翻后按
//!      公式抽水、未跟注返还净额）。
//!
//! 纯表状态 + mental-poker 明牌直接注入（`playing_card` 字段是 reveal
//! 级联的最终落点，`list_revealed_cards` 只读该字段——注入等价于
//! reveal 完成，不需要走密码学协议）。

use super::*;
use crate::pokergame::betting::BettingRound;
use crate::pokergame::evaluator::{best_hand, evaluate_five};
use crate::pokergame::hand_rank::{Rank, Suit, EvalCard};
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use poker_protocol::crypto::{base_g, ElGamalCiphertext};
use poker_protocol::z_poker::card::{PlayingCard, Rank as CardRank, Suit as CardSuit};
use poker_protocol::z_poker::protocol::{
    PlayerEncryptedCard, PlayerState, RevealState,
};

fn make_table(table_id: u32) -> Table {
    Table::new(table_id, "holdem".to_string(), 10000, 9, String::new())
}

/// 入座假玩家（对齐 rules_tests::seat_fake）。
fn seat_fake(table: &mut Table, seat_id: u32, stack: u64) -> GamePkHex {
    let pk = GamePkHex::new(format!("pk-holdem-{seat_id}"));
    let player = GamePlayer {
        name: format!("p{seat_id}"),
        bankroll: stack as i64,
        pk_hex: pk.clone(),
        readable_hands: vec![],
        wallet_address: WalletAddress(format!("0x{:064x}", seat_id)),
    };
    table.sit_player(player, seat_id, stack, false);
    if let Some(seat) = table.local_seats.get_mut(&seat_id) {
        seat.folded = false;
    }
    pk
}

fn ev(rank: Rank, suit: Suit) -> EvalCard {
    EvalCard::new(rank, suit)
}

fn pc(rank: CardRank, suit: CardSuit) -> PlayingCard {
    PlayingCard { rank, suit }
}

fn card(index: u32, card: PlayingCard) -> PlayerEncryptedCard {
    PlayerEncryptedCard {
        card_index: index,
        encrypted_card: ElGamalCiphertext {
            c1: base_g(),
            c2: base_g(),
        },
        reveal_state: RevealState {
            pending_players: vec![],
            reveal_tokens: vec![],
        },
        playing_card: Some(card),
    }
}

/// 注入某座位的明牌底牌（reveal 完成后的最终形态）。
fn inject_hole_cards(t: &mut Table, pk: &GamePkHex, hole: [PlayingCard; 2]) {
    let state = t.mental_poker_game.players.entry(pk.0.clone()).or_insert_with(
        || PlayerState {
            pk_hex: pk.0.clone(),
            pk: base_g(),
            hand_encrypted: vec![],
            is_leave: false,
        },
    );
    state.hand_encrypted = hole
        .into_iter()
        .enumerate()
        .map(|(i, c)| card(i as u32, c))
        .collect();
}

/// 注入公共牌（数量 = 已发到哪条街；≥5 才可摊牌评估）。
fn inject_board(t: &mut Table, board: &[PlayingCard]) {
    t.mental_poker_game.community_cards_encrypted = board
        .iter()
        .enumerate()
        .map(|(i, c)| card(i as u32, *c))
        .collect();
}

// ============================================================
// 1. 牌型识别与比较（evaluate_five / best_hand / HandRank Ord）
// ============================================================
mod hand_evaluation {
    use super::*;

    #[test]
    fn royal_flush_recognized() {
        let hand = [
            ev(Rank::Ace, Suit::Spades),
            ev(Rank::King, Suit::Spades),
            ev(Rank::Queen, Suit::Spades),
            ev(Rank::Jack, Suit::Spades),
            ev(Rank::Ten, Suit::Spades),
        ];
        assert_eq!(evaluate_five(&hand), crate::pokergame::hand_rank::HandRank::RoyalFlush);
    }

    #[test]
    fn straight_flush_and_steel_wheel() {
        // 9-high 同花顺。
        let nine_high = [
            ev(Rank::Nine, Suit::Hearts),
            ev(Rank::Eight, Suit::Hearts),
            ev(Rank::Seven, Suit::Hearts),
            ev(Rank::Six, Suit::Hearts),
            ev(Rank::Five, Suit::Hearts),
        ];
        assert_eq!(
            evaluate_five(&nine_high),
            crate::pokergame::hand_rank::HandRank::StraightFlush(Rank::Nine)
        );
        // 钢轮（A2345 同花）：5 高同花顺。
        let steel = [
            ev(Rank::Ace, Suit::Clubs),
            ev(Rank::Two, Suit::Clubs),
            ev(Rank::Three, Suit::Clubs),
            ev(Rank::Four, Suit::Clubs),
            ev(Rank::Five, Suit::Clubs),
        ];
        assert_eq!(
            evaluate_five(&steel),
            crate::pokergame::hand_rank::HandRank::StraightFlush(Rank::Five)
        );
    }

    #[test]
    fn quads_full_house_trips_patterns() {
        let quads = [
            ev(Rank::King, Suit::Spades),
            ev(Rank::King, Suit::Hearts),
            ev(Rank::King, Suit::Diamonds),
            ev(Rank::King, Suit::Clubs),
            ev(Rank::Two, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&quads),
            crate::pokergame::hand_rank::HandRank::FourOfAKind(Rank::King, Rank::Two)
        );
        let boat = [
            ev(Rank::Seven, Suit::Spades),
            ev(Rank::Seven, Suit::Hearts),
            ev(Rank::Seven, Suit::Diamonds),
            ev(Rank::Ace, Suit::Clubs),
            ev(Rank::Ace, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&boat),
            crate::pokergame::hand_rank::HandRank::FullHouse(Rank::Seven, Rank::Ace)
        );
        let trips = [
            ev(Rank::Five, Suit::Spades),
            ev(Rank::Five, Suit::Hearts),
            ev(Rank::Five, Suit::Diamonds),
            ev(Rank::Ace, Suit::Clubs),
            ev(Rank::Two, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&trips),
            crate::pokergame::hand_rank::HandRank::ThreeOfAKind(Rank::Five, [Rank::Ace, Rank::Two])
        );
    }

    #[test]
    fn flush_straight_wheel_patterns() {
        let flush = [
            ev(Rank::Ace, Suit::Diamonds),
            ev(Rank::Jack, Suit::Diamonds),
            ev(Rank::Eight, Suit::Diamonds),
            ev(Rank::Six, Suit::Diamonds),
            ev(Rank::Two, Suit::Diamonds),
        ];
        assert_eq!(
            evaluate_five(&flush),
            crate::pokergame::hand_rank::HandRank::Flush([Rank::Ace, Rank::Jack, Rank::Eight, Rank::Six, Rank::Two])
        );
        let broadway = [
            ev(Rank::Ace, Suit::Spades),
            ev(Rank::King, Suit::Hearts),
            ev(Rank::Queen, Suit::Diamonds),
            ev(Rank::Jack, Suit::Clubs),
            ev(Rank::Ten, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&broadway),
            crate::pokergame::hand_rank::HandRank::Straight(Rank::Ace)
        );
        // 轮子（A2345）：5 高顺子，A 只当 1 用。
        let wheel = [
            ev(Rank::Ace, Suit::Spades),
            ev(Rank::Two, Suit::Hearts),
            ev(Rank::Three, Suit::Diamonds),
            ev(Rank::Four, Suit::Clubs),
            ev(Rank::Five, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&wheel),
            crate::pokergame::hand_rank::HandRank::Straight(Rank::Five)
        );
    }

    #[test]
    fn lower_patterns_with_kickers() {
        let two_pair = [
            ev(Rank::Queen, Suit::Spades),
            ev(Rank::Queen, Suit::Hearts),
            ev(Rank::Nine, Suit::Diamonds),
            ev(Rank::Nine, Suit::Clubs),
            ev(Rank::King, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&two_pair),
            crate::pokergame::hand_rank::HandRank::TwoPair(Rank::Queen, Rank::Nine, Rank::King)
        );
        let one_pair = [
            ev(Rank::Ten, Suit::Spades),
            ev(Rank::Ten, Suit::Hearts),
            ev(Rank::Ace, Suit::Diamonds),
            ev(Rank::Seven, Suit::Clubs),
            ev(Rank::Three, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&one_pair),
            crate::pokergame::hand_rank::HandRank::OnePair(Rank::Ten, [Rank::Ace, Rank::Seven, Rank::Three])
        );
        let high = [
            ev(Rank::King, Suit::Spades),
            ev(Rank::Ten, Suit::Hearts),
            ev(Rank::Eight, Suit::Diamonds),
            ev(Rank::Six, Suit::Clubs),
            ev(Rank::Two, Suit::Spades),
        ];
        assert_eq!(
            evaluate_five(&high),
            crate::pokergame::hand_rank::HandRank::HighCard([Rank::King, Rank::Ten, Rank::Eight, Rank::Six, Rank::Two])
        );
    }

    /// 类别排序链：高一类恒压低一类（真实五张样本两两比较）。
    #[test]
    fn category_ordering_chain() {
        let royal = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::King, Suit::Spades),
            ev(Rank::Queen, Suit::Spades), ev(Rank::Jack, Suit::Spades),
            ev(Rank::Ten, Suit::Spades),
        ];
        let quads = [
            ev(Rank::Nine, Suit::Spades), ev(Rank::Nine, Suit::Hearts),
            ev(Rank::Nine, Suit::Diamonds), ev(Rank::Nine, Suit::Clubs),
            ev(Rank::Ace, Suit::Spades),
        ];
        let boat = [
            ev(Rank::King, Suit::Spades), ev(Rank::King, Suit::Hearts),
            ev(Rank::King, Suit::Diamonds), ev(Rank::Queen, Suit::Clubs),
            ev(Rank::Queen, Suit::Spades),
        ];
        let flush = [
            ev(Rank::Ace, Suit::Hearts), ev(Rank::King, Suit::Hearts),
            ev(Rank::Nine, Suit::Hearts), ev(Rank::Seven, Suit::Hearts),
            ev(Rank::Three, Suit::Hearts),
        ];
        let straight = [
            ev(Rank::Nine, Suit::Spades), ev(Rank::Eight, Suit::Hearts),
            ev(Rank::Seven, Suit::Diamonds), ev(Rank::Six, Suit::Clubs),
            ev(Rank::Five, Suit::Spades),
        ];
        let trips = [
            ev(Rank::Four, Suit::Spades), ev(Rank::Four, Suit::Hearts),
            ev(Rank::Four, Suit::Diamonds), ev(Rank::Ace, Suit::Clubs),
            ev(Rank::King, Suit::Spades),
        ];
        let two_pair = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::Ace, Suit::Hearts),
            ev(Rank::King, Suit::Diamonds), ev(Rank::King, Suit::Clubs),
            ev(Rank::Queen, Suit::Spades),
        ];
        let one_pair = [
            ev(Rank::Two, Suit::Spades), ev(Rank::Two, Suit::Hearts),
            ev(Rank::Ace, Suit::Diamonds), ev(Rank::King, Suit::Clubs),
            ev(Rank::Queen, Suit::Spades),
        ];
        let high = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::King, Suit::Hearts),
            ev(Rank::Nine, Suit::Diamonds), ev(Rank::Seven, Suit::Clubs),
            ev(Rank::Five, Suit::Spades),
        ];
        let chain = [royal, quads, boat, flush, straight, trips, two_pair, one_pair, high];
        for pair in chain.windows(2) {
            let high_hand = evaluate_five(&{ [pair[0][0], pair[0][1], pair[0][2], pair[0][3], pair[0][4]] });
            let low_hand = evaluate_five(&{ [pair[1][0], pair[1][1], pair[1][2], pair[1][3], pair[1][4]] });
            assert!(high_hand > low_hand, "{high_hand:?} must beat {low_hand:?}");
        }
    }

    /// 轮子 vs 6 高顺子 / Broadway vs K 高顺子：只比顺子高点。
    #[test]
    fn straight_high_end_comparisons() {
        let wheel = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::Two, Suit::Hearts),
            ev(Rank::Three, Suit::Diamonds), ev(Rank::Four, Suit::Clubs),
            ev(Rank::Five, Suit::Spades),
        ];
        let six_high = [
            ev(Rank::Six, Suit::Spades), ev(Rank::Two, Suit::Hearts),
            ev(Rank::Three, Suit::Diamonds), ev(Rank::Four, Suit::Clubs),
            ev(Rank::Five, Suit::Spades),
        ];
        assert!(evaluate_five(&six_high) > evaluate_five(&wheel));
        let king_high = [
            ev(Rank::King, Suit::Spades), ev(Rank::Queen, Suit::Hearts),
            ev(Rank::Jack, Suit::Diamonds), ev(Rank::Ten, Suit::Clubs),
            ev(Rank::Nine, Suit::Spades),
        ];
        let broadway = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::King, Suit::Hearts),
            ev(Rank::Queen, Suit::Diamonds), ev(Rank::Jack, Suit::Clubs),
            ev(Rank::Ten, Suit::Spades),
        ];
        assert!(evaluate_five(&broadway) > evaluate_five(&king_high));
    }

    /// kicker 逐级比较：对子/两对/三条/四条/同花。
    #[test]
    fn kicker_chains() {
        let c = |r: Rank, s: Suit| ev(r, s);
        // 一对：第三 kicker 定胜负。
        let pair_high = [c(Rank::Ace, Suit::Spades), c(Rank::Ace, Suit::Hearts), c(Rank::King, Suit::Diamonds), c(Rank::Queen, Suit::Clubs), c(Rank::Nine, Suit::Spades)];
        let pair_low = [c(Rank::Ace, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::King, Suit::Diamonds), c(Rank::Queen, Suit::Clubs), c(Rank::Eight, Suit::Spades)];
        assert!(evaluate_five(&pair_high) > evaluate_five(&pair_low));
        // 两对：先比高对、再比低对、最后 kicker。
        let tp_high_top = [c(Rank::Ace, Suit::Spades), c(Rank::Ace, Suit::Hearts), c(Rank::Three, Suit::Diamonds), c(Rank::Three, Suit::Clubs), c(Rank::King, Suit::Spades)];
        let tp_high_bottom = [c(Rank::Ace, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::Two, Suit::Diamonds), c(Rank::Two, Suit::Clubs), c(Rank::King, Suit::Spades)];
        assert!(evaluate_five(&tp_high_top) > evaluate_five(&tp_high_bottom));
        let tp_kicker = [c(Rank::Ace, Suit::Spades), c(Rank::Ace, Suit::Hearts), c(Rank::Three, Suit::Diamonds), c(Rank::Three, Suit::Clubs), c(Rank::King, Suit::Spades)];
        let tp_kicker_low = [c(Rank::Ace, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::Three, Suit::Hearts), c(Rank::Three, Suit::Spades), c(Rank::Queen, Suit::Spades)];
        assert!(evaluate_five(&tp_kicker) > evaluate_five(&tp_kicker_low));
        // 三条：kicker 链。
        let trips_hi = [c(Rank::Nine, Suit::Spades), c(Rank::Nine, Suit::Hearts), c(Rank::Nine, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::King, Suit::Spades)];
        let trips_lo = [c(Rank::Nine, Suit::Diamonds), c(Rank::Nine, Suit::Clubs), c(Rank::Nine, Suit::Spades), c(Rank::Ace, Suit::Hearts), c(Rank::Queen, Suit::Spades)];
        assert!(evaluate_five(&trips_hi) > evaluate_five(&trips_lo));
        // 四条：比单张 kicker（明四条常见场景）。
        let quads_hi = [c(Rank::Seven, Suit::Spades), c(Rank::Seven, Suit::Hearts), c(Rank::Seven, Suit::Diamonds), c(Rank::Seven, Suit::Clubs), c(Rank::Ace, Suit::Spades)];
        let quads_lo = [c(Rank::Seven, Suit::Spades), c(Rank::Seven, Suit::Hearts), c(Rank::Seven, Suit::Diamonds), c(Rank::Seven, Suit::Clubs), c(Rank::King, Suit::Spades)];
        assert!(evaluate_five(&quads_hi) > evaluate_five(&quads_lo));
        // 同花：逐张比。
        let flush_hi = [c(Rank::Ace, Suit::Hearts), c(Rank::King, Suit::Hearts), c(Rank::Nine, Suit::Hearts), c(Rank::Six, Suit::Hearts), c(Rank::Four, Suit::Hearts)];
        let flush_lo = [c(Rank::Ace, Suit::Spades), c(Rank::King, Suit::Spades), c(Rank::Nine, Suit::Spades), c(Rank::Six, Suit::Spades), c(Rank::Three, Suit::Spades)];
        assert!(evaluate_five(&flush_hi) > evaluate_five(&flush_lo));
    }

    /// 葫芦比较：先比三条；三条相同比一对。
    #[test]
    fn full_house_chain() {
        let c = |r: Rank, s: Suit| ev(r, s);
        let trips_eight = [c(Rank::Eight, Suit::Spades), c(Rank::Eight, Suit::Hearts), c(Rank::Eight, Suit::Diamonds), c(Rank::Five, Suit::Clubs), c(Rank::Five, Suit::Spades)];
        let trips_seven = [c(Rank::Seven, Suit::Spades), c(Rank::Seven, Suit::Hearts), c(Rank::Seven, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::Ace, Suit::Spades)];
        assert!(evaluate_five(&trips_eight) > evaluate_five(&trips_seven));
        // 同为 888：AA 对 > KK 对（公共三条 + 底牌对的真实场景）。
        let pair_aces = [c(Rank::Eight, Suit::Spades), c(Rank::Eight, Suit::Hearts), c(Rank::Eight, Suit::Diamonds), c(Rank::Ace, Suit::Clubs), c(Rank::Ace, Suit::Spades)];
        let pair_kings = [c(Rank::Eight, Suit::Spades), c(Rank::Eight, Suit::Hearts), c(Rank::Eight, Suit::Diamonds), c(Rank::King, Suit::Clubs), c(Rank::King, Suit::Spades)];
        assert!(evaluate_five(&pair_aces) > evaluate_five(&pair_kings));
    }

    /// 7 选 5：同花 > 顺子；葫芦 > 同花（同一手七张里的最优组合）。
    #[test]
    fn best_hand_selects_best_five_of_seven() {
        let c = |r: Rank, s: Suit| ev(r, s);
        // 七张：黑桃同花 + 无关顺子原料 → 选同花。
        let seven_flush = [
            c(Rank::Ace, Suit::Spades), c(Rank::King, Suit::Spades),
            c(Rank::Nine, Suit::Spades), c(Rank::Six, Suit::Spades),
            c(Rank::Two, Suit::Spades),
            c(Rank::Queen, Suit::Hearts), c(Rank::Jack, Suit::Diamonds),
        ];
        let (rank, used) = best_hand(&seven_flush).expect("7 cards have a hand");
        assert_eq!(rank, crate::pokergame::hand_rank::HandRank::Flush([Rank::Ace, Rank::King, Rank::Nine, Rank::Six, Rank::Two]));
        assert_eq!(used.len(), 5);
        // 七张：葫芦 + 一对原料 → 选葫芦。
        let seven_boat = [
            c(Rank::King, Suit::Spades), c(Rank::King, Suit::Hearts),
            c(Rank::King, Suit::Diamonds), c(Rank::Three, Suit::Clubs),
            c(Rank::Three, Suit::Spades),
            c(Rank::Three, Suit::Hearts), c(Rank::Two, Suit::Diamonds),
        ];
        let (rank, _) = best_hand(&seven_boat).expect("boat");
        assert_eq!(rank, crate::pokergame::hand_rank::HandRank::FullHouse(Rank::King, Rank::Three));
    }

    /// 牌面 playing the board：两家都打公共牌 → 平分。
    #[test]
    fn board_plays_split() {
        let board = [
            ev(Rank::Ace, Suit::Spades), ev(Rank::King, Suit::Hearts),
            ev(Rank::Queen, Suit::Diamonds), ev(Rank::Jack, Suit::Clubs),
            ev(Rank::Nine, Suit::Spades),
        ];
        let junk_a = [ev(Rank::Two, Suit::Hearts), ev(Rank::Three, Suit::Hearts), board[0], board[1], board[2], board[3], board[4]];
        let junk_b = [ev(Rank::Seven, Suit::Hearts), ev(Rank::Six, Suit::Hearts), board[0], board[1], board[2], board[3], board[4]];
        let (ra, _) = best_hand(&junk_a).unwrap();
        let (rb, _) = best_hand(&junk_b).unwrap();
        assert_eq!(ra, rb, "both play the board A-K-Q-J-9");
    }

    /// 公共牌四条 + 单张 kicker 战：底牌 A 压底牌 K。
    #[test]
    fn board_quads_kicker_battle() {
        let c = |r: Rank, s: Suit| ev(r, s);
        let board = [
            c(Rank::Seven, Suit::Spades), c(Rank::Seven, Suit::Hearts),
            c(Rank::Seven, Suit::Diamonds), c(Rank::Seven, Suit::Clubs),
            c(Rank::Two, Suit::Spades),
        ];
        let ace_hole = [c(Rank::Ace, Suit::Spades), c(Rank::Three, Suit::Hearts), board[0], board[1], board[2], board[3], board[4]];
        let king_hole = [c(Rank::King, Suit::Spades), c(Rank::Queen, Suit::Hearts), board[0], board[1], board[2], board[3], board[4]];
        let (ra, _) = best_hand(&ace_hole).unwrap();
        let (rk, _) = best_hand(&king_hole).unwrap();
        assert_eq!(ra, crate::pokergame::hand_rank::HandRank::FourOfAKind(Rank::Seven, Rank::Ace));
        assert!(ra > rk);
    }

    /// 公共牌轮子 + 底牌 6 → 6 高顺子压公共轮子（经典陷阱场景）。
    #[test]
    fn board_wheel_hole_six_makes_six_high_straight() {
        let c = |r: Rank, s: Suit| ev(r, s);
        let board = [
            c(Rank::Ace, Suit::Spades), c(Rank::Two, Suit::Hearts),
            c(Rank::Three, Suit::Diamonds), c(Rank::Four, Suit::Clubs),
            c(Rank::Five, Suit::Spades),
        ];
        let with_six = [c(Rank::Six, Suit::Hearts), c(Rank::Six, Suit::Diamonds), board[0], board[1], board[2], board[3], board[4]];
        let plays_board = [c(Rank::King, Suit::Hearts), c(Rank::Queen, Suit::Diamonds), board[0], board[1], board[2], board[3], board[4]];
        let (r6, _) = best_hand(&with_six).unwrap();
        let (rb, _) = best_hand(&plays_board).unwrap();
        assert_eq!(r6, crate::pokergame::hand_rank::HandRank::Straight(Rank::Six));
        assert!(r6 > rb, "6-high straight must beat the board wheel");
    }

    /// 七张里成对 + 四张顺子原料：识别顺子而非顺子对子混淆——
    /// 顺子 > 一对（类别优先）。
    #[test]
    fn best_hand_prefers_straight_over_pair_decoy() {
        let c = |r: Rank, s: Suit| ev(r, s);
        let seven = [
            c(Rank::Five, Suit::Spades), c(Rank::Six, Suit::Hearts),
            c(Rank::Seven, Suit::Diamonds), c(Rank::Eight, Suit::Clubs),
            c(Rank::Nine, Suit::Spades),
            c(Rank::Nine, Suit::Hearts), c(Rank::Nine, Suit::Diamonds),
        ];
        let (rank, _) = best_hand(&seven).unwrap();
        assert!(rank > crate::pokergame::hand_rank::HandRank::HighCard([Rank::Ace; 5]));
        assert!(rank > crate::pokergame::hand_rank::HandRank::ThreeOfAKind(Rank::Nine, [Rank::Ace, Rank::King]));
    }

    /// 少于 5 张无手牌；同花七张取最高五张。
    #[test]
    fn best_hand_edge_shapes() {
        let c = |r: Rank, s: Suit| ev(r, s);
        let four = [c(Rank::Ace, Suit::Spades), c(Rank::King, Suit::Hearts), c(Rank::Queen, Suit::Diamonds), c(Rank::Jack, Suit::Clubs)];
        assert!(best_hand(&four).is_none());
        // 6 张同花：取前五高。
        let six_flush = [
            c(Rank::Ace, Suit::Clubs), c(Rank::King, Suit::Clubs),
            c(Rank::Queen, Suit::Clubs), c(Rank::Jack, Suit::Clubs),
            c(Rank::Nine, Suit::Clubs), c(Rank::Seven, Suit::Clubs),
        ];
        let (rank, used) = best_hand(&six_flush).unwrap();
        assert_eq!(rank, crate::pokergame::hand_rank::HandRank::Flush([Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]));
        assert_eq!(used.len(), 5);
        assert!(!used.contains(&c(Rank::Seven, Suit::Clubs)), "lowest card dropped");
    }
}

// ============================================================
// 2. 摊牌结算（注入明牌 → evaluate_player_hands → settle_hand）
// ============================================================
mod showdown_settlement {
    use super::*;

    /// 带真实玩家与底注记账的摊牌桌。
    /// (id, stack_after, total_bet, folded)；pot = Σ total_bet + extra。
    fn showdown_table(
        table_id: u32,
        seats: &[(u32, u64, u64, bool)],
    ) -> Table {
        let mut t = make_table(table_id);
        for &(id, stack_after, total_bet, folded) in seats {
            let pk = seat_fake(&mut t, id, stack_after.max(total_bet));
            let _ = pk;
            if let Some(s) = t.local_seats.get_mut(&id) {
                s.stack = stack_after;
                s.total_bet = total_bet;
                s.folded = folded;
            }
        }
        let pot: u64 = t.local_seats.values().map(|s| s.total_bet).sum();
        t.set_pot(pot);
        t
    }

    fn hole(t: &mut Table, seat_id: u32, cards: [CardRank; 2]) {
        let pk = GamePkHex::new(format!("pk-holdem-{seat_id}"));
        inject_hole_cards(
            t,
            &pk,
            [pc(cards[0], CardSuit::Spade), pc(cards[1], CardSuit::Heart)],
        );
    }

    fn board(t: &mut Table, cards: [CardRank; 5]) {
        let suits = [
            CardSuit::Spade,
            CardSuit::Heart,
            CardSuit::Diamond,
            CardSuit::Club,
            CardSuit::Spade,
        ];
        let board: Vec<PlayingCard> = cards
            .into_iter()
            .zip(suits)
            .map(|(r, s)| pc(r, s))
            .collect();
        inject_board(&mut *t, &board);
    }

    fn stacks(t: &Table) -> Vec<u64> {
        [1, 2, 3, 4]
            .iter()
            .map(|id| t.local_seats.get(id).map(|s| s.stack).unwrap_or(0))
            .collect()
    }

    /// 高对压低对：赢家净得 pot − rake（默认 5%，cap 1000）；
    /// 零和守恒；状态机收尾正确。
    #[test]
    fn higher_pair_wins_raked_showdown() {
        let mut t = showdown_table(40_101, &[(1, 2000, 1000, false), (2, 2000, 1000, false)]);
        hole(&mut t, 1, [CardRank::King, CardRank::King]); // 口袋对 K
        hole(&mut t, 2, [CardRank::Ace, CardRank::Ace]); // 口袋对 A
        board(&mut t, [CardRank::Nine, CardRank::Four, CardRank::Two, CardRank::Seven, CardRank::Jack]);

        t.settle_hand();

        // 期望：P2 一对 A 胜；contested = 2000 → rake = 100（5% ≤ cap）。
        assert_eq!(t.summary.rake_collected, 100);
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 2000 + 1900);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 2000);
        // pot 保留净额（record_hand_history 以 pot + rake 重建毛额；
        // 清零发生在下一手 start_hand 的 reset_board_and_pot）。
        assert_eq!(t.pot(), 1900, "pot keeps the net amount after settle");
        assert!(t.summary.went_to_showdown);
        assert!(t.summary.hand_over);
        assert_eq!(t.round_state(), RoundState::Waiting);
        // 零和：初始 8000 = 终局 8000 + rake 100？ 不——rake 离开玩家
        // 手中，终局 stacks + rake == 初始。
        assert_eq!(
            stacks(&t).iter().sum::<u64>() + t.summary.rake_collected,
            6000,
            "chip conservation"
        );
        assert!(t.summary.win_messages.iter().any(|m| m.contains("wins")));
    }

    /// 同点数比 kicker：都是一对 A，Q kicker 压 J kicker。
    #[test]
    fn kicker_beats_same_pair() {
        let mut t = showdown_table(40_102, &[(1, 1500, 500, false), (2, 1500, 500, false)]);
        hole(&mut t, 1, [CardRank::Ace, CardRank::Queen]);
        hole(&mut t, 2, [CardRank::Ace, CardRank::Jack]);
        board(&mut t, [CardRank::Ace, CardRank::Nine, CardRank::Five, CardRank::Two, CardRank::King]);

        t.settle_hand();
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1500 + 1000 - 50);
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 1500);
    }

    /// 三层 all-in 边池逐层派奖（真实手牌决胜负）：
    /// A 短 all-in 100 持最强牌（主池）；B all-in 300 持次强（第一边池）；
    /// C 跟满 500 持最弱（外层 200 = 未跟注返还自拿）。
    #[test]
    fn side_pot_awards_per_layer_with_real_hands() {
        let mut t = showdown_table(
            40_103,
            &[
                (1, 0, 100, false),   // A all-in 100
                (2, 0, 300, false),   // B all-in 300
                (3, 500, 500, false), // C 跟满仍有筹码
            ],
        );
        // 公共牌 9-4-2-7-J 无花无顺：A 一对 A（Ad Ah）> B 一对 9（9s 9c）？
        // 注意 9 在公共牌：B 成对 9 < A 成对 A；C 高牌 K 最弱。
        hole(&mut t, 1, [CardRank::Ace, CardRank::Queen]); // 对 A（A 配 Q kicker）
        hole(&mut t, 2, [CardRank::King, CardRank::Eight]); // 高牌 K——比 C 低？
        hole(&mut t, 3, [CardRank::Ten, CardRank::Six]); // 高牌 T 最弱
        board(&mut t, [CardRank::Ace, CardRank::Nine, CardRank::Four, CardRank::Two, CardRank::Seven]);
        // 手牌实况：A = 对 A(A,A,K,9,7)；B = 高牌 K(K,9,8,7,4)；C = 高牌
        // T(T,9,7,6,4)。主池 {A,B,C}：A 胜；边池 {B,C}：B 胜；外层 {C}。

        t.calculate_side_pots();
        assert_eq!(t.summary.side_pots.len(), 2, "两层边池：{:?}", t.summary.side_pots);
        assert_eq!(t.summary.side_pots[0].amount, 400, "B/C 争夺层");
        assert_eq!(t.summary.side_pots[1].amount, 200, "C 独占未跟注层");
        assert_eq!(t.main_pot(), 300);

        t.settle_hand();
        // contested = 主池 300 + 边池 400 = 700 → rake 35（5%）。
        assert_eq!(t.summary.rake_collected, 35);
        // 主池 285 → A；边池 380 → B；外层 200 → C（返还）。
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 285, "A wins the main pot");
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 380, "B wins the first side pot");
        assert_eq!(t.local_seats.get(&3).unwrap().stack, 500 + 200, "C gets the uncalled layer back");
        // 零和守恒：初始 1400 = 终局 + rake。
        assert_eq!(
            stacks(&t).iter().sum::<u64>() + t.summary.rake_collected,
            100 + 300 + 1000
        );
    }

    /// 公共牌成牌两家都打 → 平分池（偶数池精确对半）。
    #[test]
    fn board_play_split_even() {
        let mut t = showdown_table(40_104, &[(1, 1500, 500, false), (2, 1500, 500, false)]);
        hole(&mut t, 1, [CardRank::Two, CardRank::Three]);
        hole(&mut t, 2, [CardRank::Seven, CardRank::Eight]);
        board(&mut t, [CardRank::Ace, CardRank::King, CardRank::Queen, CardRank::Jack, CardRank::Nine]);

        t.settle_hand();
        // 两人都打 A-K-Q-J-9 高牌 → 平分 1000 − 50 rake = 950？ 不：
        // rake 先扣（950）再平分 → 475/475。
        assert_eq!(t.summary.rake_collected, 50);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1500 + 475);
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 1500 + 475);
        assert!(t.summary.win_messages.iter().any(|m| m.contains("High Card")));
    }

    /// 三家平分（公共牌为各家最优）：900 池 → 300/300/300。
    #[test]
    fn three_way_split_even() {
        let mut t = showdown_table(
            40_107,
            &[(1, 1000, 300, false), (2, 1000, 300, false), (3, 1000, 300, false)],
        );
        hole(&mut t, 1, [CardRank::Two, CardRank::Three]);
        hole(&mut t, 2, [CardRank::Four, CardRank::Five]);
        hole(&mut t, 3, [CardRank::Seven, CardRank::Eight]);
        board(&mut t, [CardRank::Ace, CardRank::King, CardRank::Queen, CardRank::Jack, CardRank::Nine]);

        t.settle_hand();
        // 三方争夺层 900 → rake 45 → 855 可整除 3 → 285/285/285。
        assert_eq!(t.summary.rake_collected, 45);
        for id in 1..=3 {
            assert_eq!(t.local_seats.get(&id).unwrap().stack, 1000 + 285);
        }
    }

    /// 不足 5 张公共牌 → 评估为空 → F5 平分路径（eligible 序 =
    /// eligible_ids 序，奇数筹码归首座）。
    #[test]
    fn under_five_board_cards_split_without_evaluation() {
        let mut t = showdown_table(40_105, &[(1, 1000, 101, false), (2, 1000, 0, false)]);
        hole(&mut t, 1, [CardRank::Ace, CardRank::King]);
        hole(&mut t, 2, [CardRank::Two, CardRank::Three]);
        // 4 张公共牌（< 5）→ evaluate_player_hands 返回空。
        t.mental_poker_game.community_cards_encrypted = [CardRank::Queen, CardRank::Jack, CardRank::Nine, CardRank::Seven]
            .into_iter()
            .enumerate()
            .map(|(i, r)| PlayerEncryptedCard {
                card_index: i as u32,
                encrypted_card: ElGamalCiphertext {
                    c1: base_g(),
                    c2: base_g(),
                },
                reveal_state: RevealState {
                    pending_players: vec![],
                    reveal_tokens: vec![],
                },
                playing_card: Some(pc(r, CardSuit::Spade)),
            })
            .collect();

        t.determine_winner_by_ids(101, &[1, 2]);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1000 + 51, "first eligible takes the odd chip");
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 1000 + 50);
    }

    /// 弃牌者不能赢池：注入了牌但 folded → 排除在评估之外。
    #[test]
    fn folded_seat_excluded_from_evaluation() {
        let mut t = showdown_table(
            40_106,
            &[
                (1, 1000, 100, true),  // 弃牌
                (2, 1000, 100, false),
                (3, 1000, 100, false),
            ],
        );
        hole(&mut t, 1, [CardRank::Ace, CardRank::King]); // 最强但已弃
        hole(&mut t, 2, [CardRank::Queen, CardRank::Jack]);
        hole(&mut t, 3, [CardRank::Ten, CardRank::Eight]);
        board(&mut t, [CardRank::Ace, CardRank::Nine, CardRank::Four, CardRank::Two, CardRank::Seven]);

        let results: Vec<u32> = t
            .evaluate_player_hands()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(!results.contains(&1), "folded seat must not be evaluated");

        t.settle_hand();
        // 2 与 3 争夺：2 的高牌 A,Q,J,9,4? 2 = A,Q,J,9,4；3 = A,9,9…
        // 3 有对 9（9h 公共 + 9h? 不——公共 9 一张）→ 2: A,Q,J,9,4 高牌；
        // 3: T,9 → 高牌 A,9… 2 胜（Q kicker）。
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 1000 + 300 - 15);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1000);
    }
}

// ============================================================
// 3. 盲注定位 / 下注序列 / fold-win 抽水
// ============================================================
mod blinds_betting_and_fold_win {
    use super::*;
    use crate::pokergame::rake::fold_win_rake;
    use poker_protocol::z_poker::card::PlayingCard as PCard;

    /// 三人首手（无盲注轨道）：按钮即小盲（dead-button 轨道模型——
    /// 与 canonical AIR rc 组的 SB = rotation_base 同一口径）。
    #[test]
    fn three_handed_first_hand_blinds() {
        let mut t = make_table(40_201);
        seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        seat_fake(&mut t, 3, 1000);
        t.set_button(Some(3));
        t.set_last_bb_seat(None);
        t.set_blinds();
        assert_eq!(t.big_blind(), Some(1), "BB = button 的下一位");
        assert_eq!(t.small_blind(), Some(3), "首手小盲 = 按钮座位");
        assert_eq!(t.pot(), 150);
        assert_eq!(t.turn(), Some(2), "UTG = BB 后第一个可行动座位");
        assert_eq!(t.last_bb_seat(), 1, "BB 轨道推进");
    }

    /// 跨手：轨道（上一手 BB）为轮转基准 → SB = 上手 BB、BB = 下一位
    ///（TDA dead-button 规则）。
    #[test]
    fn second_hand_blinds_rotate_by_track() {
        let mut t = make_table(40_202);
        seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        seat_fake(&mut t, 3, 1000);
        t.set_button(Some(1));
        t.set_last_bb_seat(Some(2));
        t.set_blinds();
        assert_eq!(t.small_blind(), Some(2), "SB = 上一手 BB 座位");
        assert_eq!(t.big_blind(), Some(3));
        assert_eq!(t.turn(), Some(1), "UTG 绕回按钮");
        assert_eq!(t.last_bb_seat(), 3);
    }

    /// 轮转基准座位 sitting out：基准回退到其前驱参与者（环形——座 1
    /// 低于全部参与者时环绕到最大座位 4）补位小盲，与镜像压缩 rank
    /// 映射一致。
    #[test]
    fn departed_base_predecessor_posts_small_blind() {
        let mut t = make_table(40_203);
        seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        seat_fake(&mut t, 3, 1000);
        seat_fake(&mut t, 4, 1000);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.sitting_out = true;
        }
        t.set_button(Some(2));
        t.set_last_bb_seat(Some(1));
        t.set_blinds();
        assert_eq!(t.small_blind(), Some(4), "基准座不参与 → 前驱参与者（环形环绕到座 4）交小盲");
        assert_eq!(t.big_blind(), Some(2), "BB = 基准后第一个参与者");
        assert_eq!(t.pot(), 150, "小盲 50 + 大盲 100 入池");
    }

    /// 盲注 all-in 封顶：SB 不足额只投全部；BB 不足额投全部。
    #[test]
    fn short_blinds_post_all_in() {
        let mut t = make_table(40_208);
        seat_fake(&mut t, 1, 30);
        seat_fake(&mut t, 2, 1000);
        seat_fake(&mut t, 3, 1000);
        seat_fake(&mut t, 4, 1000);
        // 首手（无轨道）：SB = 按钮(4)、BB = 座 1（仅 30 → 封顶全下）。
        t.set_button(Some(4));
        t.set_last_bb_seat(None);
        t.set_blinds();
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 0, "short BB posts all-in");
        assert_eq!(t.pot(), 50 + 30, "SB 50 + BB capped 30");
        assert_eq!(t.local_seats.get(&4).unwrap().stack, 1000 - 50, "SB 满额");
        assert!(t.has_actionable_player(), "仍有可行动玩家");
    }

    /// min-raise 链：加注更新 current_bet 与 min_raise；短 all-in 只推
    /// current_bet 不重开。
    #[test]
    fn raise_chain_updates_min_raise() {
        let mut br = BettingRound::new_preflop(100);
        br.update_after_raise(300, 1, false);
        assert_eq!((br.current_bet(), br.min_raise()), (300, 200));
        br.update_after_raise(700, 2, false);
        assert_eq!((br.current_bet(), br.min_raise()), (700, 400));
        // 短 all-in（增量 80 < 400）：current 推进、min_raise 不动。
        br.update_after_raise(780, 3, true);
        assert_eq!((br.current_bet(), br.min_raise()), (780, 400));
    }

    /// 翻前 fold-win：未跟注部分自然返还（赢家独吞全池，净额 = 对手
    /// 投入），不抽水。
    #[test]
    fn preflop_fold_win_returns_uncalled_net() {
        let mut t = make_table(40_204);
        seat_fake(&mut t, 1, 500);
        seat_fake(&mut t, 2, 1000);
        t.transition_to(RoundState::PreFlop);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 500;
            s.total_bet = 500;
            s.stack = 500;
        }
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.bet = 100;
            s.total_bet = 100;
            s.folded = true;
        }
        t.set_pot(600);

        t.end_without_showdown();
        // A 投 500 赢 600 → 净 +100（恰好 B 的投入）；无台费。
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 500 + 600);
        assert_eq!(t.summary.rake_collected, 0, "no flop, no drop");
    }

    /// 翻后 fold-win：按 fold_win_rake 公式抽水——基数 = 池 − 未跟注
    /// 部分，抽水后派净池。
    #[test]
    fn postflop_fold_win_raked_by_formula() {
        let mut t = make_table(40_205);
        seat_fake(&mut t, 1, 500);
        seat_fake(&mut t, 2, 1000);
        t.transition_to(RoundState::Flop);
        // 翻牌已见（3 张公共明牌）→ flop_seen。
        t.mental_poker_game.community_cards_encrypted = (0..3)
            .map(|i| PlayerEncryptedCard {
                card_index: i,
                encrypted_card: ElGamalCiphertext {
                    c1: base_g(),
                    c2: base_g(),
                },
                reveal_state: RevealState {
                    pending_players: vec![],
                    reveal_tokens: vec![],
                },
                playing_card: Some(PCard {
                    rank: CardRank::Ace,
                    suit: CardSuit::Spade,
                }),
            })
            .collect();
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 500;
            s.total_bet = 500;
            s.stack = 500;
        }
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.bet = 300;
            s.total_bet = 300;
            s.folded = true;
        }
        t.set_pot(800);

        t.end_without_showdown();
        // 公式：uncalled = 500−300 = 200；contested = 600 → 5% = 30。
        let expected = fold_win_rake(800, &[500, 300], 0, true);
        assert_eq!(t.summary.rake_collected, expected);
        assert_eq!(expected, 30);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 500 + 770);
        // 初始买入：座 1 = 500(下注) + 500(剩余)；座 2 = 300 + 1000。
        assert_eq!(
            stacks_sum(&t) + t.summary.rake_collected,
            500 + 500 + 300 + 1000,
            "chip conservation"
        );
    }

    fn stacks_sum(t: &Table) -> u64 {
        t.local_seats.values().map(|s| s.stack).sum()
    }
}
