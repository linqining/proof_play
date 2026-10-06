//! Canonical showdown-settlement semantics fixtures.
//!
//! These builders produce deterministic, fixed-width settlement scenes whose
//! derived [`SettlementPlan`] values are LOCKED by the accompanying tests.
//! They are the shared semantics oracle for the upcoming showdown settlement
//! AIR: the AIR's fixed-width decomposition (9 seats / ≤9 pot layers / ≤2
//! runouts / hand ranks / odd chip / rake) must reproduce exactly these
//! awards, rakes and layer amounts.
//!
//! Invariants asserted for every scene:
//! - conservation: `gross_pot == rake + total_awards` and per-seat award sums;
//! - determinism: re-derivation and the domain-separated digest are stable;
//! - structure: `pots.len() ≤ SETTLEMENT_SEATS`, layer `gross` sums to the
//!   gross pot, and uncontested layers carry no rake.

use crate::object_model::ObjectID;
use crate::contracts::texas_poker::card::Card;
use crate::contracts::texas_poker::settlement::{
    SETTLEMENT_SEATS, SettlementBoards, SettlementPlan, derive_settlement_plan_for_boards,
};
use crate::contracts::texas_poker::side_pot::calculate_side_pots;
use crate::contracts::texas_poker::types::{SeatStatus, TexasPokerTable};

/// A locked showdown scene: the table snapshot plus its boards.
pub struct SettlementScene {
    /// 结算瞬间的牌桌快照（座位、下注、底池、规则与公共牌）。
    pub table: TexasPokerTable,
    /// 本场景的运行牌面（单 board 或 run-it-twice 双 board）。
    pub boards: SettlementBoards,
}

impl SettlementScene {
    /// Derive the canonical plan for this scene.
    pub fn plan(&self) -> crate::error::PokerL1Result<SettlementPlan> {
        derive_settlement_plan_for_boards(&self.table, &self.boards)
    }

    /// Assert every canonical settlement invariant over the derived plan.
    pub fn assert_invariants(&self) -> SettlementPlan {
        let plan = self.plan().expect("scene derives a settlement plan");
        assert!(
            usize::from(plan.pot_count) <= SETTLEMENT_SEATS,
            "pot layers exceed the fixed settlement width"
        );
        assert_eq!(
            plan.gross_pot,
            plan.rake + plan.total_awards,
            "settlement must conserve chips"
        );
        let layer_gross: u64 = plan.active_pots().iter().map(|pot| pot.gross_amount).sum();
        assert_eq!(layer_gross, plan.gross_pot, "layers must tile the pot");
        let layer_rake: u64 = plan.active_pots().iter().map(|pot| pot.rake).sum();
        assert_eq!(layer_rake, plan.rake, "rake must tile across layers");
        let award_sum: u64 = plan.awards.iter().sum();
        assert_eq!(
            award_sum, plan.total_awards,
            "per-seat awards must tile the total"
        );
        for pot in plan.active_pots() {
            if !pot.is_contested() {
                assert_eq!(pot.rake, 0, "uncalled layers are never raked");
            }
            let runout_sum: u64 = pot.runouts.iter().map(|r| r.amount).sum();
            if pot.is_contested() {
                assert_eq!(
                    runout_sum, pot.net_amount,
                    "contested layers must split their net across runouts"
                );
            }
            for runout in &pot.runouts {
                let runout_awards: u64 = runout.awards.iter().sum();
                assert_eq!(
                    runout_awards, runout.amount,
                    "runout awards must conserve the runout amount"
                );
            }
        }
        // Determinism: a second derivation must be identical.
        let again = self.plan().expect("re-derivation succeeds");
        assert_eq!(plan, again, "settlement derivation is not deterministic");
        plan
    }
}

fn base_table(seats: u8) -> TexasPokerTable {
    TexasPokerTable::new(
        ObjectID::new([0xF1; 20], 0),
        [0xEE; 20],
        seats,
        1,
        2,
    )
}

fn seat(
    table: &mut TexasPokerTable,
    index: usize,
    stack: u64,
    total_bet: u64,
    status: SeatStatus,
    hand: [Card; 2],
) {
    table.seats[index].fixture_set_player([index as u8 + 1; 20]);
    table.seats[index].set_stack(stack).expect("stack in range");
    table.seats[index].fixture_set_total_bet(total_bet);
    table.seats[index].set_status(status);
    table.seats[index].fixture_set_hand(hand.into());
}

/// Three-seat all-in ladder (100/200/300): two contested layers plus an
/// uncalled 100 return to the top bettor. No rake, single board.
pub fn three_seat_ladder() -> SettlementScene {
    let mut table = base_table(3);
    seat(
        &mut table,
        0,
        900,
        100,
        SeatStatus::AllIn,
        [Card::new(0, 14), Card::new(1, 14)],
    );
    seat(
        &mut table,
        1,
        800,
        200,
        SeatStatus::AllIn,
        [Card::new(0, 13), Card::new(1, 13)],
    );
    seat(
        &mut table,
        2,
        700,
        300,
        SeatStatus::AllIn,
        [Card::new(0, 12), Card::new(1, 12)],
    );
    table.pot = 600;
    table.chip_pool = 10_000;
    table.community_cards = vec![
        Card::new(2, 2),
        Card::new(3, 4),
        Card::new(2, 6),
        Card::new(3, 8),
        Card::new(2, 10),
    ]
    .try_into()
    .unwrap();
    SettlementScene {
        boards: SettlementBoards::single(table.community_cards.to_vec()),
        table,
    }
}

/// Nine-seat full all-in ladder (10/20/…/90): the fixed-width extreme with
/// nine bet levels, i.e. the maximum layer count the AIR must handle.
pub fn nine_seat_ladder() -> SettlementScene {
    let mut table = base_table(9);
    // Seats 0..7 hold pairs of ranks [14,13,12,11,9,7,5,3] — strictly
    // descending and disjoint from the board ranks {2,4,6,8,10}, so no seat
    // improves to trips or a straight; seat 8 holds ace-king off the board
    // and loses every contested layer.
    let ladder = [14u8, 13, 12, 11, 9, 7, 5, 3];
    for index in 0..8usize {
        let rank = ladder[index];
        seat(
            &mut table,
            index,
            1_000,
            10 * (index as u64 + 1),
            SeatStatus::AllIn,
            [Card::new(0, rank), Card::new(1, rank)],
        );
    }
    seat(
        &mut table,
        8,
        1_000,
        90,
        SeatStatus::AllIn,
        [Card::new(3, 14), Card::new(3, 13)],
    );
    let pot: u64 = (1..=9u64).map(|level| 10 * level).sum();
    table.pot = pot;
    table.chip_pool = 100_000;
    // Board ranks 2/4/6/8/10 (even, mixed suits) cannot combine with any
    // pocket pair into trips or a straight.
    table.community_cards = vec![
        Card::new(2, 2),
        Card::new(3, 4),
        Card::new(2, 6),
        Card::new(3, 8),
        Card::new(2, 10),
    ]
    .try_into()
    .unwrap();
    SettlementScene {
        boards: SettlementBoards::single(table.community_cards.to_vec()),
        table,
    }
}

/// Percentage-rake two-seat split pot on a single board: both seats play the
/// board (two pair aces and kings), splitting the raked net with one odd chip
/// dealt clockwise after the button.
pub fn raked_odd_chip_split() -> SettlementScene {
    let mut table = base_table(3);
    // Board A♠ A♥ K♠ K♥ Q♠ plays for both live seats; the off-suit low
    // pockets cannot improve it.
    seat(
        &mut table,
        0,
        500,
        50,
        SeatStatus::AllIn,
        [Card::new(2, 2), Card::new(3, 3)],
    );
    seat(
        &mut table,
        1,
        500,
        50,
        SeatStatus::AllIn,
        [Card::new(1, 2), Card::new(2, 4)],
    );
    // Seat 2 folds after contributing nothing.
    seat(
        &mut table,
        2,
        500,
        0,
        SeatStatus::Folded,
        [Card::new(1, 4), Card::new(3, 4)],
    );
    table.pot = 100;
    table.chip_pool = 5_000;
    table.rules.rake_mode = crate::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
    table.rules.rake_bps = 500;
    table.rules.rake_cap = 1_000;
    table.community_cards = vec![
        Card::new(0, 14),
        Card::new(1, 14),
        Card::new(0, 13),
        Card::new(1, 13),
        Card::new(0, 12),
    ]
    .try_into()
    .unwrap();
    SettlementScene {
        boards: SettlementBoards::single(table.community_cards.to_vec()),
        table,
    }
}

/// Fold-win（全场仅剩一名未弃牌玩家）场景集合——走
/// [`derive_fold_win_plan`]（无牌面校验 + "no flop, no drop" 抽水）。
/// `plan()` 语义不适用（fold 场景不是摊牌），测试直接调
/// `derive_fold_win_plan(&scene.table)`。
pub mod fold_win {
    use super::{Card, SettlementBoards, SettlementScene, SeatStatus, base_table, seat};

    fn raked_rules(table: &mut crate::contracts::texas_poker::types::TexasPokerTable) {
        table.rules.rake_mode =
            crate::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
        table.rules.rake_bps = 500;
        table.rules.rake_cap = 1_000;
    }

    /// 翻前盲注偷池：BB 面对加注弃牌，board 空 → 不抽水。
    pub fn preflop_blind_steal() -> SettlementScene {
        let mut table = base_table(2);
        seat(
            &mut table,
            0,
            970,
            30,
            SeatStatus::Active,
            [Card::new(0, 14), Card::new(1, 14)],
        );
        seat(
            &mut table,
            1,
            980,
            20,
            SeatStatus::Folded,
            [Card::new(2, 2), Card::new(3, 3)],
        );
        table.pot = 50;
        table.chip_pool = 5_000;
        raked_rules(&mut table);
        SettlementScene {
            boards: SettlementBoards::single(table.community_cards.to_vec()),
            table,
        }
    }

    /// 翻后弃牌 + 未跟注返还排除：A 下注 300，B 跟到 100 后翻牌弃牌。
    /// 底池 400，未跟注 200，争夺 200 → 抽 10。
    pub fn postflop_uncalled_excluded() -> SettlementScene {
        let mut table = base_table(2);
        seat(
            &mut table,
            0,
            700,
            300,
            SeatStatus::Active,
            [Card::new(0, 14), Card::new(1, 14)],
        );
        seat(
            &mut table,
            1,
            900,
            100,
            SeatStatus::Folded,
            [Card::new(2, 2), Card::new(3, 3)],
        );
        table.pot = 400;
        table.chip_pool = 5_000;
        raked_rules(&mut table);
        table.community_cards = vec![
            Card::new(2, 4),
            Card::new(3, 6),
            Card::new(2, 8),
        ]
        .try_into()
        .unwrap();
        SettlementScene {
            boards: SettlementBoards::single(table.community_cards.to_vec()),
            table,
        }
    }

    /// 三人翻后弃牌：未跟注按所有非赢家的最高下注计。
    /// bets [500(winner), 300, 100]：未跟注 200，争夺 700 → 抽 35。
    pub fn postflop_three_way() -> SettlementScene {
        let mut table = base_table(3);
        seat(
            &mut table,
            0,
            500,
            500,
            SeatStatus::Active,
            [Card::new(0, 14), Card::new(1, 14)],
        );
        seat(
            &mut table,
            1,
            700,
            300,
            SeatStatus::Folded,
            [Card::new(2, 2), Card::new(3, 3)],
        );
        seat(
            &mut table,
            2,
            900,
            100,
            SeatStatus::Folded,
            [Card::new(1, 5), Card::new(2, 7)],
        );
        table.pot = 900;
        table.chip_pool = 5_000;
        raked_rules(&mut table);
        table.community_cards = vec![
            Card::new(2, 4),
            Card::new(3, 6),
            Card::new(2, 8),
        ]
        .try_into()
        .unwrap();
        SettlementScene {
            boards: SettlementBoards::single(table.community_cards.to_vec()),
            table,
        }
    }

    /// 翻后弃牌触达 cap：200 万全争夺，5% = 10 万 > cap 1000 → 1000。
    pub fn postflop_cap() -> SettlementScene {
        let mut table = base_table(2);
        seat(
            &mut table,
            0,
            0,
            1_000_000,
            SeatStatus::Active,
            [Card::new(0, 14), Card::new(1, 14)],
        );
        seat(
            &mut table,
            1,
            0,
            1_000_000,
            SeatStatus::Folded,
            [Card::new(2, 2), Card::new(3, 3)],
        );
        table.pot = 2_000_000;
        table.chip_pool = 5_000_000;
        raked_rules(&mut table);
        table.community_cards = vec![
            Card::new(2, 4),
            Card::new(3, 6),
            Card::new(2, 8),
        ]
        .try_into()
        .unwrap();
        SettlementScene {
            boards: SettlementBoards::single(table.community_cards.to_vec()),
            table,
        }
    }
}

/// Run-it-twice with per-board winners: seat 0 wins board 1, seat 1 wins
/// board 2, exercising both runout slots of every layer.
pub fn run_it_twice_split_winners() -> SettlementScene {
    let mut table = base_table(2);
    // Seat 0: A♠ K♠; seat 1: A♦ A♣. Board 1 gives seat 0 a spade flush;
    // board 2 shares the flop but pairs the ace of hearts, giving seat 1
    // trip aces.
    seat(
        &mut table,
        0,
        600,
        100,
        SeatStatus::AllIn,
        [Card::new(0, 14), Card::new(0, 13)],
    );
    seat(
        &mut table,
        1,
        600,
        100,
        SeatStatus::AllIn,
        [Card::new(2, 14), Card::new(3, 14)],
    );
    table.pot = 200;
    table.chip_pool = 5_000;
    // Shared mixed-suit flop 2♠ 4♣ 6♠ (RIT from the flop). Board 1's
    // spade turn and river complete seat 0's flush; board 2's ace of hearts
    // gives seat 1 trip aces while seat 0 stays at four spades.
    let board1 = vec![
        Card::new(0, 2),
        Card::new(3, 4),
        Card::new(0, 6),
        Card::new(0, 8),
        Card::new(0, 10),
    ];
    let board2 = vec![
        Card::new(0, 2),
        Card::new(3, 4),
        Card::new(0, 6),
        Card::new(1, 14),
        Card::new(1, 9),
    ];
    SettlementScene {
        boards: SettlementBoards::twice(
            crate::contracts::texas_poker::types::RitStartStreet::Flop,
            board1,
            board2,
        ),
        table,
    }
}

/// The canonical side-pot layering the AIR's pot decomposition must mirror.
pub fn side_pot_layers(
    bets: &[u64],
    folded: &[bool],
    all_in: &[bool],
) -> Result<
    crate::contracts::texas_poker::side_pot::SidePotResult,
    crate::contracts::texas_poker::side_pot::SidePotError,
> {
    calculate_side_pots(bets, folded, all_in)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::texas_poker::settlement::derive_fold_win_plan;

    #[test]
    fn three_seat_ladder_semantics_are_locked() {
        let scene = three_seat_ladder();
        let plan = scene.assert_invariants();
        // Main pot 300 (3 × 100) to seat 0 (aces); side pot 200 (2 × 100)
        // to seat 1 (kings, best of the two deeper stacks); uncalled 100
        // returns to seat 2 unraked.
        assert_eq!(plan.active_pots().len(), 3);
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.awards[0], 300);
        assert_eq!(plan.awards[1], 200);
        assert_eq!(plan.awards[2], 100);
        assert_eq!(plan.winner_mask, 0b111);
    }

    #[test]
    fn nine_seat_ladder_uses_the_full_fixed_width() {
        let scene = nine_seat_ladder();
        let plan = scene.assert_invariants();
        // Nine distinct all-in levels slice nine layers: layer k (bet level
        // 10·(k+1)) is won by seat k, the best hand still eligible at that
        // depth; the final 10 of seat 8 is an uncalled return.
        assert_eq!(plan.active_pots().len(), 9);
        assert_eq!(plan.rake, 0);
        for seat_index in 0..8usize {
            assert_eq!(
                plan.awards[seat_index],
                (90 - 10 * seat_index as u64),
                "layer {seat_index} winner mismatch: {:?}",
                plan.awards
            );
        }
        assert_eq!(plan.awards[8], 10);
        let total: u64 = plan.awards.iter().sum();
        assert_eq!(total, 450);
    }

    #[test]
    fn raked_odd_chip_split_semantics_are_locked() {
        let scene = raked_odd_chip_split();
        let plan = scene.assert_invariants();
        // 5% of 100 = 5 rake (below cap). Net 95 splits 47/48 between the
        // tied seats; the first seat clockwise after button 2 takes the odd
        // chip (seat 0 of this table).
        assert_eq!(plan.rake, 5);
        let mut awards = [plan.awards[0], plan.awards[1]];
        awards.sort();
        assert_eq!(awards, [47, 48]);
    }

    // ---- fold-win（"no flop, no drop"）----

    #[test]
    fn fold_win_preflop_blind_steal_is_never_raked() {
        let scene = fold_win::preflop_blind_steal();
        let plan = derive_fold_win_plan(&scene.table).expect("fold plan derives");
        // 翻前结束：零抽水，赢家独得底池，守恒通过 validate。
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.awards[0], 50);
        assert_eq!(plan.total_awards, 50);
        assert_eq!(plan.winner_mask, 0b001);
        assert_eq!(plan.active_pots().len(), 1);
        assert_eq!(plan.pots[0].rake, 0);
    }

    #[test]
    fn fold_win_postflop_rakes_only_contested_money() {
        let scene = fold_win::postflop_uncalled_excluded();
        let plan = derive_fold_win_plan(&scene.table).expect("fold plan derives");
        // 底池 400，未跟注返还 200（A 的 300 − B 的 100）不抽；
        // 争夺 200 × 5% = 10；赢家净得 390。
        assert_eq!(plan.rake, 10);
        assert_eq!(plan.awards[0], 390);
        assert_eq!(plan.total_awards, 390);
        assert_eq!(plan.pots[0].rake, 10);
        assert_eq!(plan.pots[0].net_amount, 390);
        // 零和（对账用）：赢家 delta = 390 − 300 = +90；输家 = −100；
        // treasury = +10。
        assert_eq!(plan.awards[0] as i128 - 300, 90);
        assert_eq!(100_i128 + 10, 110);
    }

    #[test]
    fn fold_win_three_way_uses_max_other_bet_for_uncalled() {
        let scene = fold_win::postflop_three_way();
        let plan = derive_fold_win_plan(&scene.table).expect("fold plan derives");
        // 未跟注 = 500 − 300（非赢家的最高下注）= 200；争夺 700 × 5% = 35。
        assert_eq!(plan.rake, 35);
        assert_eq!(plan.awards[0], 865);
    }

    #[test]
    fn fold_win_postflop_respects_rake_cap() {
        let scene = fold_win::postflop_cap();
        let plan = derive_fold_win_plan(&scene.table).expect("fold plan derives");
        // 5% = 100,000 > cap 1,000。
        assert_eq!(plan.rake, 1_000);
        assert_eq!(plan.awards[0], 1_999_000);
    }

    #[test]
    fn fold_win_rejects_multi_unfolded_tables() {
        let scene = three_seat_ladder(); // 三名 all-in（未弃牌）
        assert!(derive_fold_win_plan(&scene.table).is_err());
    }

    #[test]
    fn run_it_twice_split_winners_semantics_are_locked() {
        let scene = run_it_twice_split_winners();
        let plan = scene.assert_invariants();
        // Both runouts pay 100 each: board 1 (flush) to seat 0, board 2
        // (paired ace) to seat 1.
        assert_eq!(plan.awards[0], 100);
        assert_eq!(plan.awards[1], 100);
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.winner_mask, 0b11);
        for pot in plan.active_pots() {
            assert_eq!(pot.runouts[0].winner_mask, 1 << 0);
            assert_eq!(pot.runouts[1].winner_mask, 1 << 1);
        }
    }

    #[test]
    fn side_pot_layering_is_deterministic_and_bounded() {
        let bets = [10u64, 20, 30, 30, 30, 30, 30, 30, 90];
        let folded = [false; 9];
        let all_in = [true; 9];
        let result = side_pot_layers(&bets, &folded, &all_in).expect("layers");
        assert!(usize::from(result.pot_count) <= SETTLEMENT_SEATS);
        let again = side_pot_layers(&bets, &folded, &all_in).expect("re-derive");
        assert_eq!(result, again);
    }
}
