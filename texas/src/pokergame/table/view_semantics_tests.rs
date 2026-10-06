//! Stage 0 视图派生语义钉板（apply_betting_view / refresh_from_vm）。
//!
//! 这些测试钉住「VM 视图 → 游戏层账本」的派生规则——正是 mirror 双状态
//! 模式的同步缝隙（失步死锁族 bug 的所在地）。Stage 1 把散落的
//! apply_betting_view / sync_rejected_view 收敛为单一 `refresh_from_vm()`
//! 入口后，这些断言在派生规则上逐条保持：
//! - 在注：座位四元组（bet/total_bet/stack/has_acted）+ pot = pot+street_bets
//!   + betting_round/current_bet/min_raise/call_amount + turn 派生；
//! - hand_over：跳过 stack 同步（游戏层派奖是记账权威）、pot 取
//!   fold_win_pot、不开下注轮、不触发街道仪式；
//! - 离开下注相位且未终局：触发 advance_to_next_phase（相位联锁——
//!   2026-09-13 失步死锁的修复语义，Stage 1 事件驱动化的行为基线）；
//! - 无镜像时 refresh_from_vm 为空操作。

use super::*;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use crate::starknet::vm_session::{BettingView, BettingViewSeat};

fn make_table(table_id: u32) -> Table {
    Table::new(table_id, "view-semantics".to_string(), 10000, 9, String::new())
}

fn seat_fake(table: &mut Table, seat_id: u32, stack: u64) -> GamePkHex {
    let pk = GamePkHex::new(format!("pk-view-{seat_id}"));
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

fn view_seat(pk: &str, bet: u64, total_bet: u64, stack: u64, has_acted: bool) -> BettingViewSeat {
    BettingViewSeat {
        pk_hex: pk.to_string(),
        folded: false,
        bet,
        total_bet,
        stack,
        has_acted,
    }
}

/// 在注视图：账本、底池、轮转全部按 VM 派生；不触发街道仪式。
#[test]
fn in_betting_view_derives_ledger_pot_and_turn() {
    let mut t = make_table(40_101);
    let p1 = seat_fake(&mut t, 1, 950);
    let p2 = seat_fake(&mut t, 2, 800);
    t.transition_to(RoundState::PreFlop);

    let view = BettingView {
        seats: vec![
            view_seat(&p1.0, 50, 50, 950, false),
            view_seat(&p2.0, 200, 200, 800, true),
        ],
        pot: 100,          // VM 已收集部分
        street_bets: 250,  // 本街在途
        current_turn_pk: Some(p2.0.clone()),
        current_bet: Some(150),
        min_raise: Some(100),
        in_betting: true,
        hand_over: false,
        fold_win_pot: None,
    };
    t.apply_betting_view(&view);

    let s1 = t.local_seats.get(&1).unwrap();
    assert_eq!((s1.bet, s1.total_bet, s1.stack, s1.has_acted), (50, 50, 950, false));
    let s2 = t.local_seats.get(&2).unwrap();
    assert_eq!((s2.bet, s2.total_bet, s2.stack, s2.has_acted), (200, 200, 800, true));
    assert_eq!(t.pot(), 350, "derived pot = vm pot + street bets");
    let betting = t.betting_round.as_ref().expect("betting round derived");
    assert_eq!((betting.current_bet(), betting.min_raise()), (150, 100));
    assert_eq!(t.summary.call_amount, Some(150));
    assert_eq!(t.turn(), Some(2), "turn derived from VM current actor");
    assert!(!s1.turn && s2.turn);
    assert_eq!(t.round_state(), RoundState::PreFlop, "no ceremony advance while betting");
}

/// hand_over：stack 不同步（游戏层派奖权威）、pot 取终局前底池、无下注轮。
#[test]
fn hand_over_view_keeps_stacks_and_uses_fold_win_pot() {
    let mut t = make_table(40_102);
    seat_fake(&mut t, 1, 900);
    seat_fake(&mut t, 2, 950);
    t.transition_to(RoundState::PreFlop);
    // 预置游戏层终局 stack（派奖结果）；VM 侧座位 stack 已被清零——
    // 视图不得把 0 覆盖进来。
    let view = BettingView {
        seats: vec![
            view_seat("pk-view-1", 0, 150, 0, true),
            view_seat("pk-view-2", 0, 150, 0, true),
        ],
        pot: 0,
        street_bets: 0,
        current_turn_pk: None,
        current_bet: None,
        min_raise: None,
        in_betting: false,
        hand_over: true,
        fold_win_pot: Some(300),
    };
    t.apply_betting_view(&view);
    assert_eq!(t.local_seats.get(&1).unwrap().stack, 900, "stack sync skipped on hand_over");
    assert_eq!(t.local_seats.get(&2).unwrap().stack, 950);
    assert_eq!(t.pot(), 300, "fold-win pot is the payout base");
    assert!(t.betting_round.is_none());
    assert_eq!(t.summary.call_amount, None);
    assert_eq!(t.turn(), None);
    assert_eq!(t.round_state(), RoundState::PreFlop, "hand_over does not advance streets");
}

/// 相位联锁（失步死锁修复的语义钉板）：VM 在 dispatch 内离开下注相位
/// （normalize 收注 + 推街）而手牌未终局 → 游戏层必须立即执行自己的
/// 发牌仪式（发下一街 + 开 reveal 窗口），否则 VM 在窗口等 token、
/// 游戏层永远不发牌。
#[test]
fn leaving_betting_triggers_street_ceremony() {
    let mut t = make_table(40_103);
    seat_fake(&mut t, 1, 900);
    seat_fake(&mut t, 2, 900);
    t.transition_to(RoundState::PreFlop);

    let view = BettingView {
        seats: vec![
            view_seat("pk-view-1", 0, 150, 900, true),
            view_seat("pk-view-2", 0, 150, 900, true),
        ],
        pot: 300,
        street_bets: 0,
        current_turn_pk: None,
        current_bet: None,
        min_raise: None,
        in_betting: false,
        hand_over: false,
        fold_win_pot: None,
    };
    t.apply_betting_view(&view);
    assert_eq!(t.round_state(), RoundState::Flop, "street ceremony ran");
    assert_eq!(t.mental_poker_game.community_cards_encrypted.len(), 3);
    assert!(t.reveal_token_state.is_active());
    assert_eq!(t.reveal_token_state.phase, RevealPhase::CommunityReveal);
    assert!(t.betting_round.is_none(), "left betting → no stale round");
}

/// 无镜像时 refresh_from_vm 是空操作（fail-closed：无镜像的手不存在
/// 下注动作，同步入口无副作用）。
#[test]
fn refresh_from_vm_without_mirror_is_inert() {
    let mut t = make_table(40_104);
    seat_fake(&mut t, 1, 900);
    t.transition_to(RoundState::PreFlop);
    t.set_pot(123);
    t.refresh_from_vm();
    assert_eq!(t.round_state(), RoundState::PreFlop);
    assert_eq!(t.pot(), 123);
}
