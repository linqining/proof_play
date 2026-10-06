//! Stage 0 规则基线测试（控制逻辑入 AIR 重构前的行为钉板）。
//!
//! 覆盖重构必须保持（或有意改变并同步改断言）的纯规则语义：
//! - 下注合法性矩阵（validate_check/call/raise、min-raise、短 all-in）
//! - fail-closed：无实时镜像时下注动作（含 all-in）一律拒绝、零改写
//! - `is_betting_round_complete`（BB option、all-in 排除、fold 不提前完成）
//! - `check_betting_timeout`（计时窗口 / 不可行动座位跳过；超时 fold 的
//!   VM 路径在 allin_e2e 覆盖）
//! - `advance_to_next_phase` 街道阶梯 + `set_blinds` 单挑/全员盲注 all-in
//! - reveal 级联（on_reveal_complete / on_reveal_timeout / 良性错误分类）
//! - 座位管理（kick 保留 total_bet、局中断线不 sitting_out、重连、rebuy）
//! - fold-win 派奖与无 reveal 卡片的平分池（odd-chip）
//!
//! 纯表状态（无实时镜像）——单一状态重构后镜像路径外的唯一残留是这些
//! 语义钉板与展示层派生。

use super::*;
use crate::pokergame::betting::BettingRound;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use crate::pokergame::seat::Seat;

/// limit = 10000 → min_bet = 50，盲注 50/100。
fn make_table(table_id: u32) -> Table {
    Table::new(table_id, "rules".to_string(), 10000, 9, String::new())
}

/// 入座一个假玩家（无 mental-poker 注册），清 folded 使其参与。
fn seat_fake(table: &mut Table, seat_id: u32, stack: u64) -> GamePkHex {
    let pk = GamePkHex::new(format!("pk-rules-{seat_id}"));
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

/// 纯记账座位（BettingRound::validate_* 只读 stack/bet）。
fn plain_seat(id: u32, stack: u64, bet: u64) -> Seat {
    let mut s = Seat::new(id, None, 0, stack);
    s.folded = false;
    s.bet = bet;
    s
}

// ============================================================
// 下注合法性（BettingRound::validate_* / update_after_raise）
// ============================================================
mod betting_validation {
    use super::*;

    #[test]
    fn check_requires_no_chips_owed() {
        let br = BettingRound::new_preflop(100);
        // 已跟平（bet == current_bet）→ check 合法。
        assert!(br.validate_check(&plain_seat(1, 900, 100)).is_ok());
        // 还欠 50 → 必须跟注或弃牌，不得 check。
        assert!(br.validate_check(&plain_seat(1, 900, 50)).is_err());
        // current_bet 0（翻牌后新轮）→ 任何人可 check。
        let postflop = BettingRound::new(100);
        assert!(postflop.validate_check(&plain_seat(1, 900, 0)).is_ok());
    }

    #[test]
    fn call_requires_chips_owed() {
        let br = BettingRound::new_preflop(100);
        assert!(br.validate_call(&plain_seat(1, 900, 50)).is_ok());
        // 无欠款时 call 是非法输入（应走 check）。
        assert!(br.validate_call(&plain_seat(1, 900, 100)).is_err());
    }

    #[test]
    fn raise_enforces_min_raise_and_chips() {
        let br = BettingRound::new_preflop(100); // current_bet=100, min_raise=100
        let seat = plain_seat(1, 1000, 0);
        // 非全下加注低于 min_raise → 拒。
        assert!(br.validate_raise(&seat, 50).is_err());
        // 正常足额加注 → 过。
        assert!(br.validate_raise(&seat, 100).is_ok());
        // 筹码不足（needed > stack）→ 拒。
        let short = plain_seat(1, 120, 0);
        assert!(br.validate_raise(&short, 100).is_err());
    }

    #[test]
    fn short_all_in_below_min_raise_is_legal() {
        // 短 all-in 形状：current 100，座位置 40，补齐 60 恰好清空筹码。
        // TDA：all-in 不受 min_raise 约束（但也不重开行动权）。
        let br = BettingRound::new_preflop(100);
        let allin = plain_seat(1, 60, 40);
        assert!(br.validate_raise(&allin, 0).is_ok());
    }

    #[test]
    fn update_after_raise_reopens_only_on_full_raise() {
        let mut br = BettingRound::new_preflop(100);
        // 短 all-in（增量 40 < min_raise 100）：min_raise 不更新（不重开）。
        br.update_after_raise(140, 1, true);
        assert_eq!(br.current_bet(), 140);
        assert_eq!(br.min_raise(), 100, "short all-in must not reopen action");
        // 足额 all-in（增量 200 ≥ 100）：重开行动权。
        br.update_after_raise(340, 2, true);
        assert_eq!(br.min_raise(), 200);
        // 普通加注：始终更新。
        br.update_after_raise(500, 1, false);
        assert_eq!(br.current_bet(), 500);
        assert_eq!(br.min_raise(), 160);
    }
}

// ============================================================
// handle_allin / 下注动作 fail-closed（单一状态重构后）
// ============================================================
mod handle_allin_paths {
    use super::*;

    /// fail-closed 钉板：无实时镜像（不可证明手）时一切下注动作（含
    /// all-in）被直接拒绝、状态零改写——本地规则兜底路径已删除，规则
    /// 引擎只保留 VM 一份。金额算术（all-in 两分支的 target/封顶）由
    /// betting_validation 矩阵 + allin_e2e（真实 VM 路径）覆盖。
    #[test]
    fn betting_actions_rejected_without_live_mirror() {
        let mut t = make_table(30_101);
        let p1 = seat_fake(&mut t, 1, 550);
        let p2 = seat_fake(&mut t, 2, 500);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 50;
            s.total_bet = 50;
        }
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.bet = 100;
            s.total_bet = 100;
        }
        t.set_pot(150);
        t.betting_round = Some(BettingRound::new_preflop(100));
        t.summary.call_amount = Some(100);

        assert!(t.handle_allin(&p1).is_none(), "all-in rejected (fail-closed)");
        assert!(t.handle_raise(&p1, 600).is_none());
        assert!(t.handle_call(&p2).is_none());
        assert!(t.handle_check(&p2).is_none());
        assert!(t.handle_fold(&p1).is_none());
        // 状态零改写。
        assert_eq!(t.pot(), 150);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 550);
        assert_eq!(t.local_seats.get(&1).unwrap().bet, 50);
        assert!(!t.local_seats.get(&1).unwrap().folded);
    }
}

// ============================================================
// is_betting_round_complete
// ============================================================
mod betting_round_completion {
    use super::*;

    fn completion_table(table_id: u32, seats: &[(u32, u64, u64, bool, bool)]) -> Table {
        // (seat_id, stack, bet, folded, has_acted)
        let mut t = make_table(table_id);
        for &(id, stack, bet, folded, acted) in seats {
            let pk = seat_fake(&mut t, id, stack.max(bet));
            let _ = pk;
            if let Some(s) = t.local_seats.get_mut(&id) {
                s.stack = stack;
                s.bet = bet;
                s.total_bet = bet;
                s.folded = folded;
                s.has_acted = acted;
            }
        }
        t.betting_round = Some(BettingRound::new_preflop(100));
        t
    }

    /// BB 的 option 不得被跳过：盲注不算行动，BB 未行动则轮次未完成。
    #[test]
    fn bb_option_not_skipped() {
        // p1=SB 置 50 未行动；p2=BB 置 100 未行动（盲注）。
        let mut t = completion_table(30_201, &[(1, 900, 50, false, false), (2, 900, 100, false, false)]);
        assert!(!t.is_betting_round_complete(), "SB owes + nobody acted");
        // SB 跟平到 100：BB option 仍未行动 → 未完成。
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 100;
            s.has_acted = true;
        }
        assert!(!t.is_betting_round_complete(), "BB option must not be skipped");
        // BB check（行动）→ 完成。
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.has_acted = true;
        }
        assert!(t.is_betting_round_complete());
    }

    /// 弃牌不得令轮次提前完成：仍有未行动者欠注 → 未完成。
    #[test]
    fn fold_does_not_prematurely_complete() {
        // p1 加注到 200 已行动；p2 弃牌；p3 未行动且欠 100。
        let mut t = completion_table(
            30_202,
            &[(1, 800, 200, false, true), (2, 900, 100, true, true), (3, 900, 100, false, false)],
        );
        if let Some(ref mut b) = t.betting_round {
            b.update_after_raise(200, 1, false);
        }
        assert!(!t.is_betting_round_complete(), "p3 still owes and has not acted");
        // p3 跟平 → 完成。
        if let Some(s) = t.local_seats.get_mut(&3) {
            s.bet = 200;
            s.has_acted = true;
        }
        assert!(t.is_betting_round_complete());
    }

    /// all-in 座位（stack 0）不计入"须行动"集合。
    #[test]
    fn all_in_seat_excluded_from_completion() {
        // p1 已 all-in 置 150（未行动）；p2 跟平 150 已行动。
        let t = completion_table(30_203, &[(1, 0, 150, false, false), (2, 500, 150, false, true)]);
        assert!(t.is_betting_round_complete(), "all-in seat cannot act");
    }

    #[test]
    fn everyone_gone_completes() {
        // 全员弃牌/all-in → active 集合空 → 完成。
        let t = completion_table(30_204, &[(1, 0, 150, false, true), (2, 900, 100, true, true)]);
        assert!(t.is_betting_round_complete());
    }
}

// ============================================================
// check_betting_timeout
// ============================================================
mod betting_timeout {
    use super::*;

    fn timeout_table(table_id: u32) -> (Table, GamePkHex) {
        let mut t = make_table(table_id);
        let p1 = seat_fake(&mut t, 1, 900);
        seat_fake(&mut t, 2, 900);
        t.betting_round = Some(BettingRound::new_preflop(100));
        t.summary.call_amount = Some(100);
        t.set_turn(Some(1));
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.turn = true;
            s.bet = 50;
        }
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.bet = 100;
        }
        // 计时起点拨回 60s 前 → 已超时（timeout 30s）。
        t.set_betting_started_at(now_ms().saturating_sub(60_000));
        (t, p1)
    }

    /// 超时 fold 走 VM 权威路径（allin_e2e::betting_timeout_folds_via_vm
    /// 覆盖）；纯表层只钉计时窗口与跳过语义。
    #[test]
    fn within_timeout_is_noop() {
        let (mut t, _) = timeout_table(30_302);
        t.set_betting_started_at(now_ms());
        assert!(t.check_betting_timeout(30).is_none());
        assert!(!t.local_seats.get(&1).unwrap().folded);
    }

    /// 轮到不可行动座位（all-in）→ 跳过并重置计时，不 fold。
    #[test]
    fn unactionable_turn_holder_is_skipped() {
        let (mut t, _) = timeout_table(30_303);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.stack = 0;
        }
        assert!(t.check_betting_timeout(30).is_none(), "skip is not an action");
        assert_eq!(t.turn(), Some(2), "turn moves to the next actionable seat");
        assert!(!t.local_seats.get(&1).unwrap().folded, "no fold on skip");
        assert!(
            t.betting_started_at() > now_ms().saturating_sub(5_000),
            "timer re-armed"
        );
    }
}

// ============================================================
// advance_to_next_phase 街道阶梯 + set_blinds 定位
// ============================================================
mod phase_ladder {
    use super::*;

    fn two_player_table(table_id: u32) -> Table {
        let mut t = make_table(table_id);
        seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        t
    }

    /// PreFlop → Flop → Turn → River → Showdown 全阶梯：每街发对牌数、
    /// 开 CommunityReveal 窗口；终街开 ShowdownReveal。
    #[test]
    fn street_ladder_deals_and_opens_reveal_windows() {
        let mut t = two_player_table(30_401);
        t.transition_to(RoundState::PreFlop);

        let ladder = [
            (RoundState::Flop, 3usize, RevealPhase::CommunityReveal),
            (RoundState::Turn, 4, RevealPhase::CommunityReveal),
            (RoundState::River, 5, RevealPhase::CommunityReveal),
            (RoundState::Showdown, 5, RevealPhase::ShowdownReveal),
        ];
        for (want_state, want_cards, want_phase) in ladder {
            t.advance_to_next_phase();
            assert_eq!(t.round_state(), want_state);
            assert_eq!(
                t.mental_poker_game.community_cards_encrypted.len(),
                want_cards,
                "community card count at {want_state:?}"
            );
            assert!(t.reveal_token_state.is_active(), "window open at {want_state:?}");
            assert_eq!(t.reveal_token_state.phase, want_phase);
            // 关窗（pending 空 → 完成；无 reveal 卡片 → F5 平分路径收尾）。
            t.on_reveal_complete();
            assert!(!t.reveal_token_state.is_active());
        }
        assert!(t.summary.went_to_showdown, "showdown awarding ran");
    }

    /// Waiting 状态下推进是空操作（warn 分支），不发牌不开窗。
    #[test]
    fn advance_from_waiting_is_inert() {
        let mut t = two_player_table(30_402);
        t.advance_to_next_phase();
        assert_eq!(t.round_state(), RoundState::Waiting);
        assert!(t.mental_poker_game.community_cards_encrypted.is_empty());
        assert!(!t.reveal_token_state.is_active());
    }

    /// 单挑盲注定位：BB=2、SB=1（另一参与者）、UTG=SB 先行动。
    #[test]
    fn set_blinds_heads_up_positions() {
        let mut t = two_player_table(30_403);
        t.set_button(Some(1));
        t.set_last_bb_seat(None);
        t.set_blinds();
        assert_eq!(t.big_blind(), Some(2));
        assert_eq!(t.small_blind(), Some(1));
        assert_eq!(t.last_bb_seat(), 2, "BB track advances");
        assert_eq!(t.pot(), 150, "50 + 100 blinds");
        assert_eq!(t.summary.call_amount, Some(100));
        assert_eq!(t.min_raise(), 100);
        assert_eq!(t.turn(), Some(1), "HU preflop: SB acts first");
    }

    /// 全员盲注 all-in（各持恰好盲注额）：无可行动玩家 → 不设 turn（C5）。
    #[test]
    fn set_blinds_all_blind_all_in_leaves_no_turn() {
        let mut t = make_table(30_404);
        seat_fake(&mut t, 1, 50);
        seat_fake(&mut t, 2, 100);
        t.set_button(Some(1));
        t.set_last_bb_seat(None);
        t.set_blinds();
        assert_eq!(t.pot(), 150, "both blinds posted in full");
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 0);
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 0);
        assert_eq!(t.turn(), None, "no actionable player → no turn");
    }
}

// ============================================================
// reveal 级联（on_reveal_complete / on_reveal_timeout）
// ============================================================
mod reveal_cascade {
    use super::*;

    /// 构造激活的 reveal 窗口（phase + pending 由用例指定）。
    fn active_reveal(t: &mut Table, phase: RevealPhase, pending: Vec<GamePkHex>) {
        t.reveal_token_state.phase = phase;
        t.reveal_token_state.pending_players = pending;
    }

    /// HandReveal 完成 → post_blinds + 翻前下注轮（对齐 Move
    /// check_reveal_phase_complete 的完成分支）。
    #[test]
    fn hand_reveal_completion_posts_blinds_and_starts_betting() {
        let mut t = make_table(30_501);
        seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        t.transition_to(RoundState::PreFlop);
        active_reveal(&mut t, RevealPhase::HandReveal, vec![]);

        t.on_reveal_complete();
        assert!(!t.reveal_token_state.is_active(), "window consumed");
        assert_eq!(t.pot(), 150, "blinds posted");
        assert!(t.betting_round.is_some(), "preflop betting started");
        assert_eq!(t.summary.call_amount, Some(100));
        assert_eq!(t.turn(), Some(1), "HU UTG = SB");
    }

    /// 未完成（仍有 pending）时 on_reveal_complete 是空操作。
    #[test]
    fn reveal_complete_requires_empty_pending() {
        let mut t = make_table(30_502);
        let p1 = seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        t.transition_to(RoundState::PreFlop);
        active_reveal(&mut t, RevealPhase::HandReveal, vec![p1]);
        t.on_reveal_complete();
        assert!(t.reveal_token_state.is_active(), "still pending → not consumed");
        assert_eq!(t.pot(), 0, "no blinds while pending");
    }

    /// 翻前 reveal 超时：踢出超时者 → 剩余 ≥2 → 退款重开整手。
    #[test]
    fn preflop_timeout_kicks_pending_and_restarts_hand() {
        let mut t = make_table(30_503);
        let p1 = seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        seat_fake(&mut t, 3, 1000);
        t.transition_to(RoundState::PreFlop);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 50;
            s.total_bet = 50;
        }
        t.set_pot(50);
        active_reveal(&mut t, RevealPhase::HandReveal, vec![p1.clone()]);

        t.on_reveal_timeout();
        // 踢出 + 重开整手：被踢者（stack 0）在 reset_for_next_hand 中离座。
        assert!(!t.pk_to_seat.contains_key(&p1), "pending timeout → kicked (pk unbound)");
        assert!(!t.local_seats.contains_key(&1), "broke kicked seat removed on restart");
        assert!(t.local_seats.contains_key(&2) && t.local_seats.contains_key(&3));
        assert_eq!(t.round_state(), RoundState::Waiting, "hand restarted");
        assert!(!t.reveal_token_state.is_active());
        assert_eq!(t.pot(), 0, "bets refunded on restart");
    }

    /// 双人桌一人超时：踢出后活跃不足 → 直接重置（Waiting 早退分支）。
    #[test]
    fn two_player_timeout_kicks_and_resets() {
        let mut t = make_table(30_504);
        let p1 = seat_fake(&mut t, 1, 1000);
        seat_fake(&mut t, 2, 1000);
        t.transition_to(RoundState::PreFlop);
        active_reveal(&mut t, RevealPhase::HandReveal, vec![p1.clone()]);
        t.on_reveal_timeout();
        assert_eq!(t.round_state(), RoundState::Waiting);
        assert!(!t.pk_to_seat.contains_key(&p1), "kicked before the reset");
    }

    /// 良性错误分类：幂等重放静默，真正的非法提交不静默。
    #[test]
    fn benign_error_classification() {
        assert!(Table::is_benign_reveal_error(Table::ERR_ALREADY_SUBMITTED));
        assert!(Table::is_benign_reveal_error("Reveal token phase not active"));
        assert!(!Table::is_benign_reveal_error("Invalid token in HandReveal phase"));
        assert!(!Table::is_benign_reveal_error("reveal rejected by VM: bad proof"));
    }

    /// 重复/迟到提交的错误形状：不在 pending → ALREADY_SUBMITTED；
    /// 窗口未开 → phase not active。
    #[test]
    fn out_of_window_submission_errors() {
        let mut t = make_table(30_505);
        let p1 = seat_fake(&mut t, 1, 1000);
        let p2 = seat_fake(&mut t, 2, 1000);
        active_reveal(&mut t, RevealPhase::HandReveal, vec![p2]);
        let err = t
            .submit_player_reveal_tokens(&p1, vec![])
            .expect_err("non-pending submit must fail");
        assert!(err.contains(Table::ERR_ALREADY_SUBMITTED), "{err}");

        t.reveal_token_state.reset();
        let err = t
            .submit_player_reveal_tokens(&p1, vec![])
            .expect_err("inactive phase must fail");
        assert!(err.contains("phase not active"), "{err}");
    }
}

// ============================================================
// 座位管理（kick / 断线 / 重连 / rebuy）
// ============================================================
mod seat_management {
    use super::*;

    fn three_player_preflop(table_id: u32) -> (Table, GamePkHex, GamePkHex, GamePkHex) {
        let mut t = make_table(table_id);
        let p1 = seat_fake(&mut t, 1, 900);
        let p2 = seat_fake(&mut t, 2, 900);
        let p3 = seat_fake(&mut t, 3, 900);
        t.transition_to(RoundState::PreFlop);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.bet = 100;
            s.total_bet = 100;
        }
        t.set_pot(100);
        (t, p1, p2, p3)
    }

    /// 手牌进行中踢出：stack 清零、座位保留、total_bet 保住供边池计算。
    #[test]
    fn kick_mid_hand_preserves_total_bet_for_side_pots() {
        let (mut t, p1, _, _) = three_player_preflop(30_601);
        t.kick_player_internal(&p1);
        let s = t.local_seats.get(&1).unwrap();
        assert!(s.left_during_hand, "seat marked left-during-hand");
        assert!(s.folded, "kicked seat cannot win");
        assert_eq!(s.stack, 0);
        assert_eq!(s.total_bet, 100, "contribution preserved for side pots");
        assert!(!t.pk_to_seat.contains_key(&p1), "pk unbound");
        // 剩余 2 人 → 手牌继续（不重置）。
        assert_eq!(t.round_state(), RoundState::PreFlop);
    }

    /// 局中断线只记 disconnected，不 sitting_out（2026-09-08 回归：
    /// 局中置 sitting_out 会让手牌被 tick 直接重置）。
    #[test]
    fn mid_hand_disconnect_keeps_seat_in_play() {
        let (mut t, p1, _, _) = three_player_preflop(30_602);
        t.mark_player_disconnected_mid_hand(&p1);
        let s = t.local_seats.get(&1).unwrap();
        assert!(s.disconnected);
        assert!(!s.sitting_out, "mid-hand disconnect must NOT sit out");
        assert_eq!(t.unfolded_players().len(), 3, "still in the hand");
    }

    /// 大厅断线（非局中）：sitting_out；代打弃牌走 VM 权威路径——无镜像
    /// 时不本地 fold（fail-closed，单一状态重构后语义）。
    #[test]
    fn lobby_disconnect_sits_out_without_local_fold() {
        let (mut t, p1, _, _) = three_player_preflop(30_603);
        t.betting_round = Some(BettingRound::new_preflop(100));
        t.set_turn(Some(1));
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.turn = true;
        }
        let r = t.mark_player_disconnected(&p1);
        assert!(r.is_none(), "no local auto-fold without a live VM mirror");
        let s = t.local_seats.get(&1).unwrap();
        assert!(s.disconnected && s.sitting_out);
        assert!(!s.folded, "fold decision belongs to the VM (timeout path)");
    }

    #[test]
    fn reconnect_restores_seat() {
        let (mut t, p1, _, _) = three_player_preflop(30_604);
        t.mark_player_disconnected_mid_hand(&p1);
        assert!(t.reconnect_player(&format!("0x{:064x}", 1u64)));
        let s = t.local_seats.get(&1).unwrap();
        assert!(!s.disconnected && !s.sitting_out);
        assert!(!t.reconnect_player("0xdead"));
    }

    #[test]
    fn rebuy_adds_chips() {
        let (mut t, _, _, _) = three_player_preflop(30_605);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.stack = 0;
        }
        t.rebuy_player(1, 1000);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1000);
    }
}

// ============================================================
// fold-win 派奖 + 平分池
// ============================================================
mod fold_win_and_splits {
    use super::*;

    /// 翻前弃牌终结：唯一幸存者赢全池，翻前不抽水。
    #[test]
    fn end_without_showdown_awards_sole_survivor_unraked() {
        let mut t = make_table(30_701);
        seat_fake(&mut t, 1, 900);
        seat_fake(&mut t, 2, 900);
        t.transition_to(RoundState::PreFlop);
        if let Some(s) = t.local_seats.get_mut(&1) {
            s.folded = true;
            s.bet = 50;
            s.total_bet = 50;
        }
        if let Some(s) = t.local_seats.get_mut(&2) {
            s.bet = 100;
            s.total_bet = 100;
        }
        t.set_pot(150);
        t.end_without_showdown();
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 900 + 150, "winner takes the pot");
        assert_eq!(t.summary.rake_collected, 0, "no flop, no drop");
        assert!(t.summary.hand_over);
        assert_eq!(t.round_state(), RoundState::Waiting);
        assert!(!t.summary.win_messages.is_empty());
    }

    /// 无 reveal 卡片时的平分（F5 路径）：odd chip 给序号靠前的赢家。
    #[test]
    fn odd_chip_split_without_revealed_cards() {
        let mut t = make_table(30_702);
        for id in 1..=3 {
            seat_fake(&mut t, id, 1000);
        }
        t.set_pot(101);
        t.determine_winner_by_ids(101, &[1, 2]);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1000 + 51, "first seat takes the odd chip");
        assert_eq!(t.local_seats.get(&2).unwrap().stack, 1000 + 50);
        assert_eq!(t.local_seats.get(&3).unwrap().stack, 1000, "not eligible");
    }

    #[test]
    fn single_eligible_winner_takes_all_without_evaluation() {
        let mut t = make_table(30_703);
        for id in 1..=3 {
            seat_fake(&mut t, id, 1000);
        }
        t.set_pot(200);
        t.determine_winner_by_ids(200, &[3]);
        assert_eq!(t.local_seats.get(&3).unwrap().stack, 1200);
        assert_eq!(t.local_seats.get(&1).unwrap().stack, 1000);
    }
}
