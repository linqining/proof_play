use super::*;
use crate::pokergame::hand_rank::{vin_card_to_eval_card, EvalCard, HandRank};
use crate::pokergame::evaluator::best_hand;

impl Table {
    /// 对齐 Move side_pot::calculate_side_pots：使用 total_bet（累积下注）计算边池。
    /// 仅在 showdown 时调用一次（由 on_reveal_complete(ShowdownReveal) 触发）。
    /// self.pot 保持不变（已包含所有下注），self.side_pots 填充边池列表，
    /// main_pot() = pot - sum(side_pots) 即主池金额。
    pub fn calculate_side_pots(&mut self) {
        // 清空旧 side_pots（对齐 Move: 每次重新计算）
        self.summary.side_pots.clear();

        // 收集所有有下注的玩家 (seat_id, total_bet, folded, all_in)
        // all_in = stack == 0 && total_bet > 0（对齐 Move: stack 耗尽即 all-in）
        let player_bets: Vec<(u32, u64, bool, bool)> = self.seats().values()
            .filter(|s| s.total_bet > 0)
            .map(|s| (s.id, s.total_bet, s.folded, s.stack == 0))
            .collect();

        if player_bets.is_empty() {
            return;
        }

        // 收集所有 all-in 的下注额（去重），对齐 Move collect_all_in_bets
        let mut all_in_bets: Vec<u64> = player_bets.iter()
            .filter(|(_, _, _, all_in)| *all_in)
            .map(|(_, bet, _, _)| *bet)
            .collect();
        all_in_bets.sort_unstable();
        all_in_bets.dedup();

        // 没有 all-in 玩家 → 无边池，全部归主池
        if all_in_bets.is_empty() {
            return;
        }

        // 按层级计算边池，对齐 Move calculate_side_pots
        let n = player_bets.len();
        let mut prev_level: u64 = 0;
        let mut side_pots: Vec<SidePot> = Vec::new();

        for &level in &all_in_bets {
            if level <= prev_level { continue; }

            let mut pot_amount: u64 = 0;
            let mut eligible: Vec<u32> = Vec::new();
            for j in 0..n {
                let (seat_id, bet, folded, _) = player_bets[j];
                if bet > prev_level {
                    let contribution = if bet < level { bet - prev_level } else { level - prev_level };
                    pot_amount += contribution;
                    if !folded {
                        eligible.push(seat_id);
                    }
                }
            }
            if pot_amount > 0 {
                side_pots.push(SidePot { amount: pot_amount, players: eligible });
            }
            prev_level = level;
        }

        // 最外层（超出最大 all-in 的部分），对齐 Move
        let mut outer_amount: u64 = 0;
        let mut outer_eligible: Vec<u32> = Vec::new();
        for j in 0..n {
            let (seat_id, bet, folded, _) = player_bets[j];
            if bet > prev_level {
                outer_amount += bet - prev_level;
                if !folded {
                    outer_eligible.push(seat_id);
                }
            }
        }
        if outer_amount > 0 {
            side_pots.push(SidePot { amount: outer_amount, players: outer_eligible });
        }

        // M-A3 修复：最后一个边池 eligible 为空时，合并到上一个有 eligible 的层级
        if !side_pots.is_empty() {
            let last_idx = side_pots.len() - 1;
            if side_pots[last_idx].players.is_empty() && side_pots[last_idx].amount > 0 {
                let merge_amount = side_pots[last_idx].amount;
                side_pots.pop();
                if !side_pots.is_empty() {
                    // 找到最后一个有 eligible 的层级
                    let mut merge_idx = 0;
                    for k in (0..side_pots.len()).rev() {
                        if !side_pots[k].players.is_empty() {
                            merge_idx = k;
                            break;
                        }
                    }
                    side_pots[merge_idx].amount += merge_amount;
                } else {
                    // 所有层级 eligible 都为空，放回（由调用方处理）
                    side_pots.push(SidePot { amount: merge_amount, players: Vec::new() });
                }
            }
        }

        // 第一个边池 = 主池（对齐 Move: first.amount = main_pot），其余 = 边池。
        // Rust 中 self.pot 已包含所有下注，main_pot() = pot - sum(side_pots) 即主池。
        // 所以第一个边池不放入 self.side_pots，仅保留其余。
        if side_pots.len() > 1 {
            self.summary.side_pots = side_pots[1..].to_vec();
        }
    }



    pub fn determine_side_pot_winners(&mut self) {
        if self.summary.side_pots.is_empty() { return; }
        // Collect (amount, eligible_ids) pairs first to avoid cloning side_pots
        let pot_info: Vec<(u64, Vec<u32>)> = self.summary.side_pots.iter()
            .map(|sp| {
                let eligible: Vec<u32> = sp.players.iter()
                    .filter(|id| self.seats().get(id).map_or(false, |s| !s.folded))
                    .copied()
                    .collect();
                (sp.amount, eligible)
            })
            .collect();
        for (amount, eligible_ids) in pot_info {
            if eligible_ids.is_empty() { continue; }
            self.determine_winner_by_ids(amount, &eligible_ids);
        }
    }

    pub fn determine_main_pot_winner(&mut self) {
        let unfolded_ids: Vec<u32> = self.seats().values()
            .filter(|s| !s.folded)
            .map(|s| s.id)
            .collect();
        // 对齐 Move settle_hand: 使用 main_pot（= pot - sum(side_pots)），而非整个 pot
        self.determine_winner_by_ids(self.main_pot(), &unfolded_ids);
        self.summary.went_to_showdown = true;
        // 注意：round_state 已在 advance_to_next_phase(River) 中设为 Showdown，无需再 transition_to
        self.set_showdown_at(now_ms());
    }

    pub fn finish_showdown(&mut self) {
        self.clear_seat_turns();
        self.summary.hand_over = true;
        self.transition_to(RoundState::Waiting);
        self.set_hand_complete_at(now_ms());
        self.sit_out_felted_players();
        // #18 审计输出：本手动作日志摘要（含超时 auto 代打标记）。
        // auto 占比过半显式告警——服务器代打折叠任意玩家的审计钩子；
        // §8.2 电路吸收（动作日志哈希作为第 37 入参）启用后即为其输入源。
        let window = &self.action_log[self.hand_log_start.min(self.action_log.len())..];
        let auto_count = window.iter().filter(|e| e.auto).count();
        let digest_hex = crate::pokergame::actions::action_log_digest_hex(window);
        if !window.is_empty() {
            if auto_count * 2 > window.len() {
                tracing::warn!(
                    "[#18] table {} hand audit: AUTO actions {auto_count}/{} — 服务器代打占比过半，digest={digest_hex}",
                    self.summary.id,
                    window.len()
                );
            }
            tracing::info!(
                "[#18] table {} hand complete: action_log digest={digest_hex} (actions={}, auto={auto_count})",
                self.summary.id,
                window.len()
            );
        }
        self.record_hand_history();

        // Starknet 结算：镜像手牌 prove → outer aggregate → register/settle 上链
        // （dev 模式只生成 calldata 并记日志）。失败不影响链下记账。
        crate::starknet::hooks::on_hand_complete(self);
    }

    /// 镜像 Move settle_hand：Showdown 展示超时后分配底池并重置牌桌。
    /// 先 calculate_side_pots(total_bet)，再按链上口径收取台费，
    /// 然后分配 side pot 和 main pot 给赢家，最后 finish_showdown。
    #[cfg(test)]
    pub fn settle_hand(&mut self) {
        self.calculate_side_pots();
        self.collect_rake_for_settlement();
        self.determine_side_pot_winners();
        self.determine_main_pot_winner();
        self.finish_showdown();
    }

    /// 摊牌抽水（链上口径，见 `pokergame::rake` 模块注释）：
    /// `rake = min(gross_pot * bps / 10_000, cap)`，仅从争夺层按比例分摊。
    /// 扣减直接作用于 pot 与边池金额——`main_pot() = pot − Σside_pots`
    /// 自动净额化，赢家到手金额与链上结算一致。fold-win 路径
    /// （`end_without_showdown`）不调用本函数，与链上
    /// "uncontested pot must not be raked" 不变量一致。
    pub fn collect_rake_for_settlement(&mut self) {
        let params = crate::pokergame::rake::rake_params();
        let gross_pot = self.pot();
        let main_amount = self.main_pot();
        let main_eligible = self.unfolded_players().len();
        let side_layers: Vec<(u64, usize)> = self.summary.side_pots.iter()
            .map(|sp| {
                let eligible = sp.players.iter()
                    .filter(|id| self.seats().get(id).map_or(false, |s| !s.folded))
                    .count();
                (sp.amount, eligible)
            })
            .collect();
        let mut layers = Vec::with_capacity(1 + side_layers.len());
        layers.push((main_amount, main_eligible));
        layers.extend(side_layers);
        // 台费基数 = 争夺层总额（eligible ≥ 2），镜像链上 contested_gross
        // （poker_l1 settlement.rs:594-595）。未跟注返还层（如 all-in 超出
        // 部分退回）不参与抽水——若按总池计算会在该场景多抽：1000 池 =
        // 主池 600 争夺 + 400 未跟注返还时，链上抽 600×5%=30，按总池会抽
        // 50，赢家到账差 20。
        let contested_gross: u64 = layers.iter()
            .filter(|(_, eligible)| *eligible >= 2)
            .map(|(amount, _)| amount)
            .sum();
        let total_rake = crate::pokergame::rake::compute_rake(contested_gross, params);
        if total_rake == 0 {
            return;
        }
        let allocations = crate::pokergame::rake::allocate_rake(&layers, total_rake, contested_gross);
        self.summary.rake_collected = total_rake;
        // compute_rake 已 min(基数) 封顶；saturating 作第二道防线（audit M4）
        self.set_pot(gross_pot.saturating_sub(total_rake));
        for (i, sp) in self.summary.side_pots.iter_mut().enumerate() {
            sp.amount = sp.amount.saturating_sub(allocations.get(i + 1).copied().unwrap_or(0));
        }
    }

    pub fn evaluate_player_hands(&self) -> Vec<(u32, HandRank)> {
        let mut results = Vec::new();
        let (player_revealed_map, comm_revealed_cards) = self.mental_poker_game.list_revealed_cards();
        if comm_revealed_cards.len() < 5 { return results; }
        tracing::info!("comm_revealed_cards: {:?}", comm_revealed_cards);
        for seat in self.seats().values() {
            let seat_player = match seat.player.as_ref() {
                Some(p) => p,
                None => continue,
            };
            let revealed_cards = match player_revealed_map.get(&seat_player.pk_hex.0){
                Some(rc) => rc,
                None => continue,
            };

            if !seat.folded && !seat.sitting_out && revealed_cards.len() >= 2 {
                let mut eval_cards: Vec<EvalCard> = Vec::new();
                for card in revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                for card in &comm_revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                tracing::info!("evaluate_player_hands eval_cards: {:?}", eval_cards);
                if eval_cards.len() >= 5 {
                    if let Some((hand_rank, _)) = best_hand(&eval_cards) {
                        results.push((seat.id, hand_rank));
                    }
                }
            }
        }
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    pub fn determine_winner_by_ids(&mut self, amount: u64, eligible_ids: &[u32]) {
        if eligible_ids.is_empty() { return; }
        if eligible_ids.len() == 1 {
            let winner_id = eligible_ids[0];
            let win_amount = amount;
            let wallet = self.local_seats.get(&winner_id)
                .and_then(|s| s.player.as_ref().map(|p| p.wallet_address.0.clone()));
            if let Some(seat) = self.local_seats.get_mut(&winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount);
                if win_amount > 0 {
                    self.summary.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount));
                }
            }
            if let Some(w) = wallet {
                crate::starknet::prove_log::record_payout(self, &w, win_amount);
            }
            self.update_history();
            return;
        }
        let hand_results = self.evaluate_player_hands();
        let eligible_results: Vec<(u32, HandRank)> = hand_results
            .into_iter()
            .filter(|(id, _)| eligible_ids.contains(id))
            .collect();
        // 摊牌牌型快照（主池/边池逐池调用，按座位去重合并）：
        // 供 ClientTable 下发与终局 HandHistoryRecord 落账。
        for (id, rank) in &eligible_results {
            if !self.summary.showdown_hand_ranks.iter().any(|h| h.seat == *id) {
                self.summary.showdown_hand_ranks.push(
                    crate::pokergame::table_summary::ShowdownHandRank {
                        seat: *id,
                        rank: rank.name().to_string(),
                    },
                );
            }
        }
        if eligible_results.is_empty() {
            // F5 fix: No reveal cards available — split evenly among all eligible
            // instead of silently dropping the pot.
            let win_amount = amount / eligible_ids.len() as u64;
            let remainder = amount % eligible_ids.len() as u64;
            let mut payouts: Vec<(String, u64)> = Vec::new();
            for (idx, winner_id) in eligible_ids.iter().enumerate() {
                let extra = if idx < remainder as usize { 1 } else { 0 };
                let wallet = self.local_seats.get(winner_id)
                    .and_then(|s| s.player.as_ref().map(|p| p.wallet_address.0.clone()));
                if let Some(seat) = self.local_seats.get_mut(winner_id) {
                    let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                    seat.win_hand(win_amount + extra);
                    if win_amount + extra > 0 {
                        self.summary.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount + extra));
                    }
                }
                if let Some(w) = wallet {
                    payouts.push((w, win_amount + extra));
                }
            }
            for (w, amt) in payouts {
                crate::starknet::prove_log::record_payout(self, &w, amt);
            }
            self.update_history();
            return;
        }
        let best_rank = &eligible_results[0].1;
        let winners: Vec<u32> = eligible_results
            .iter()
            .filter(|(_, rank)| rank == best_rank)
            .map(|(id, _)| *id)
            .collect();
        let win_amount = amount / winners.len() as u64;
        let remainder = amount % winners.len() as u64;
        let mut payouts: Vec<(String, u64)> = Vec::new();
        for (idx, winner_id) in winners.iter().enumerate() {
            let extra = if idx < remainder as usize { 1 } else { 0 };
            let wallet = self.local_seats.get(winner_id)
                .and_then(|s| s.player.as_ref().map(|p| p.wallet_address.0.clone()));
            if let Some(seat) = self.local_seats.get_mut(winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount + extra);
                if win_amount + extra > 0 {
                    self.summary.win_messages.push(format!("{} wins ${:.2} with {}", player_name, win_amount + extra, best_rank.name()));
                }
            }
            if let Some(w) = wallet {
                payouts.push((w, win_amount + extra));
            }
        }
        for (w, amt) in payouts {
            crate::starknet::prove_log::record_payout(self, &w, amt);
        }
        self.update_history();
    }
}

#[cfg(test)]
mod side_pot_tests {
    use super::*;

    /// 直接构造纯记账状态（total_bet/stack/folded）——calculate_side_pots
    /// 只读这三项，无需真实玩家/牌局。
    fn seat_with(id: u32, total_bet: u64, stack_after: u64, folded: bool) -> crate::pokergame::seat::Seat {
        let mut s = crate::pokergame::seat::Seat::new(id, None, total_bet + stack_after, 0);
        s.total_bet = total_bet;
        s.stack = stack_after;
        s.folded = folded;
        s
    }

    fn table_with(seats: Vec<crate::pokergame::seat::Seat>) -> Table {
        let mut t = Table::new(1, "side-pots".to_string(), 10_000, 9, String::new());
        for s in seats {
            t.local_seats.insert(s.id, s);
        }
        // pot 置为全部投入之和（calculate_side_pots 不改 pot；main_pot = pot − Σside）。
        let total: u64 = t.local_seats.values().map(|s| s.total_bet).sum();
        t.set_pot(total);
        t
    }

    /// 三人双层 all-in：A(100) < B(300) < C(500，且有剩余筹码)。
    /// 边池 = [B/C 争夺 400, C 独占 200]；主池 300 三人争夺。
    #[test]
    fn two_level_all_in_side_pots() {
        let mut t = table_with(vec![
            seat_with(1, 100, 0, false),  // A all-in 100
            seat_with(2, 300, 0, false),  // B all-in 300
            seat_with(3, 500, 200, false), // C 投入 500 仍有筹码
        ]);
        t.calculate_side_pots();
        let sp = &t.summary.side_pots;
        assert_eq!(sp.len(), 2, "两层边池：{sp:?}");
        // eligible 顺序来自 HashMap 迭代，按集合比较。
        let mut l0 = sp[0].players.clone();
        l0.sort_unstable();
        assert_eq!((sp[0].amount, l0), (400, vec![2, 3]));
        assert_eq!((sp[1].amount, sp[1].players.clone()), (200, vec![3]));
        // 主池 = 900 − 600 = 300（A/B/C 争夺）。
        assert_eq!(t.main_pot(), 300);
        assert_eq!(t.pot(), 900);
    }

    /// 无 all-in（所有人都有剩余筹码）→ 无边池，全部主池。
    #[test]
    fn no_all_in_no_side_pots() {
        let mut t = table_with(vec![
            seat_with(1, 50, 950, false),
            seat_with(2, 120, 880, false),
        ]);
        t.calculate_side_pots();
        assert!(t.summary.side_pots.is_empty());
        assert_eq!(t.main_pot(), 170);
    }

    /// 弃牌玩家投入计入层级但不在 eligible（他不能赢该层）。
    #[test]
    fn folded_player_contributes_but_not_eligible() {
        let mut t = table_with(vec![
            seat_with(1, 50, 300, true),   // A 投 50 后弃牌（仍有筹码，非 all-in）
            seat_with(2, 100, 0, false),  // B all-in 100
            seat_with(3, 100, 400, false), // C 跟注 100 仍有筹码
        ]);
        t.calculate_side_pots();
        // 唯一 all-in 层 = [B,C 争夺 250]；单层 → 不进 side_pots，全是主池。
        assert!(t.summary.side_pots.is_empty(), "{:?}", t.summary.side_pots);
        assert_eq!(t.main_pot(), 250);
    }

    /// M-A3：最高层 eligible 为空（唯一贡献者已弃牌）→ 金额上并到
    /// 最后一个有 eligible 的层级，最终只剩单一主池。
    #[test]
    fn ma3_empty_eligible_top_layer_merges_down() {
        let mut t = table_with(vec![
            seat_with(1, 100, 0, false), // A all-in 100（活跃）
            seat_with(2, 300, 0, true),  // B 投满 300 后已死（stack=0 且弃牌）
        ]);
        t.calculate_side_pots();
        // 无第二个有 eligible 的层可挂 → 全部 400 归主池，A 独赢。
        assert!(t.summary.side_pots.is_empty(), "{:?}", t.summary.side_pots);
        assert_eq!(t.main_pot(), 400);
    }

    /// 空投入（没人下注）→ 直接返回，不产生任何池。
    #[test]
    fn no_bets_is_noop() {
        let mut t = table_with(vec![seat_with(1, 0, 1000, false)]);
        t.calculate_side_pots();
        assert!(t.summary.side_pots.is_empty());
        assert_eq!(t.pot(), 0);
    }
}
