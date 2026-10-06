use super::*;
use poker_protocol::crypto::EcPoint;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;
use crate::pokergame::game_state::LeaveGameRoundJson;

impl Table {
    pub fn add_player(&mut self, game_pk: GamePkHex, wallet_addr: WalletAddress) -> Result<(), JoinError> {
        if self.players().contains_key(&game_pk) {
            tracing::info!("Player {} is already in game add_player", *game_pk);
            return Ok(());
        }
        self.local_players.insert(game_pk, wallet_addr);
        Ok(())
    }

    pub fn remove_player_by_pk(&mut self, pk: &GamePkHex) {
        self.local_players.remove(pk);
        tracing::info!("remove_player_by_pk stand_player_by_pk: {}", pk);
        // 对齐 Move：手牌进行中使用 kick_player_internal，保留 seat 供 side pot 计算
        if self.is_playing() {
            self.kick_player_internal(pk);
            // 实时 VM 镜像接受点（单一状态表示）：强制弃牌同步 dispatch。
            if let Some(player) = self
                .local_seats
                .values()
                .find_map(|s| s.player.as_ref().filter(|p| &p.pk_hex == pk))
            {
                let wallet = player.wallet_address.0.clone();
                self.vm_force_fold(&wallet);
            }
        } else {
            self.stand_player_by_pk(pk);
            let _ = self.mental_poker_game.leave_player(pk);
        }
    }

    /// 镜像 Move kick_player_internal：手牌进行中踢出玩家。
    /// - 退还 stack（记日志，实际退款由链上事件处理）
    /// - 将 seat.bet 加到 pot（当前轮未收取的下注）
    /// - 标记 left_during_hand = true, folded = true，保留 total_bet 供 side pot 计算
    /// - 从 shuffle/reveal/reconstruct pending 列表移除
    /// - 若为当前洗牌者 → advance_shuffle
    /// - 若为当前行动者 → advance_turn 或 end_without_showdown
    /// - 若活跃玩家不足 → reset_for_next_hand
    pub fn kick_player_internal(&mut self, pk: &GamePkHex) {
        let seat_id = match self.pk_to_seat.get(pk) {
            Some(&id) => id,
            None => return,
        };

        let is_current_shuffler = self.shuffle_state.current_player_pk.as_ref() == Some(pk);
        let is_current_turn = self.turn() == Some(seat_id);

        // 从 mental_poker_game 移除（更新 aggregated_pk）
        let _ = self.mental_poker_game.leave_player(pk);

        // 从 players map 移除
        self.local_players.remove(pk);
        self.pk_to_seat.remove(pk);

        // 处理 seat：退 stack，标记 left_during_hand
        // 注意：seat.bet 的金额已通过 add_to_pot 累积到 self.pot，不应再加（否则双重计算）
        // 先提取数据，避免借用冲突
        let refund_amount = {
            let seats = self.seats();
            let seat = match seats.get(&seat_id) {
                Some(s) => s,
                None => return,
            };
            seat.stack
        };

        // 退 stack（记日志，Move 中发 PlayerRefund 事件）
        if refund_amount > 0 {
            if let Some(seat) = self.seats().get(&seat_id) {
                if let Some(player) = &seat.player {
                    tracing::info!("[kick_player] Refund {} stack to player {}",
                        refund_amount, player.pk_hex);
                }
            }
        }

        // 标记 seat 状态：保留 total_bet 和 player 供 side pot / refund
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.stack = 0;
            seat.hand.clear();
            seat.bet = 0;
            seat.left_during_hand = true;
            seat.folded = true; // 标记为 folded，不能赢
            seat.has_acted = false;
            seat.is_waiting = false;
            seat.turn = false;
        }

        // 从 shuffle state 移除
        self.shuffle_state.pending_players.retain(|p| p != pk);
        self.shuffle_state.completed_players.retain(|p| p != pk);
        if is_current_shuffler {
            self.shuffle_state.current_player_pk = None;
        }

        // 从 reveal token state 移除
        if self.reveal_token_state.is_active() {
            self.reveal_token_state.pending_players.retain(|p| p != pk);
            self.reveal_token_state.completed_players.retain(|p| p != pk);
            self.reveal_token_state.player_assignments.remove(pk);
        }

        // 从 reconstruct state 移除
        if self.reconstruct_state.is_active {
            self.reconstruct_state.pending_players.retain(|p| p != pk);
            self.reconstruct_state.completed_players.retain(|p| p != pk);
            self.reconstruct_state.player_deck.remove(pk);
        }

        // 若为当前洗牌者 → advance_shuffle
        if is_current_shuffler && self.shuffle_state.is_active() {
            self.advance_shuffle();
        }

        // 若为当前行动者 → advance_turn 或 end_without_showdown
        if is_current_turn && self.betting_round.is_some() {
            let active = self.active_players().len();
            if active <= 1 {
                self.end_without_showdown();
            }
            // 否则由 game_loop 的 handle_turn_advance 处理
        }

        // 活跃玩家不足 → reset_for_next_hand
        if self.active_players().len() < MIN_START_NUM as usize {
            self.reset_for_next_hand();
        }
    }

    pub fn leave_talbe_and_clear_shuffle(&mut self, pk: &GamePkHex){
        self.remove_player_by_pk(pk);
        self.shuffle_state.completed_players.retain(|p| p != pk);
        self.shuffle_state.pending_players.retain(|p| p != pk);
        if self.shuffle_state.current_player_pk.as_ref() == Some(pk) {
            self.shuffle_state.current_player_pk = None;
        }
        self.waiting_players.remove(pk);
    }

    pub fn leave_player_with_proof(
        &mut self,
        pk: &GamePkHex,
        player_pk: &EcPoint,
        leave_round_json: &LeaveGameRoundJson,
    ) -> Result<(), String> {
        // Verify the player is in the game
        if !self.players().contains_key(pk) {
            return Err("Player not found".to_string());
        }

        // Convert JSON to native types
        let leave_round = leave_round_json.to_leave_game_round()?;

        // Verify input_cards match current deck
        let current_deck = &self.mental_poker_game.deck_encrypted;
        if leave_round.input_cards.len() != current_deck.len() {
            return Err("Input cards length mismatch".to_string());
        }
        for (i, input_ct) in leave_round.input_cards.iter().enumerate() {
            if input_ct.c1 != current_deck[i].c1 || input_ct.c2 != current_deck[i].c2 {
                return Err(format!("Input card {} does not match current deck", i));
            }
        }

        // Verify the LeaveProof（排除集强校验，fail-closed）：
        // 玩家自己的手牌槽必须原样保留——剥层输出公开 sk·c1（= reveal
        // token），若允许剥自己手牌的层，其余玩家串谋即可解密其底牌
        //（违反扑克规则）。排除集由服务端从发牌状态推导，不信任离开者。
        let excluded: Vec<usize> = self
            .mental_poker_game
            .players
            .get(&**pk)
            .map(|p| p.hand_encrypted.iter().map(|c| c.card_index as usize).collect())
            .unwrap_or_default();
        for &i in &excluded {
            if i >= leave_round.output_cards.len() {
                return Err(format!("excluded slot {i} out of range"));
            }
            if leave_round.output_cards[i].c1 != leave_round.input_cards[i].c1
                || leave_round.output_cards[i].c2 != leave_round.input_cards[i].c2
            {
                return Err(format!(
                    "leave must keep own hole card slot {i} unchanged (anti-reveal rule)"
                ));
            }
        }
        // DLEq 覆盖剥层子集（与客户端 execute_with_exclusions 同构）。
        let sub_input: Vec<_> = leave_round.input_cards.iter().enumerate()
            .filter(|(i, _)| !excluded.contains(i))
            .map(|(_, ct)| ct.clone())
            .collect();
        let sub_output: Vec<_> = leave_round.output_cards.iter().enumerate()
            .filter(|(i, _)| !excluded.contains(i))
            .map(|(_, ct)| ct.clone())
            .collect();
        if sub_input.is_empty() {
            return Err("leave stripped nothing".to_string());
        }
        // 2026-09 Poseidon epoch：与 poker_l1 状态机同一 leave 生产域
        // （修复此前 Merlin/FiatShamirSha3 同标签不同海绵的域分裂）。
        let mut transcript = PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::LEAVE_POSEIDON_V2,
        );
        if !leave_round.leave_proof.verify(&sub_input, &sub_output, player_pk, &mut transcript) {
            return Err("Invalid leave proof".to_string());
        }

        // Update the deck with the leave output
        self.mental_poker_game.deck_encrypted = leave_round.output_cards;
        tracing::info!("leave_player_with_proof pk: {}", pk);

        // 对齐 Move：手牌进行中使用 kick_player_internal 保留 seat 供 side pot 计算
        if self.is_playing() {
            // 先从 mental_poker_game 移除（leave_player_with_proof 已更新 deck）
            let _ = self.mental_poker_game.leave_player(&**pk);
            // kick_player_internal 会处理退款、pot、状态清理
            self.kick_player_internal(pk);
        } else {
            // 非游戏中进行清理
            self.shuffle_state.completed_players.retain(|p| p != pk);
            self.shuffle_state.pending_players.retain(|p| p != pk);
            if self.shuffle_state.current_player_pk.as_ref() == Some(pk) {
                self.shuffle_state.current_player_pk = None;
            }
            self.waiting_players.remove(pk);
            self.local_players.remove(pk);
            self.pk_to_seat.remove(pk);
            self.stand_player_by_pk(pk);
            let _ = self.mental_poker_game.leave_player(&**pk);
        }

        Ok(())
    }



    pub fn find_random_empty_seat(&self) -> Option<u32> {
        let empty_seats: Vec<u32> = (1..=self.max_players())
            .filter(|&seat_id| !self.seats().contains_key(&seat_id))
            .collect();

        if empty_seats.is_empty() {
            None
        } else {
            use rand::seq::SliceRandom;
            empty_seats.choose(&mut rand::thread_rng()).copied()
        }
    }

    pub fn sit_player(&mut self, player: GamePlayer, seat_id: u32, amount: u64, is_waiting: bool) {
        if seat_id < 1 || seat_id > self.max_players() {
            return;
        }
        if self.seats().contains_key(&seat_id) {
            return;
        }
        let pk_hex = player.pk_hex.clone();
        let mut seat = Seat::new(seat_id, Some(player), amount, amount);
        seat.is_waiting = is_waiting;
        let first_player = self.seats().is_empty();
        self.local_seats.insert(seat_id, seat);
        self.pk_to_seat.insert(pk_hex, seat_id);
        if first_player {
            self.set_button(Some(seat_id));
        }
    }

    pub fn rebuy_player(&mut self, seat_id: u32, amount: u64) {
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.stack += amount;
        }
    }

    pub fn stand_player_by_pk(&mut self, pk: &GamePkHex) {
        self.pk_to_seat.remove(pk);
        let mut seat_to_remove: Option<u32> = None;
        for (id, seat) in self.seats().iter() {
            if seat.player.as_ref().map_or(false, |p| &p.pk_hex == pk) {
                seat_to_remove = Some(*id);
                break;
            }
        }
        if let Some(id) = seat_to_remove {
            self.local_seats.remove(&id);
        }
        if self.seats().is_empty() {
            self.reset_empty_table();
        }
    }

    pub fn find_player_by_pk(&self, pk: &GamePkHex) -> Option<&Seat> {
        self.pk_to_seat.get(pk).and_then(|&seat_id| self.local_seats.get(&seat_id))
    }

    pub fn find_player_by_pk_mut(&mut self, pk: &GamePkHex) -> Option<&mut Seat> {
        if let Some(&seat_id) = self.pk_to_seat.get(pk) {
            self.local_seats.get_mut(&seat_id)
        } else {
            None
        }
    }

    pub fn find_player_by_wallet(&self, wallet: &str) -> Option<&Seat> {
        for seat in self.local_seats.values() {
            if seat.player.as_ref().map_or(false, |p| p.wallet_address.0 == wallet) {
                return Some(seat);
            }
        }
        None
    }

    pub fn unfolded_players(&self) -> Vec<&Seat> {
        // F10 fix: exclude sitting_out players
        self.local_seats.values().filter(|s| !s.folded && !s.sitting_out).collect()
    }

    pub fn active_players(&self) -> Vec<&Seat> {
        self.local_seats.values().filter(|s| !s.sitting_out && !s.is_waiting).collect()
    }

    /// F2 fix: return Option<u32> instead of an arbitrary seat when no match.
    /// Returns None if no matching seat is found within one full lap.
    pub fn next_player_by_filter<F>(&self, player: u32, places: u32, filter: F) -> Option<u32>
    where
        F: Fn(&Seat) -> bool,
    {
        if places == 0 {
            return Some(player);
        }
        let mut count = 0u32;
        let mut current = player;
        for _ in 0..self.max_players() {
            current = if current >= self.max_players() { 1 } else { current + 1 };
            if let Some(seat) = self.seats().get(&current) {
                if filter(seat) {
                    count += 1;
                    if count >= places {
                        return Some(current);
                    }
                }
            }
        }
        tracing::warn!("[next_player_by_filter] no matching seat found from player {} (places={})", player, places);
        None
    }

    /// F3 fix: exclude all-in players (stack == 0) in addition to folded/sitting_out.
    /// 修复：同时排除 is_waiting 玩家，与 is_betting_round_complete / has_actionable_player 对齐，
    /// 避免 turn 落到 is_waiting 玩家上（该玩家不会主动行动，导致下注轮卡住或 turn 来回跳）。
    pub fn next_unfolded_player(&self, player: u32, places: u32) -> Option<u32> {
        self.next_player_by_filter(player, places, |seat| {
            !seat.folded && !seat.sitting_out && !seat.is_waiting && seat.stack > 0
        })
    }

    pub fn next_active_player(&self, player: u32, places: u32) -> Option<u32> {
        self.next_player_by_filter(player, places, |seat| !seat.sitting_out && !seat.is_waiting)
    }

    pub fn mark_player_disconnected(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let is_turn = seat.turn;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.disconnected = true;
            seat.disconnected_at = Some(now);
            seat.sitting_out = true;
        }
        if is_turn {
            // 单一状态重构：断线代打弃牌也必须经 VM dispatch（本地直接
            // seat.fold() 会绕过权威状态造成双写失步）。force_fold 非致命
            // （VM 拒绝 = 状态不变），随后统一从 VM 重派生视图。
            if let Some(seat) = self.local_seats.get(&seat_id) {
                if let Some(player) = &seat.player {
                    let wallet = player.wallet_address.0.clone();
                    self.vm_force_fold(&wallet);
                }
            }
            self.refresh_from_vm();
            if self.local_seats.get(&seat_id).map(|s| s.folded).unwrap_or(false) {
                return Some(ActionResult {
                    seat_id,
                    message: format!("{} auto-folds (disconnected)", player_name),
                });
            }
        }
        None
    }

    pub fn reconnect_player(&mut self, wallet_address: &str) -> bool {
        for seat in self.local_seats.values_mut() {
            if seat.player.as_ref().map_or(false, |p| p.wallet_address.0 == wallet_address) {
                if let Some(player) = seat.player.as_mut() {
                    tracing::info!("reconnect_player: {}", player.name.clone());
                }
                seat.disconnected = false;
                seat.disconnected_at = None;
                seat.sitting_out = false;
                return true;
            }
        }
        false
    }

    /// 手牌进行中断线：只记 disconnected，**不**置 sitting_out。
    /// sitting_out 会被 unfolded_players/is_betting_round_complete 当作
    /// "已出局"过滤——局中置位会让 tick 把手牌直接重置（unfolded≤1 →
    /// end_without_showdown，无 fold 记录），结算走 showdown 计划但
    /// 公共牌不满 5 张 → build failed，客户端上手牌凭空消失
    /// （2026-09-08 hand 1788804569 线上）。局内筹码由 30s 下注超时
    /// 正常 fold（实时镜像已 dispatch，可证明）；下一手开始时仍未重连
    /// 才由 start_preflop_shuffle 转 sitting_out。
    pub fn mark_player_disconnected_mid_hand(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.disconnected = true;
            seat.disconnected_at = Some(now);
        }
        None
    }

    pub fn is_player_disconnected_by_pk(&self, pk: &GamePkHex) -> bool {
        self.seats().values()
            .any(|s| s.player.as_ref().map_or(false, |p| &p.pk_hex == pk) && s.disconnected)
    }
}
