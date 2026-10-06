use super::*;

impl Table {
    /// 本手揭示参与者（与 record_hand_start 的 VM 计划同源过滤）：活跃座位
    /// （非 sitting_out / 非 is_waiting）且有玩家且已注册进 mental_poker。
    ///
    /// 此前 preflop/community 揭示直接用 `mental_poker_game.players.keys()`
    /// 全集：断线转 sitting_out 的玩家、残留注册都进了 pending_players——
    /// 他们永不提交揭示份额，游戏层只能等 45s 超时踢人重开整手；而 VM
    /// 镜像的 reveal 窗口按 VM 计划座位构建，两边参与者集失配后镜像窗口
    /// 推进错位、陈旧镜像跨手残留，最终表现为"betting 被拒：not in
    /// betting round"死锁（2026-09-18 500 手长跑首小时复现）。showdown
    /// 揭示自始使用同款过滤，preflop/community 对齐之。
    fn reveal_participant_pks(&self) -> Vec<GamePkHex> {
        self.seats()
            .values()
            .filter(|s| !s.sitting_out && !s.is_waiting)
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .filter(|pk| self.mental_poker_game.players.contains_key(pk.as_str()))
            .collect()
    }

    pub fn start_preflop_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            return;
        }
        let player_pks: Vec<GamePkHex> = self.reveal_participant_pks();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            let mut hand_cards = Vec::new();
            for (other_pk, state) in &self.mental_poker_game.players {
                if pk.0 == *other_pk {
                    continue;
                }
                for card in &state.hand_encrypted {
                    hand_cards.push(card.encrypted_card.clone());
                }
            }
            player_assignments.insert(
                pk.clone(),
                PlayerRevealAssignment {
                    hand_card: hand_cards,
                    community_card: vec![],
                },
            );
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::HandReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 5,
            timeout_start: Some(std::time::Instant::now()),
            last_notice_at: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!(
            "[REVEAL-TOKEN] Hand reveal phase started for {} players",
            player_pks.len()
        );
    }

    pub fn start_community_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_community_reveal_phase] Reveal phase already active");
            return;
        }

        let player_pks: Vec<GamePkHex> = self.reveal_participant_pks();

        let unreveal_cards = self
            .mental_poker_game
            .list_unreveal_community_cards_encrypted();
        let community_cards: Vec<ElGamalCiphertext> = unreveal_cards
            .iter()
            .map(|c| c.encrypted_card.clone())
            .collect();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            player_assignments.insert(
                pk.clone(),
                PlayerRevealAssignment {
                    hand_card: vec![],
                    community_card: community_cards.clone(),
                },
            );
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::CommunityReveal,
            current_card_index: 0,
            // G6 修复：community reveal 阶段不揭示玩家手牌，total_cards_per_player 应为 0
            total_cards_per_player: 0,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            last_notice_at: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!(
            "[REVEAL-TOKEN] Community reveal phase started for {} players ({} community cards)",
            player_pks.len(),
            self.mental_poker_game.community_cards_encrypted.len()
        );
    }

    pub fn start_showdown_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        // F4 fix: only include players who are actually in the mental poker game,
        // so pending_players stays consistent with player_assignments.
        let player_pks: Vec<GamePkHex> = self
            .seats()
            .values()
            .filter(|s| !s.folded)
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .filter(|pk| self.mental_poker_game.players.contains_key(pk.as_str()))
            .collect();
        let mut player_assignments = HashMap::new();
        for seat in self.seats().values() {
            if seat.folded {
                continue;
            }
            if let Some(player) = &seat.player {
                if let Some(men_player) = self.mental_poker_game.players.get(player.pk_hex.as_str())
                {
                    let hand_cards = men_player
                        .hand_encrypted
                        .iter()
                        .map(|f| f.encrypted_card.clone())
                        .collect();
                    player_assignments.insert(
                        player.pk_hex.clone(),
                        PlayerRevealAssignment {
                            hand_card: hand_cards,
                            community_card: vec![],
                        },
                    );
                }
            }
        }
        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::ShowdownReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            last_notice_at: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks,
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Hand card reveal (showdown) phase started");
    }

    pub fn mark_player_reveal_complete(&mut self, player_pk: &GamePkHex) -> bool {
        if !self.reveal_token_state.is_active() {
            return false;
        }
        if !self
            .reveal_token_state
            .pending_players
            .iter()
            .any(|p| p == player_pk)
        {
            return false;
        }

        self.reveal_token_state
            .completed_players
            .push(player_pk.clone());
        self.reveal_token_state
            .pending_players
            .retain(|p| p != player_pk);

        tracing::info!(
            "[REVEAL-TOKEN] Player {} completed {} phase, remaining: {}",
            player_pk,
            self.reveal_token_state.phase,
            self.reveal_token_state.pending_players.len()
        );

        if self.reveal_token_state.pending_players.is_empty() {
            self.on_reveal_complete();
            return true;
        }
        false
    }

    /// 镜像 Move on_reveal_complete：所有 pending 玩家完成后的状态转换
    pub fn on_reveal_complete(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        if !self.reveal_token_state.pending_players.is_empty() {
            return;
        }

        let phase = self.reveal_token_state.phase;
        self.reveal_token_state.reset();

        // 缺口 B fail-fast：本阶段存在物化失败的牌（份额齐但明文不合法）时，
        // 中止该手并全额退款——绝不让空牌面静默打完。走与 reveal 超时相同
        // 的 refund + reset 路径（牌局可继续开下一手，deck 基线重建）。
        if self.materialization_broken() {
            tracing::error!(
                "[on_reveal_complete] materialization FAILED after phase {:?}; aborting hand with full refund (fail-fast)",
                phase
            );
            self.refund_all_bets();
            self.reset_for_next_hand();
            self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
                message: Some("牌局已中止：存在无法解密的牌，本手下注已全额退还".to_string()),
            });
            return;
        }

        // 方案A 单点广播：reveal 结果事件从游戏层完成点统一发出（此前只挂在
        // WS REVEAL_SUBMIT handler，bot 等进程内路径完成时会绕过广播，导致
        // 前端收不到 HAND_REVEAL_RESULT / COMMUNITY_REVEAL_RESULT 而不显示牌）。
        self.emit_event(crate::pokergame::table::events::TableEvent::RevealResult { phase });

        match phase {
            RevealPhase::None => {
                // 不应到达（is_active 已检查），防御性处理
                tracing::warn!("[on_reveal_complete] reached with None phase");
            }
            RevealPhase::HandReveal => {
                // 翻牌前手牌揭牌完成 → 进入 PreFlop 下注轮
                // 对齐 Move check_reveal_phase_complete: post_blinds THEN start_betting_round(true)
                // set_blinds 已包含首行动作设置（对齐 Move post_blinds），无需再调用 init_turn
                self.set_blinds();
                // 盲注唯一权威复核（2026-09-19 hand 1789813453 千手长跑复现）：
                // 计划冻结（record_hand_start）与此处盲注计算之间的窗口里，
                // 座位标志可被并发事件翻转——reconnect_player 无条件清
                // sitting_out，翻牌前重连抖动会让 set_blinds 把无牌座位重新
                // 计入轮转（单挑判定/盲注落点整体偏移），与 VM 按冻结计划
                // 所发盲注反向 → 本手全部动作被 VM 拒绝且永不收敛（超时
                // 代打被拒后强吃 fold 也无法对齐），桌面永久卡死。VM 在
                // bootstrap 已按冻结计划发盲：此处直接以 VM 视图覆写本地
                // 盲注账本（bets/stack/pot/turn/call_amount），并把计划外
                // 座位钉回 sitting_out（清掉 set_blinds 可能挂上的幻影注额
                // /turn 残影），两层从首动作起逐位一致。
                let vm_view = self.vm_session.as_ref().map(|sh| sh.current_view());
                if let Some(view) = vm_view {
                    if view.in_betting {
                        self.apply_betting_view(&view);
                        let in_vm: std::collections::HashSet<&str> =
                            view.seats.iter().map(|s| s.pk_hex.as_str()).collect();
                        for (seat_id, seat) in self.local_seats.iter_mut() {
                            let Some(player) = seat.player.as_ref() else {
                                continue;
                            };
                            if in_vm.contains(player.pk_hex.0.as_str()) {
                                continue;
                            }
                            let residue = seat.bet != 0 || seat.turn;
                            if residue || !seat.sitting_out {
                                tracing::warn!(
                                    "[blinds-authority] seat {seat_id} in-seat but not in frozen plan — pinned out for this hand (residue bet={}, turn={})",
                                    seat.bet,
                                    seat.turn
                                );
                            }
                            seat.bet = 0;
                            seat.total_bet = 0;
                            seat.turn = false;
                            seat.has_acted = false;
                            if !seat.sitting_out {
                                seat.sitting_out = true;
                                if !self.hand_excluded_seats.contains(seat_id) {
                                    self.hand_excluded_seats.push(*seat_id);
                                }
                            }
                        }
                    }
                }
                self.start_betting_round(true);
            }
            RevealPhase::CommunityReveal => {
                // 公共牌揭牌完成 → 进入对应下注轮
                self.start_betting_round(false);
            }
            RevealPhase::ShowdownReveal => {
                // 摊牌揭牌完成 → 判定赢家
                // 对齐 Move settle_hand: 先 calculate_side_pots(total_bet)，再按
                // 链上口径收取台费，然后分配。漏掉抽水会让前端筹码与链上
                // 结算每手偏差 5%（2026-09-04 线上复现：链上 -340/+306/+34，
                // 前端 760/1240 总和守恒）。
                // 派彩前快照终局投入——win_hand 会清零赢家的 total_bet，
                // 结算对账（take_settle_input）必须用派彩前值。
                crate::starknet::prove_log::record_final_bets(self);
                self.calculate_side_pots();
                self.collect_rake_for_settlement();
                self.determine_side_pot_winners();
                self.determine_main_pot_winner();
            }
            RevealPhase::RedealReveal => {
                // 重新发牌揭牌完成，保持当前 round_state 不变
                tracing::info!(
                    "[on_reveal_complete] Redeal reveal complete, round_state stays {:?}",
                    self.round_state()
                );
            }
        }

        // 仅在下注轮开始时同步 seat.turn（ShowdownReveal 后无行动者，不需要同步）
        if phase != RevealPhase::ShowdownReveal {
            let current_turn = self.turn();
            for i in 1..=self.max_players() {
                if let Some(seat) = self.local_seats.get_mut(&i) {
                    seat.turn = current_turn == Some(i);
                }
            }
        }
        tracing::info!(
            "[REVEAL-TOKEN] All reveal phases complete, switch round state to {:?}",
            self.round_state()
        );
        // 通知前端 reveal 完成
        self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
            message: None,
        });
    }

    /// 镜像 Move on_reveal_timeout：处理揭牌超时
    pub fn on_reveal_timeout(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        let timed_out_pks = self.reveal_token_state.pending_players.clone();
        let reveal_phase = self.reveal_token_state.phase;
        tracing::warn!("[REVEAL-TOKEN] Timeout for players: {:?}", timed_out_pks);

        // 方案A（超时进轨迹）：先驱动镜像的 AdvanceDeadline dispatch——L1 踢掉
        // 未交份额座位并按活跃数内联级联（reset / end_without_showdown / 进入
        // Reconstructing / 恢复换牌挂起的下注轮）。游戏层随后镜像同一结局；
        // 无镜像或被拒仅告警（可用性优先，失配由后续对齐校验 fail-closed 兜底）。
        match self.vm_try_advance_deadline() {
            Some(Ok(())) => {}
            Some(Err(e)) => tracing::error!("[REVEAL-TOKEN] VM advance_deadline failed: {e}"),
            None => {}
        }

        // 换牌窗口超时（对齐 L1 on_reveal_timeout 的 Redealing 分支）：踢掉未交
        // 份额的座位后恢复被挂起的下注轮继续牌局——换牌死局只影响被换的那张
        // 牌（持有者可再次 redeal），deck 未被破坏，refund/reconstruct 是过度反应。
        if reveal_phase == RevealPhase::RedealReveal {
            for pk in &timed_out_pks {
                self.remove_player_by_pk(pk);
            }
            if self.round_state() == RoundState::Waiting {
                return;
            }
            let active_count = self.active_players().len();
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            self.reveal_token_state.reset();
            tracing::info!(
                "[REDEAL] window timed out; betting restored with {} active player(s)",
                active_count
            );
            self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
                message: None,
            });
            return;
        }

        let is_preflop = self.round_state() == RoundState::PreFlop;
        // 对齐 Move clear_reveal_timeout_player：踢出所有超时玩家
        // kick_player_internal 会处理退款/pot/状态清理，可能触发 reset_for_next_hand
        for pk in &timed_out_pks {
            self.remove_player_by_pk(pk);
        }

        // kick 可能已触发 reset_for_next_hand（活跃玩家不足）
        if self.round_state() == RoundState::Waiting {
            return;
        }

        let active_count = self.active_players().len();

        if is_preflop {
            // PreFlop reveal 超时：重开整手
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 退还未被踢玩家的筹码，重开整手
            self.refund_all_bets();
            self.reset_for_next_hand();
        } else {
            // 其他阶段超时：启动 reconstruct
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 启动 reconstruct（失败必须可见：静默丢弃 = 桌面卡死在无窗口
            // 状态，后续 tick 无从恢复）。

            if let Err(e) = self.start_reconstruct() {
                tracing::error!("[REVEAL-TOKEN] start_reconstruct failed: {e}");
            }
        }
    }

    /// 镜像 Move start_betting_round：启动下注轮。
    /// 对齐 Move: 创建 BettingRound + 重置 acted_this_round + 设置首行动作。
    pub fn start_betting_round(&mut self, is_preflop: bool) {
        // C5 修复扩展到 preflop：当所有活跃玩家已 all-in 时，跳过下注轮。
        // preflop 时盲注已下，若全员 all-in 则无人可行动，直接推进。
        // postflop 同理：find_next_active_seat 在全员 all-in 时会返回 None，需先检查。
        if !self.has_actionable_player() {
            self.betting_round = None;
            self.advance_to_next_phase();
            return;
        }

        if is_preflop {
            // PreFlop: 盲注已由调用方发布（set_blinds），bet 保留盲注金额。
            // 仅重置 has_acted（对齐 Move: seat.acted_this_round = false）
            for seat in self.local_seats.values_mut() {
                seat.has_acted = false;
            }
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new_preflop(
                self.summary.min_bet * 2,
            ));
            // preflop 的 current_turn 已由 set_blinds 设置，无需再设
        } else {
            // PostFlop: 重置下注 + 创建下注轮（对齐 Move: seat.bet = 0, acted_this_round = false）
            self.reset_bets_and_actions();
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new(
                self.summary.min_bet * 2,
            ));

            // 对齐 Move start_betting_round: 设置 postflop 首行动作。
            // 非 heads-up：button 之后第一个可行动座位（button 最后行动）。
            // heads-up：BB 先行动（button 职责=SB，最后行动）——dead button
            // 下 BB 座位可能与 button 座位不同，显式从 BB 开始（含 BB 本身；
            // BB 已 all-in/fold 时顺延到 BB 之后第一个可行动座位）。
            let first = if self.active_players().len() == 2 {
                let bb = self.big_blind().unwrap_or(self.button().unwrap_or(1));
                let bb_actionable = self
                    .seats()
                    .get(&bb)
                    .map(|s| !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0)
                    .unwrap_or(false);
                if bb_actionable {
                    Some(bb)
                } else {
                    self.next_unfolded_player(bb, 1)
                }
            } else {
                self.next_unfolded_player(self.button().unwrap_or(1), 1)
            };
            self.set_turn(first);
        }
        self.set_betting_started_at(now_ms());
    }

    /// 对齐 Move has_actionable_player：是否存在可行动的玩家（非 fold、非 all-in、非 waiting）
    pub fn has_actionable_player(&self) -> bool {
        self.seats()
            .values()
            .any(|s| !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0)
    }

    /// 玩家已不在本轮 pending（重复提交 / 状态已推进）的错误文本。
    /// 多客户端同账号、广播与 TABLE_UPDATED fallback 并发、服务器重播等
    /// 场景下重复到达属正常现象，提交方应按幂等成功处理（见 is_benign）。
    pub const ERR_ALREADY_SUBMITTED: &str = "Player already submitted or not pending";

    pub fn submit_player_reveal_tokens(
        &mut self,
        player_pk: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        if !self.reveal_token_state.is_active() {
            return Err("Reveal token phase not active".to_string());
        }
        if !self
            .reveal_token_state
            .pending_players
            .iter()
            .any(|p| p == player_pk)
        {
            return Err(Self::ERR_ALREADY_SUBMITTED.to_string());
        }
        // reveal 域权威路径（单一状态重构）：先经实时 VM 做 canonical
        // 重排 + 证明验证 + 窗口推进——VM 拒绝 = 动作非法，直接拒绝客户端。
        // 无实时镜像 = 不可证明手 → fail-closed 拒绝（本地兜底已删除）。
        match self.vm_try_reveal(player_pk.0.as_str(), &tokens) {
            Some(Err(e)) => {
                tracing::warn!(
                    "[reveal-authority] table {} reveal rejected by VM: {e}",
                    self.summary.id
                );
                return Err(format!("reveal rejected by VM: {e}"));
            }
            Some(Ok(view)) => {
                tracing::debug!(
                    "[reveal-authority] table {} window_open={} board={} pending={}",
                    self.summary.id,
                    view.window_open,
                    view.revealed_board,
                    view.pending_pks.len()
                );
            }
            None => {
                tracing::warn!(
                    "[reveal-authority] table {} reveal rejected: no live VM mirror (unprovable hand, fail-closed)",
                    self.summary.id
                );
                return Err("reveal rejected: hand has no live VM mirror".to_string());
            }
        }

        let assign = match self.reveal_token_state.player_assignments.get(player_pk) {
            Some(a) => a,
            None => return Err(format!("No assignment found for player {}", player_pk)),
        };
        tracing::info!(
            "[REVEAL-TOKEN] Player {} submitted token ({}) num {:?}",
            player_pk,
            self.reveal_token_state.phase,
            tokens.len()
        );

        for token in tokens {
            let cards = match self.reveal_token_state.phase {
                RevealPhase::None => {
                    return Err("Reveal token phase not active".to_string());
                }
                RevealPhase::HandReveal => &assign.hand_card,
                RevealPhase::CommunityReveal => &assign.community_card,
                RevealPhase::ShowdownReveal => &assign.hand_card,
                RevealPhase::RedealReveal => &assign.hand_card,
            };
            if !cards.iter().any(|pct| pct == &token.encrypted_card) {
                return Err(format!(
                    "Invalid token in {} phase",
                    self.reveal_token_state.phase
                ));
            }
            if let Err(e) = self
                .mental_poker_game
                .submit_reveal_token(token.clone(), player_pk)
            {
                tracing::error!("[REVEAL-TOKEN] Token submission failed: {:?}", e);
                return Err(format!("Token submission failed: {:?}", e));
            }
        }
        Ok(())
    }

    pub fn get_reveal_token_public_state(&self) -> Option<RevealTokenPublicState> {
        if self.reveal_token_state.is_active() {
            Some(RevealTokenPublicState {
                phase: self.reveal_token_state.phase.to_string(),
                completed_players: self.reveal_token_state.completed_players.clone(),
                pending_players: self.reveal_token_state.pending_players.clone(),
                player_assignments: self.reveal_token_state.player_assignments.clone(),
            })
        } else {
            None
        }
    }

    /// 提交错误是否为良性幂等场景（`ERR_ALREADY_SUBMITTED`）。调用方据此
    /// 跳过"证明验证失败"广播与 error 回传——首次提交已推进状态机，
    /// 结果广播由 on_reveal_complete 单点下发，无需重复告警。
    /// "phase not active" 同为幂等：窗口已完成/重置后的迟到重复提交
    /// （缺口 C），客户端应静默而非弹错。
    pub fn is_benign_reveal_error(e: &str) -> bool {
        e.contains(Self::ERR_ALREADY_SUBMITTED) || e.contains("Reveal token phase not active")
    }

    /// 缺口 B（fail-fast）：检测"物化已尝试但失败"的牌——reveal 份额已齐
    /// （pending 清空、tokens 非空）但解密明文不在规范域（playing_card 为
    /// None）。这类手牌继续推进只会以空牌面收场（NOT_REGISTERED 会话线上
    /// 复现），必须在阶段推进前中止。
    fn materialization_broken(&self) -> bool {
        let hole_bad = self.mental_poker_game.players.values().any(|p| {
            p.hand_encrypted.iter().any(|c| {
                c.reveal_state.pending_players.is_empty()
                    && !c.reveal_state.reveal_tokens.is_empty()
                    && c.playing_card.is_none()
            })
        });
        if hole_bad {
            return true;
        }
        self.mental_poker_game
            .community_cards_encrypted
            .iter()
            .any(|c| {
                c.reveal_state.pending_players.is_empty()
                    && !c.reveal_state.reveal_tokens.is_empty()
                    && c.playing_card.is_none()
            })
    }
}

// ============================================================
// P0.2 不变量回归（Plan D）：reveal 编排必须满足的协议不变量。
//
// 服务器是 reveal 调度者。若（有意或回归）把玩家自己的手牌密文
// 放进该玩家在非 ShowdownReveal 阶段的 assignment，客户端会交出
// 自己的解密份额，服务器即可集齐 N 份解密底牌——这是
// "no admin can peek at cards" 的唯一主动攻击面（见
// 原 docs/starknet-plan-d-stark-curve.md（git 历史） §0.2）。以下测试把它钉死：
// - HandReveal / CommunityReveal：assignment 不得包含 assignee 自己
//   的 hand_encrypted；
// - ShowdownReveal：assignment 必须恰好是自己的 hand_encrypted。
// 客户端侧对应守卫见 client/src/context/game/useCryptoOperations.ts
// 的 revealOwnCardGuard。
// ============================================================
#[cfg(test)]
mod reveal_invariant_tests {
    use super::*;
    use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};

    fn make_test_table() -> Table {
        Table::new(7, "invariant".to_string(), 100, 6, String::new())
    }

    /// 注册一个玩家到 mental_poker_game（真实 PKOwnership 证明）并入座。
    fn register_and_seat(table: &mut Table, idx: u64) -> String {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        use poker_protocol::z_poker::PKOwnershipProof;

        let sk =
            <poker_protocol::crypto::DefaultCurve as Curve>::Scalar::random(&mut rand_core::OsRng);
        let pk = <poker_protocol::crypto::DefaultCurve as Curve>::base_g() * sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut rand_core::OsRng);
        let pk_hex = format!("{:064x}", idx);
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), pk, proof);
        let player = GamePlayer {
            name: format!("p{idx}"),
            bankroll: 1000,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: WalletAddress(format!("0xwallet{idx}")),
        };
        table.sit_player(player, idx as u32, 1000, false);
        // Seat::new 默认 folded=true（生产由开局流程清除）；测试直接清位，
        // 使 start_showdown_reveal_phase 的 !s.folded 过滤能看到这些座位。
        if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
            seat.folded = false;
        }
        pk_hex
    }

    fn deal_hands(table: &mut Table) {
        for pk in table
            .mental_poker_game
            .players
            .keys()
            .cloned()
            .collect::<Vec<_>>()
        {
            table
                .mental_poker_game
                .deal_to_player(&pk, 2)
                .expect("deal to registered player");
        }
    }

    fn own_hand_ciphers(table: &Table, pk_hex: &str) -> Vec<String> {
        table
            .mental_poker_game
            .players
            .get(pk_hex)
            .map(|p| {
                p.hand_encrypted
                    .iter()
                    .map(|c| hex_ct(&c.encrypted_card))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn hex_ct(ct: &poker_protocol::crypto::ElGamalCiphertext) -> String {
        let mut s = String::new();
        s.push_str(&hex_bytes(ct.c1.compress().as_ref()));
        s.push_str(&hex_bytes(ct.c2.compress().as_ref()));
        s
    }

    fn hex_bytes(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// HandReveal（preflop）：assignment 不得包含 assignee 自己的手牌。
    #[test]
    fn hand_reveal_assignment_excludes_own_hand_cards() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);
        assert!(
            table
                .mental_poker_game
                .players
                .values()
                .all(|p| !p.hand_encrypted.is_empty()),
            "fixture: every player must hold dealt cards"
        );

        table.start_preflop_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::HandReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("every seated player gets an assignment");
            let own = own_hand_ciphers(&table, pk_hex);
            assert!(!own.is_empty());
            for card in &assignment.hand_card {
                assert!(
                    !own.contains(&hex_ct(card)),
                    "P0.2 invariant violated: own hand card leaked into own \
                     HandReveal assignment for {pk_hex} — a client following \
                     this assignment would surrender its decryption share"
                );
            }
        }
    }

    /// CommunityReveal：assignment 只含公共牌，不得混入任何玩家手牌。
    #[test]
    fn community_reveal_assignment_contains_only_community_cards() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);
        table.mental_poker_game.deal_community_cards_encrypted(5);

        table.start_community_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::CommunityReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("assignment for every player");
            let own = own_hand_ciphers(&table, pk_hex);
            for card in &assignment.hand_card {
                assert!(
                    !own.contains(&hex_ct(card)),
                    "P0.2 invariant violated: own hand card leaked into \
                     CommunityReveal assignment for {pk_hex}"
                );
            }
        }
    }

    /// ShowdownReveal：assignment 必须恰好等于自己的 hand_encrypted
    /// （持有者此刻交出自己的份额，卡牌公开——唯一允许的自身出份额阶段）。
    #[test]
    fn showdown_reveal_assignment_is_exactly_own_hand() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);

        table.start_showdown_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::ShowdownReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("showdown assignment for every seated player");
            let own = own_hand_ciphers(&table, pk_hex);
            assert_eq!(
                assignment.hand_card.len(),
                own.len(),
                "showdown assignment must cover exactly the own hand"
            );
            for card in &assignment.hand_card {
                assert!(
                    own.contains(&hex_ct(card)),
                    "showdown assignment must only contain own hand cards"
                );
            }
        }
    }

    /// 回归（2026-09-18 长跑死锁根因）：preflop/community 揭示的参与者集
    /// 必须与 record_hand_start 的 VM 计划同源（活跃座位 ∩ mental 注册）。
    /// sitting_out 玩家（断线未归）留在 mental 注册表里，但绝不进揭示
    /// pending——否则他永不提交份额，游戏层 45s 超时重开 + VM 镜像窗口
    /// 与计划失配，最终演化为 "not in betting round" 永久死锁。
    #[test]
    fn reveal_pending_excludes_sitting_out_players() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);

        // 玩家 3 断线转 sitting_out（局中掉线、下一手仍未归）。
        if let Some(seat) = table.local_seats.get_mut(&3) {
            seat.sitting_out = true;
        }
        // mental 注册仍在（注册表跨手保留）——这正是现场条件。
        assert!(
            table.mental_poker_game.players.contains_key(&pks[2]),
            "fixture: pk3 must remain registered while sitting out"
        );

        table.start_preflop_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert!(
            state
                .pending_players
                .contains(&GamePkHex::new(pks[0].clone()))
        );
        assert!(
            state
                .pending_players
                .contains(&GamePkHex::new(pks[1].clone()))
        );
        assert!(
            !state
                .pending_players
                .contains(&GamePkHex::new(pks[2].clone())),
            "sitting_out player must not be a preflop reveal participant"
        );

        // community 揭示同款过滤。
        table.reveal_token_state.reset();
        table.mental_poker_game.deal_community_cards_encrypted(5);
        table.start_community_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert!(
            state
                .pending_players
                .contains(&GamePkHex::new(pks[0].clone()))
        );
        assert!(
            !state
                .pending_players
                .contains(&GamePkHex::new(pks[2].clone())),
            "sitting_out player must not be a community reveal participant"
        );
    }

    /// 回归（2026-09-07 线上 hand 1788801359）：揭牌仪式期间 betting_round
    /// 是上一街的陈旧轮、turn 停留在最后一个行动人身上——任何下注动作都
    /// 必须被拒绝。否则动作会带着陈旧轮语义改写底池并被记入证明日志，
    /// 镜像 VM（严格轮转）无法重放 → 结算 build failed。
    #[test]
    fn betting_actions_rejected_during_reveal_ceremony() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=2).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);
        table.mental_poker_game.deal_community_cards_encrypted(5);

        // 复现生产状态：盲注已发（turn 有值、下注在场）→ 转入揭牌仪式，
        // betting_round/turn 残留为陈旧值。
        table.set_blinds();
        assert!(
            table.turn().is_some(),
            "fixture: blinds must set first actor"
        );
        table.start_community_reveal_phase();
        assert!(
            table.reveal_token_state.is_active(),
            "fixture: ceremony must be active"
        );

        let pot_before = table.pot();
        for pk_hex in &pks {
            let pk = GamePkHex::new(pk_hex.clone());
            assert!(
                table.handle_check(&pk).is_none(),
                "check must be rejected during ceremony"
            );
            assert!(
                table.handle_call(&pk).is_none(),
                "call must be rejected during ceremony"
            );
            assert!(
                table.handle_raise(&pk, 220).is_none(),
                "raise must be rejected during ceremony"
            );
            assert!(
                table.handle_fold(&pk).is_none(),
                "fold must be rejected during ceremony"
            );
        }
        assert_eq!(
            table.pot(),
            pot_before,
            "rejected actions must not touch the pot"
        );
    }
}
