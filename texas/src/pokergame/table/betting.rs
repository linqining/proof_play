use super::*;
use crate::pokergame::betting::BettingRound;

impl Table {
    /// 揭牌仪式（翻前底牌/公共牌/摊牌 reveal）期间拒绝下注动作：此时
    /// betting_round 是上一街的陈旧轮，validate_* 会用陈旧 current_bet
    /// 误判合法性并改写底池。process_action 入口已挡客户端路径，此处
    /// 兜底 auto/timeout 等进程内调用方。
    fn reject_during_reveal_ceremony(&self) -> bool {
        self.reveal_token_state.is_active()
    }

    /// betting 域权威路径（单一状态重构）：下注动作只经实时 VM dispatch
    /// （VM 规则 = min-raise/TDA/all-in/轮次完成的唯一裁判），成功后游戏
    /// 层从返回视图派生自己的下注状态；**拒绝后同样从 VM 当前状态重派生**
    ///（refresh_from_vm——dispatch 内可能已推进相位）。
    /// 无实时镜像 = 不可证明手 → fail-closed 直接拒绝（本地规则兜底路径
    /// 已随单一状态重构删除：规则引擎只保留 VM 一份）。

    pub fn handle_fold(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        if self.reject_during_reveal_ceremony() {
            return None;
        }
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        match self.vm_try_bet(pk.0.as_str(), "fold", None) {
            Some(Ok(view)) => {
                self.apply_betting_view(&view);
                if view.hand_over {
                    // 终局弃牌：VM 已在 dispatch 内派奖并复位（视图不再
                    // 携带 folded/total_bet）——游戏层在此确定性终结本手：
                    // 补上弃牌者标记（终局前账目 apply 已保留）→ fold-win
                    // 派奖 + on_hand_complete。此前依赖 driver 的
                    // unfolded≤1 推断，而 post-reset 视图让该推断永不成立
                    //（手牌卡死在无 turn 的 PreFlop，2026-09-14 探针实测）。
                    if let Some(seat) = self.local_seats.get_mut(&seat_id) {
                        seat.folded = true;
                        seat.has_acted = true;
                    }
                    self.end_without_showdown();
                } else {
                    self.set_betting_started_at(now_ms());
                }
                Some(ActionResult { seat_id, message: format!("{} folds", player_name) })
            }
            Some(Err(e)) => {
                self.refresh_from_vm();
                tracing::warn!("[betting-authority] table {} fold rejected by VM: {e}", self.summary.id);
                None
            }
            None => {
                tracing::warn!(
                    "[betting-authority] table {} fold rejected: no live VM mirror (unprovable hand, fail-closed)",
                    self.summary.id
                );
                None
            }
        }
    }

    pub fn handle_call(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        if self.reject_during_reveal_ceremony() {
            return None;
        }
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        // 消息用的跟注增量（派生视图上的纯展示计算，先于同步读取）。
        let added_to_pot = self.summary.call_amount.map(|ca| {
            if ca > seat.stack + seat.bet { seat.stack } else { ca.saturating_sub(seat.bet) }
        });
        match self.vm_try_bet(pk.0.as_str(), "call", None) {
            Some(Ok(view)) => {
                self.apply_betting_view(&view);
                self.set_betting_started_at(now_ms());
                let msg = match added_to_pot {
                    Some(a) => format!("{} calls ${:.2}", player_name, a),
                    None => format!("{} calls", player_name),
                };
                Some(ActionResult { seat_id, message: msg })
            }
            Some(Err(e)) => {
                self.refresh_from_vm();
                tracing::warn!("[betting-authority] table {} call rejected by VM: {e}", self.summary.id);
                None
            }
            None => {
                tracing::warn!(
                    "[betting-authority] table {} call rejected: no live VM mirror (unprovable hand, fail-closed)",
                    self.summary.id
                );
                None
            }
        }
    }

    pub fn handle_check(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        if self.reject_during_reveal_ceremony() {
            return None;
        }
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        match self.vm_try_bet(pk.0.as_str(), "check", None) {
            Some(Ok(view)) => {
                self.apply_betting_view(&view);
                self.set_betting_started_at(now_ms());
                Some(ActionResult { seat_id, message: format!("{} checks", player_name) })
            }
            Some(Err(e)) => {
                self.refresh_from_vm();
                tracing::warn!("[betting-authority] table {} check rejected by VM: {e}", self.summary.id);
                None
            }
            None => {
                tracing::warn!(
                    "[betting-authority] table {} check rejected: no live VM mirror (unprovable hand, fail-closed)",
                    self.summary.id
                );
                None
            }
        }
    }

    pub fn handle_raise(&mut self, pk: &GamePkHex, amount: u64) -> Option<ActionResult> {
        if self.reject_during_reveal_ceremony() {
            return None;
        }
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        // 加注目标低于本座已下注额属异常输入（正常由 UI 约束），直接拒绝。
        if amount <= seat.bet {
            return None;
        }
        match self.vm_try_bet(pk.0.as_str(), "raise", Some(amount)) {
            Some(Ok(view)) => {
                self.apply_betting_view(&view);
                self.set_betting_started_at(now_ms());
                Some(ActionResult { seat_id, message: format!("{} raises to ${:.2}", player_name, amount) })
            }
            Some(Err(e)) => {
                self.refresh_from_vm();
                tracing::warn!("[betting-authority] table {} raise rejected by VM: {e}", self.summary.id);
                None
            }
            None => {
                tracing::warn!(
                    "[betting-authority] table {} raise rejected: no live VM mirror (unprovable hand, fail-closed)",
                    self.summary.id
                );
                None
            }
        }
    }

    /// 把权威 VM 下注视图派生进游戏层：座位投入/筹码/弃牌/行动标记、
    /// 底池、call_amount、betting_round、行动指针——全部以 VM 为准。
    /// hand_over（VM 已在 dispatch 内终结本手——fold-win 派奖 + 复位）
    /// 时：**跳过全部座位同步**——post-reset 视图不携带终局事实
    /// （folded/total_bet 已被 VM 复位清零，照抄会把游戏层账本清成 0、
    /// 丢失弃牌者标记 → end_without_showdown 永不触发、对账基准归零，
    /// 2026-09-14 foldout 探针实测）；pot 取终局前底池（fold_win_pot）。
    pub(crate) fn apply_betting_view(&mut self, view: &crate::starknet::vm_session::BettingView) {
        let turn_seat: Option<u32> = view
            .current_turn_pk
            .as_ref()
            .and_then(|pk| self.pk_to_seat.get(&GamePkHex::new(pk.clone())).copied());
        if !view.hand_over {
            for vs in &view.seats {
                if vs.pk_hex.is_empty() {
                    continue;
                }
                let Some(seat_id) = self.pk_to_seat.get(&GamePkHex::new(vs.pk_hex.clone())).copied() else {
                    continue;
                };
                if let Some(seat) = self.local_seats.get_mut(&seat_id) {
                    seat.folded = vs.folded;
                    seat.bet = vs.bet;
                    seat.total_bet = vs.total_bet;
                    seat.stack = vs.stack;
                    seat.has_acted = vs.has_acted;
                    seat.turn = turn_seat == Some(seat_id);
                }
            }
            self.set_pot(view.pot + view.street_bets);
        } else if let Some(fwp) = view.fold_win_pot {
            // 终局前底池（游戏层派奖基数）；无 fold_win_pot 的 hand_over
            // （终局后的迟到刷新）不动 pot——游戏层账目已是权威。
            self.set_pot(fwp);
        }
        if view.in_betting {
            let cb = view.current_bet.unwrap_or(0);
            let mr = view.min_raise.unwrap_or(self.summary.min_bet * 2);
            if let Some(ref mut betting) = self.betting_round {
                betting.sync_from_vm(cb, mr);
            } else {
                let mut b = BettingRound::new(self.summary.min_bet * 2);
                b.sync_from_vm(cb, mr);
                self.betting_round = Some(b);
            }
            self.summary.call_amount = Some(cb);
        } else {
            self.betting_round = None;
            self.summary.call_amount = None;
        }
        self.set_turn(turn_seat);
        // 相位联锁：VM 已在下注轮完成时收集筹码并推进街道（dispatch 内
        // normalize），游戏层必须随之执行自己的发牌仪式（发下一街牌 +
        // 打开 reveal 窗口）——否则 VM 在窗口等 token、游戏层永远不发牌。
        // hand_over（fold-win）的收尾由 handle_fold 的终局分支驱动。
        if !view.in_betting && !view.hand_over {
            self.advance_to_next_phase();
        }
    }

    // ===== 本地规则兜底路径已随单一状态重构删除（fail-closed）：无实时
    // 镜像的不可证明手不接受下注动作，规则引擎只保留 VM 一份。=====

    pub fn handle_allin(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let stack = seat.stack;
        let bet = seat.bet;
        let call_amount = self.summary.call_amount.unwrap_or(0);

        if stack == 0 {
            return None; // nothing to all-in
        }

        let total_bet = bet + stack;
        if total_bet > call_amount {
            // All-in raise：对齐 Move raise，process_raise 会处理 all-in 逻辑
            self.handle_raise(pk, total_bet)
        } else {
            // All-in call：对齐 Move call，process_call 会 cap at stack
            self.handle_call(pk)
        }
    }

    pub fn add_to_pot(&mut self, amount: u64) {
        // New bets always go to self.pot, never to existing side_pots (B4 fix).
        // side_pots are only populated by calculate_side_pots() at end of round.
        self.set_pot(self.pot() + amount);
    }

    pub fn is_betting_round_complete(&self) -> bool {
        // 对齐 Move is_betting_complete：过滤 occupied && !folded && !all_in && !is_waiting
        // Rust 中 stack == 0 等价于 Move 的 all_in
        let active: Vec<&Seat> = self.local_seats.values()
            .filter(|s| !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0)
            .collect();
        if active.is_empty() {
            return true;
        }
        // Every active player must have acted at least once this round.
        // This prevents the BB's option from being skipped and ensures
        // that folds don't cause premature round completion.
        if active.iter().any(|s| !s.has_acted) {
            return false;
        }
        // All active players must have matched the current bet (or are all-in).
        if let Some(ref betting) = self.betting_round {
            let current_bet = betting.current_bet();
            for seat in &active {
                if seat.bet < current_bet {
                    return false;
                }
            }
        }
        true
    }

    pub fn check_betting_timeout(&mut self, timeout_secs: u64) -> Option<ActionResult> {
        // 对齐 Move：使用 summary.state.betting_started_at (u64 ms) 替代 Option<Instant>
        let timeout_start = self.betting_started_at();
        if timeout_start == 0 {
            return None;
        }
        let elapsed_ms = now_ms().saturating_sub(timeout_start);
        if elapsed_ms / 1000 < timeout_secs {
            return None;
        }
        let turn_seat_id = self.turn()?;
        // Extract only the needed info to avoid cloning the entire Seat
        let (folded, sitting_out, stack, pk_hex) = {
            let seat = self.local_seats.get(&turn_seat_id)?;
            (
                seat.folded,
                seat.sitting_out,
                seat.stack,
                seat.player.as_ref().map(|p| p.pk_hex.clone()),
            )
        };
        if folded || sitting_out || stack == 0 {
            // Turn is on a player who can't act — skip them and advance turn.
            // Return a special marker so the caller knows to re-advance.
            self.set_turn(self.next_unfolded_player(turn_seat_id, 1));
            self.set_betting_started_at(now_ms());
            let current_turn = self.turn();
            for i in 1..=self.max_players() {
                if let Some(seat) = self.local_seats.get_mut(&i) {
                    seat.turn = current_turn == Some(i);
                }
            }
            return None;
        }
        // 对齐 Move on_betting_timeout：超时一律 fold（Move 中不区分 needs_to_call）。
        // handle_fold 被 VM 拒绝（陈旧/错位镜像）时降级强吃 fold：超时代打
        // 必须收敛，否则每 8s 重试被拒 → 桌面永久卡死（2026-09-18 长跑
        // PreFlop 死锁）。镜像侧 force_fold 同步离场（无镜像跳过），游戏层
        // 标记弃牌并推进 turn，牌局继续（fold-win 结算路径不受影响）。
        let pk = pk_hex?;
        match self.handle_fold(&pk) {
            Some(res) => Some(res),
            None => {
                tracing::warn!(
                    "[betting-timeout] table {} seat {turn_seat_id}: fold rejected by VM — degrading to forced fold",
                    self.summary.id
                );
                if let Some(wallet) = self.players().get(&pk) {
                    self.vm_force_fold(&wallet.0);
                }
                if let Some(seat) = self.local_seats.get_mut(&turn_seat_id) {
                    seat.folded = true;
                    seat.has_acted = true;
                }
                self.set_turn(self.next_unfolded_player(turn_seat_id, 1));
                self.set_betting_started_at(now_ms());
                let current_turn = self.turn();
                for i in 1..=self.max_players() {
                    if let Some(seat) = self.local_seats.get_mut(&i) {
                        seat.turn = current_turn == Some(i);
                    }
                }
                Some(ActionResult {
                    seat_id: turn_seat_id,
                    message: "timeout forced fold (VM degraded path)".to_string(),
                })
            }
        }
    }
}
