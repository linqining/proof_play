use super::*;
use crate::pokergame::game_state::{
    PlayerRevealAssignment, RevealPhase, RevealTokenState, ShufflePhase,
};
use poker_protocol::crypto::ElGamalCiphertext;
use poker_protocol::z_poker::DealResult;

impl Table {
    /// 对齐 Move do_start_hand（table.move:850-870）：
    /// 仅 move_button + start_preflop_shuffle + advance_shuffle。
    /// 不在此处发牌（deal_preflop），发牌在洗牌完成后由 on_before_preflop_shuffle_complete 执行，
    /// 与 Move 一致（Move 的 deal_preflop 在 start_preflop_reveal_phase 中）。
    /// 盲注和下注轮在 on_reveal_complete(HandReveal) 中通过 set_blinds + init_turn + start_betting_round(true) 创建。
    pub fn start_hand(&mut self) {
        if self.round_state() != RoundState::Waiting {
            return;
        }
        // fail-closed：证明停用开关（TEXAS_SHADOW_PROVER=0）开启时不开局
        // ——不可证明的手不可玩（结算 fail-closed 的前置一致语义）。
        if !crate::starknet::vm_session::enabled() {
            tracing::warn!(
                "[start_hand] table {} shadow prover disabled — hand not started (fail-closed)",
                self.summary.id
            );
            return;
        }
        // 开局人数按"非 sitting_out 的在座玩家"计（含 is_waiting 的中途买入者）：
        // active_players() 会过滤 is_waiting，而 waiting 标记要到
        // start_preflop_shuffle 的 clear_waiting_flags 才清除——用前者判断
        // 会形成"waiting 玩家永远不算数 → 永不开局 → 标记永不清除"的死锁。
        let seated_ready = self
            .seats()
            .values()
            .filter(|s| s.player.is_some() && !s.sitting_out)
            .count();
        if (seated_ready as u32) < MIN_START_NUM {
            return;
        }

        // #18：标记本手动作日志窗口起点（审计摘要只覆盖本手）。
        self.hand_log_start = self.action_log.len();

        // 终局净结果与凭证用的本手快照：开局时间 / 各座位期初 stack /
        // 展示流水与摊牌牌型清零（上一手的数据已在 record_hand_history 落账）。
        self.summary.hand_started_at = now_ms();
        self.summary.actions = Vec::new();
        self.summary.showdown_hand_ranks = Vec::new();
        self.hand_start_stacks = self
            .local_seats
            .iter()
            .map(|(id, s)| (*id, s.stack))
            .collect();

        // 动作签名域 v2：开局分配本手 id（客户端经 shuffleState.hand_id
        // 获得，签名与服务端 verify_action_sig / 结算记账同源）。
        self.current_hand_id = crate::starknet::prove_log::next_hand_id(self.summary.id);

        // move_button
        self.move_button();

        // 初始化洗牌状态（对齐 Move start_preflop_shuffle + Rust 特有的玩家登记/清理）
        self.start_preflop_shuffle();

        // 推进洗牌流程（对齐 Move advance_shuffle）
        self.advance_shuffle();
    }

    /// Dead button 规则（Robert's Rules of Poker §4.2b）：按钮每手无条件
    /// 前进一个座位——落点允许是空座位 / sitting out 座位（该手为"死按钮"，
    /// 不承担 button 职责），**不**跳过任何座位。跳过会把过渡手的盲注轨道
    /// 整体前移，偏离标准语义。无按钮（新桌首手）时退回旧逻辑：从座位 1
    /// 起找第一个有人的座位。
    pub fn move_button(&mut self) {
        let max = self.max_players();
        let cur = self.button().unwrap_or(0);
        if cur == 0 {
            let mut next = 1;
            for _ in 0..max {
                if next > max {
                    next = 1;
                }
                if self.seats().contains_key(&next) {
                    self.set_button(Some(next));
                    return;
                }
                next += 1;
            }
            return;
        }
        let next = if cur >= max { 1 } else { cur + 1 };
        self.set_button(Some(next));
    }

    /// 对齐 Move start_preflop_shuffle（table.move:845-848）：
    /// 设置 phase=BeforePreflop + 初始化 pending_players。
    /// Rust 额外做玩家登记/清理（remove_inactive_players/register_waiting_players/clear_waiting_flags），
    /// 这些在 Move 中由 join/leave 时维护，Rust 在此统一处理。
    pub fn start_preflop_shuffle(&mut self) {
        // Rust 特有：清理不活跃玩家、登记 waiting 玩家、清除 waiting 标记，
        // 然后把仍未重连的断线玩家转为 sitting_out（局中断线只记
        // disconnected，筹码留在局内由超时 fold 收尾；此刻上手已结束，
        // 未归者不再参与下一手发牌——2026-09-08 断线重置手牌修复）。
        let removed = self.remove_inactive_players();
        if !removed.is_empty() {
            tracing::info!(
                "[SHUFFLE] hand start removed inactive players: {:?}",
                removed
            );
        }
        let mut newly_sitting_out = 0u32;
        for seat in self.local_seats.values_mut() {
            if seat.disconnected && !seat.sitting_out {
                seat.sitting_out = true;
                newly_sitting_out += 1;
            }
        }
        if newly_sitting_out > 0 {
            tracing::info!(
                "[SHUFFLE] {newly_sitting_out} disconnected player(s) moved to sitting_out for new hand"
            );
        }
        self.register_waiting_players();
        self.clear_waiting_flags();
        // 上一手被钉出的座位（计划外重连抖动；见 reveal.rs 盲注权威复核）
        // 在 socket 仍存活（未断线）时召回本手：正常参与发牌。玩家主动
        // 坐出（SITTING_OUT）不在钉出名单，不受影响（仍需显式 SITTING_IN）。
        if !self.hand_excluded_seats.is_empty() {
            let excluded = std::mem::take(&mut self.hand_excluded_seats);
            for seat_id in excluded {
                if let Some(seat) = self.local_seats.get_mut(&seat_id) {
                    if seat.player.is_some() && !seat.disconnected && seat.sitting_out {
                        seat.sitting_out = false;
                        tracing::info!(
                            "[SHUFFLE] seat {seat_id} returns from last hand's exclusion pin (socket alive)"
                        );
                    }
                }
            }
        }

        // 开局统一重建牌组基线 (G, m + agg)：
        // 1) register_waiting_players 之后 agg 才含全部本手玩家，必须用当前
        //    agg 重算基线（reset_for_next_hand 预置的是上一手的 agg）；
        // 2) 已注册玩家的密钥层由 +agg 预置包含 → 开局洗牌统一走纯 shuffle
        //    （re_encrypt 对 agg，明文保持、公钥恒 agg，物化 c2 − Σsk·c1 = m
        //    闭环）。禁止 remask 补层：对已注册玩家是重复加层，牌组公钥会
        //    超出 Σsk → 全桌 materialize 失败（2026-09-03 双真人线上复现）。
        // 3) 上一手残留层 / Waiting 期入座轮 / 孤儿密钥层（洗牌期买入者
        //    掉线，其份额永久缺失）全部归零 —— 每手重来，无需单独的孤儿
        //    重建分支。
        self.mental_poker_game.reset();
        self.shuffle_state.completed_players.clear();
        self.init_pending_players(&std::collections::HashSet::new());

        // 对齐 Move：phase = BeforePreflop
        self.shuffle_state.phase = ShufflePhase::BeforePreflop;
        self.shuffle_state.timeout_seconds = 45;
        self.shuffle_state.hand_id = self.current_hand_id;
    }

    /// 对齐 Move：BeforePreflop 洗牌完成后发牌（在 advance_shuffle 中调用）。
    /// 等价于原 start_hand 的发牌部分：reset board/pot/bets + unfold + deal_preflop。
    pub fn on_before_preflop_shuffle_complete(&mut self) {
        self.summary.went_to_showdown = false;
        self.reset_board_and_pot();
        self.reset_bets_and_actions();
        self.unfold_players();
        self.summary.history = vec![];
        if self.active_players().len() > 1 {
            self.deal_preflop();
            self.summary.hand_over = false;
        }

        self.update_history();
    }

    pub fn unfold_players(&mut self) {
        for seat in self.local_seats.values_mut() {
            seat.folded = seat.sitting_out;
            seat.total_bet = 0;
        }
    }

    /// Dead button 盲注定位（镜像 poker_l1 post_blinds，§4.2b）：
    /// - **大盲**：上一手大盲座位（`last_bb_seat`；首手退化为 button）之后
    ///   顺时针第一个参与座位（active = 在座且非 sitting out / 非等待入局）。
    ///   轮转永不跳人、永不重复——无人连续两手交大盲。
    /// - **小盲（非单挑）**：上一手大盲座位本身；该座位已不参与本手
    ///   （离场/sitting out/等待）时，**由其前驱参与者补位小盲**——
    ///   见 [`Table::set_blinds`] 的回退说明。
    /// - **单挑（2 名参与者）**：大盲按轮转归属，小盲 = 大盲之外另一参与
    ///   玩家（承担 button 职责：翻牌前先行动、翻牌后后行动）。
    ///
    /// 首行动作（UTG）= 大盲之后第一个可行动座位（翻牌前；单挑时该扫描
    /// 恰好落在小盲身上，与真实规则一致；小盲 all-in 时顺延到大盲）。
    pub fn set_blinds(&mut self) {
        let is_heads_up = self.active_players().len() == 2;
        let button = self.button().unwrap_or(1);
        let last_bb = self.last_bb_seat();
        let has_rotation_history = last_bb > 0 && last_bb <= self.max_players();
        let mut rotation_base = if has_rotation_history {
            last_bb
        } else {
            button
        };
        // 上一手大盲座位已不参与本手时，轮转基准回退到其前驱参与者
        //（环形）。这与镜像 prove_log::rank_of_rotation_base 的压缩 rank
        // 映射逐位一致：镜像座位空间没有空座，空基准必然落在前驱参与者
        // 的 rank 上（小盲由其承担、大盲落点不变）。Robert's Rules 的
        // dead small blind（空座不补位、本手无小盲）在压缩镜像空间不可
        // 表达——为保证游戏层与镜像（结算 witness 唯一来源）的资金状态
        // 逐位一致，游戏层采用镜像可表达的同一语义。
        // button 回退路径（无盲注轨道历史的首手）不在本回退范围内。
        if has_rotation_history && !self.rotation_base_participating(rotation_base) {
            rotation_base = self
                .predecessor_participant(rotation_base)
                .unwrap_or(rotation_base);
        }
        // 大盲：轮转基准之后第一个参与座位。
        let bb = self
            .next_active_player(rotation_base, 1)
            .unwrap_or(rotation_base);
        // 小盲：单挑 = 大盲之外另一参与者；非单挑 = 轮转基准座位本身
        //（参与且 != 大盲时；基准已回退到前驱参与者，此时必参与）。
        let sb = if is_heads_up {
            self.next_active_player(bb, 1).or(Some(bb))
        } else if rotation_base != bb {
            let base_participating = self
                .seats()
                .get(&rotation_base)
                .map(|s| !s.sitting_out && !s.is_waiting)
                .unwrap_or(false);
            if base_participating {
                Some(rotation_base)
            } else {
                None
            }
        } else {
            None
        };
        // 盲注轨道落点：本手大盲座位成为下一手的轮转基准（跨手持久）。
        self.set_last_bb_seat(Some(bb));

        let mut sb_amount: u64 = 0;
        let mut bb_amount: u64 = 0;

        if let Some(sb) = sb {
            if let Some(seat) = self.local_seats.get_mut(&sb) {
                let actual_sb = seat.place_blind(self.summary.min_bet);
                sb_amount = actual_sb;
            }
        }
        if let Some(seat) = self.local_seats.get_mut(&bb) {
            let actual_bb = seat.place_blind(self.summary.min_bet * 2);
            bb_amount = actual_bb;
        }

        self.set_pot(self.pot() + sb_amount + bb_amount);
        self.summary.call_amount = Some(self.summary.min_bet * 2);
        self.set_min_raise(self.summary.min_bet * 2); // = big_blind; minimum re-raise equals the big blind
        self.set_small_blind(sb);
        self.set_big_blind(Some(bb));

        // 对齐 Move post_blinds：设置首行动作
        // UTG = 大盲之后第一个可行动座位（next_unfolded 跳过 all-in /
        // folded / sitting out / waiting）。单挑时该座位即小盲（小盲
        // all-in 时顺延到大盲，与原 sb_all_in 特例等价）。
        // C5 修复扩展：盲注后可能全员 all-in，需要检查是否有可行动玩家
        if self.has_actionable_player() {
            let first_to_act = self.next_unfolded_player(bb, 1);
            self.set_turn(first_to_act);
        } else {
            // 全员 all-in，不设置 turn，start_betting_round 会跳过下注轮
            self.set_turn(None);
        }
    }

    /// 轮转基准座位是否参与本手。与 prove_log 手牌计划的参与者过滤严格
    /// 一致：在座玩家且非 sitting out / 非等待入局。
    fn rotation_base_participating(&self, seat_id: u32) -> bool {
        self.seats()
            .get(&seat_id)
            .is_some_and(|s| s.player.is_some() && !s.sitting_out && !s.is_waiting)
    }

    /// 轮转基准的前驱参与者（环形）：座位号小于 base 的最大参与者座位；
    /// 不存在（base 低于全部参与者座位号）时环绕到全局最大参与者座位。
    /// 与镜像 prove_log::rank_of_rotation_base 的压缩 rank 映射
    ///（`rposition(seat_id <= base)` / 环绕 `len-1`）逐位一致。
    fn predecessor_participant(&self, base: u32) -> Option<u32> {
        let mut ids: Vec<u32> = self
            .seats()
            .iter()
            .filter(|(_, s)| s.player.is_some() && !s.sitting_out && !s.is_waiting)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids.iter()
            .rev()
            .find(|id| **id < base)
            .copied()
            .or_else(|| ids.last().copied())
    }

    /// Set blinds using on-chain values (from BlindsPosted event).
    /// Unlike set_blinds which calculates positions/amounts, this directly
    /// uses the values from the chain event. Used when BlindsPosted event
    /// drives the off-chain state.
    pub fn deal_preflop(&mut self) {
        // 升序座位、每座连发 2 张（对齐 poker_l1 VM DealHole 的 canonical
        // 顺序：per-seat 连续 card_slot，deck index 升序）。deck 已被客户端
        // 洗牌随机化，发牌顺序不影响公平性；该顺序保证 deck index → 玩家
        // 的映射与 mirror VM 逐字节一致（结算对拍前提）。
        let mut order: Vec<u32> = self.local_seats.keys().copied().collect();
        order.sort_unstable();

        // 诊断：聚合钥 vs 玩家公钥和（重入场景 double-count 检测）
        {
            let agg = self.mental_poker_game.key_manager.get_aggregated_pk();
            let sum = self
                .mental_poker_game
                .players
                .values()
                .fold(poker_protocol::crypto::EcPoint::identity(), |acc, p| {
                    acc + p.pk
                });
            let players_cnt = self.mental_poker_game.players.len();
            let key_cnt = self.mental_poker_game.key_manager.player_count();
            tracing::warn!(
                "[deal-diag] players={} key_entries={} agg_eq_sum={}",
                players_cnt,
                key_cnt,
                ecpoint_to_hex(&agg) == ecpoint_to_hex(&sum)
            );
            if ecpoint_to_hex(&agg) != ecpoint_to_hex(&sum) {
                tracing::error!(
                    "[deal-diag] agg={} sum={} (MISMATCH → deck 不变量破坏，公共牌/手牌将无法解密)",
                    poker_protocol::z_poker::convert::ecpoint_to_hex(&agg),
                    poker_protocol::z_poker::convert::ecpoint_to_hex(&sum)
                );
            }
        }

        for &seat_id in &order {
            let is_turn = self.turn() == Some(seat_id);
            if let Some(seat) = self.local_seats.get_mut(&seat_id) {
                if let Some(player) = &seat.player {
                    if !seat.sitting_out {
                        // 未注册进本手 mental_poker（bust 后重进/换 pk，洗牌
                        // 未轮到）→ 本手无牌可发，等下一手洗牌注册归队。安静
                        // 跳过（此前 ERROR 日志实为预期路径）。
                        if !self
                            .mental_poker_game
                            .players
                            .contains_key(player.pk_hex.as_str())
                        {
                            tracing::warn!(
                                "player {} (pk {}) seated but not registered in this hand's shuffle — no deal this hand, waits for next shuffle",
                                player.name,
                                player.pk_hex
                            );
                        } else if let Err(e) = self
                            .mental_poker_game
                            .deal_to_player(&player.pk_hex.clone(), 2)
                        {
                            tracing::error!(
                                "[deal_preflop] deal_to_player failed for player {} seat {}: {:?}",
                                player.name,
                                seat_id,
                                e
                            );
                        }
                        seat.turn = is_turn;
                    } else {
                        tracing::info!("player {} is sitting out,no deal", player.name);
                    }
                }
            }
        }
    }

    /// 镜像 L1 restart_reveal_after_reconstruct 的公共牌补发：
    /// 未揭示的旧牌废弃（其密钥层缺失、不可解），从新 deck 游标位置 0 顺序
    /// 重发缺失张数。游标账目：note_deck_reconstructed 的 offset 基线包含被
    /// 废弃的旧牌，协议游标在重发后停留在新纪元 0；哨兵 DealResult 把本次
    /// 消费补回，使后续 deal/redeal 的游标与 L1 cards_dealt 逐位对齐。
    pub fn mirror_restart_community_redeal(&mut self) {
        let street_target: usize = match self.round_state() {
            RoundState::Flop => 3,
            RoundState::Turn => 4,
            RoundState::River => 5,
            _ => return,
        };
        let revealed = self
            .mental_poker_game
            .community_cards_encrypted
            .iter()
            .filter(|c| c.playing_card.is_some())
            .count();
        let missing = street_target.saturating_sub(revealed);
        if missing == 0 {
            return;
        }
        self.mental_poker_game
            .community_cards_encrypted
            .retain(|c| c.playing_card.is_some());
        let fresh = self
            .mental_poker_game
            .deal_community_cards_encrypted(missing);
        for ct in &fresh {
            self.mental_poker_game.deal_results.push(DealResult {
                player_pk: "__restart__".to_string(),
                encrypted_cards: vec![ct.clone()],
            });
        }
        tracing::info!(
            "[RECONSTRUCT] restart re-dealt {missing} community card(s) from the new deck era (deal cursor aligned with L1 cards_dealt)"
        );
    }

    pub fn deal_flop(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(3);
    }

    pub fn deal_turn_or_river(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(1);
    }

    /// 为解密失败的玩家重新发牌（不验证 plaintext，信任客户端报告）。
    ///
    /// 方案 A（换牌进证明轨迹）：换牌先过 VM 权威门——L1 `redeal_hole_card`
    /// 校验"下注轮 + caller 即持有者 + 账本条目存在 + deck 未耗尽"后挂起下注
    /// 轮、开启 Redealing 令牌窗口；随后游戏层做协议级换牌，并对两层发牌
    /// 游标做逐字节对齐校验（不一致 = 镜像已失配，fail-closed 中止本手）。
    /// 无实时镜像 = fail-closed 拒绝（不可证明的换牌会让整手结算失去依据）。
    /// 返回重新发的牌索引列表
    pub fn redeal_cards_for_player(
        &mut self,
        player_pk: &GamePkHex,
        failed_indices: Vec<usize>,
    ) -> Result<Vec<usize>, String> {
        if !self.mental_poker_game.players.contains_key(&**player_pk) {
            return Err("Player not found".to_string());
        }

        let mut redealt = Vec::new();
        for idx in failed_indices {
            // 手牌槽位宽度守卫（德扑 = 2）：客户端报的索引即手牌槽位。
            if idx >= self.mental_poker_game.config.cards_per_player {
                tracing::warn!(
                    "Redeal slot {} outside hole-card width for {}",
                    idx,
                    player_pk
                );
                continue;
            }
            // 1) VM 侧将消费的卡（L1 cards_dealt 游标位）。
            let (l1_index, l1_ct) = match self.vm_peek_redeal_card() {
                Some(Ok(pair)) => pair,
                Some(Err(e)) => return Err(format!("redeal rejected by VM: {e}")),
                None => return Err("redeal rejected: hand has no live VM mirror".to_string()),
            };
            // 2) L1 权威换牌：挂起下注轮 + 开 Redealing 窗口（进证明轨迹）。
            match self.vm_try_redeal(&**player_pk, idx as u8) {
                Some(Ok(())) => {}
                Some(Err(e)) => return Err(format!("redeal rejected by VM: {e}")),
                None => return Err("redeal rejected: hand has no live VM mirror".to_string()),
            }
            // 3) 协议级换牌：从游戏层 deck 游标取新牌、重置 reveal_state。
            let game_ct = match self
                .mental_poker_game
                .redeal_to_player_unchecked(&**player_pk, idx)
            {
                Ok(ct) => ct,
                Err(e) => {
                    tracing::error!(
                        "Redeal failed for player {} slot {}: {:?}",
                        player_pk,
                        idx,
                        e
                    );
                    return Err(format!("Redeal failed for slot {idx}: {e:?}"));
                }
            };
            // 4) 两层对齐校验：游戏层换入的密文必须与 L1 换入的逐字节一致。
            if game_ct != l1_ct {
                tracing::error!(
                    "[REDEAL] deck cursor divergence: l1_index={} game_ct={} l1_ct={}",
                    l1_index,
                    hex::encode(game_ct.c2.compress().as_ref())
                        .get(..24)
                        .unwrap_or(""),
                    hex::encode(l1_ct.c2.compress().as_ref())
                        .get(..24)
                        .unwrap_or(""),
                );
                // fail-closed：镜像已失配，本手不可证明——全额退款中止。
                self.refund_all_bets();
                self.reset_for_next_hand();
                self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
                    message: Some("牌局已中止：换牌游标失配，本手下注已全额退还".to_string()),
                });
                return Err("redeal deck cursor divergence; hand aborted".to_string());
            }
            tracing::info!(
                "Redealt card at slot {} for player {} (deck index {} traced by VM)",
                idx,
                player_pk,
                l1_index
            );
            redealt.push(idx);
        }

        Ok(redealt)
    }

    /// 启动 redeal reveal 阶段，为换入的新牌收集所有玩家的 reveal token
    /// 不改变 round_state，保持当前街，通过 reveal_token_state 追踪 redeal 进度。
    ///
    /// assignment 只覆盖**换掉的牌**（对齐 L1 Redealing 窗口的单 assignment 形态）：
    /// 未换的旧牌上已有他人 HandReveal 份额，再次出份额会在协议层重复累加，
    /// 摊牌物化明文必错——2026-10-01 redeal 缺口修复的一部分。
    pub fn start_redeal_reveal_phase(
        &mut self,
        redealt_player_pk: &GamePkHex,
        redealt_indices: Vec<usize>,
    ) {
        if self.reveal_token_state.is_active() {
            return;
        }

        let player_pks = self
            .mental_poker_game
            .players
            .keys()
            .cloned()
            .collect::<Vec<String>>();
        let mut player_assignments = HashMap::new();

        // 只需要为重新发牌的玩家收集 reveal token，其他玩家需要为新牌生成 token
        if let Some(player) = self.mental_poker_game.players.get(&**redealt_player_pk) {
            let redealt_cards: Vec<ElGamalCiphertext> = player
                .hand_encrypted
                .iter()
                .enumerate()
                .filter(|(slot, _)| redealt_indices.contains(slot))
                .map(|(_, c)| c.encrypted_card.clone())
                .collect();
            for pk in &player_pks {
                if pk == &**redealt_player_pk {
                    continue;
                }
                player_assignments.insert(
                    GamePkHex::new(pk.clone()),
                    PlayerRevealAssignment {
                        hand_card: redealt_cards.clone(),
                        community_card: vec![],
                    },
                );
            }
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::RedealReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 0,
            timeout_start: Some(std::time::Instant::now()),
            last_notice_at: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks
                .iter()
                .filter(|pk| *pk != &**redealt_player_pk)
                .map(|pk| GamePkHex::new(pk.clone()))
                .collect(),
            player_assignments,
        };

        tracing::info!(
            "[REDEAL] Redeal reveal phase started for player {}, {} pending",
            redealt_player_pk,
            self.reveal_token_state.pending_players.len()
        );
    }

    // 相当于原来的deal_next_street
    pub fn advance_to_next_phase(&mut self) {
        // 对齐 Move advance_round：仅重置下注 + 推进阶段，不计算边池。
        // 边池仅在 showdown 时由 on_reveal_complete(ShowdownReveal) → calculate_side_pots 计算。
        self.reset_bets_and_actions();
        match self.round_state() {
            RoundState::PreFlop => {
                // deal three community card
                self.deal_flop();
                // start reveal community card
                self.transition_to(RoundState::Flop);
                self.start_community_reveal_phase();
            }
            RoundState::Flop => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::Turn);
                self.start_community_reveal_phase();
            }
            RoundState::Turn => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::River);
                self.start_community_reveal_phase();
            }
            RoundState::River => {
                self.transition_to(RoundState::Showdown);
                self.start_showdown_reveal_phase();
            }
            _ => {
                tracing::warn!(
                    "[advance_to_next_phase] unexpected round state: {:?}",
                    self.round_state()
                );
            }
        }
        self.update_history();
    }
}
