use super::*;
use crate::pokergame::game_state::ShufflePhase;
use crate::pokergame::player::truncate_name;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;

/// 验证后从生产域 transcript squeeze 展示用全局挑战（hex）。
///
/// V2 的 Fiat-Shamir 挑战散布在协议各阶段（`bg12_*` label），无单一
/// "global challenge" 字段；此处对**验证完成后的完整 transcript 状态**
/// 取一次确定性摘要——G2「global_challenge」行的数据源（同一证明恒同值，
/// 绑定全部语句与承诺）。
fn squeeze_display_challenge(transcript: &mut PoseidonFeltTranscript) -> Option<String> {
    use poker_protocol_core::CryptoTranscript as _;
    let challenge = transcript
        .challenge::<poker_protocol::crypto::DefaultCurve>(b"bg12_global_challenge")
        .scalar;
    Some(poker_protocol::z_poker::convert::scalar_to_hex(&challenge))
}

impl Table {
    pub fn is_all_players_shuffled(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn is_pending_shuffle_player_empty(&self) -> bool {
        self.shuffle_state.pending_players.is_empty()
    }

    pub fn complete_shuffle_player_count(&self) -> usize {
        self.shuffle_state.completed_players.len()
    }

    /// 对齐 Move do_start_hand → start_preflop_shuffle：启动 BeforePreflop 洗牌。
    /// 实际逻辑已移至 `start_preflop_shuffle`（phases.rs），由 `start_hand` 调用。
    /// 此处保留入口供 game_loop 直接调用（等价于 Move tick → do_start_hand）。
    pub fn start_shuffle(&mut self) -> Result<(), String> {
        if self.shuffle_state.is_active() {
            return Ok(());
        }
        self.start_hand();
        Ok(())
    }

    /// 清理不在活跃座位的 mental poker 注册（断线/离开玩家）。
    /// 返回本次实际移除的 pk —— 调用方（start_preflop_shuffle）据此检测
    /// 孤儿密钥层：被移除者若已贡献洗牌层，牌组必须重建基线全员重洗。
    pub fn remove_inactive_players(&mut self) -> Vec<GamePkHex> {
        let active_pks: std::collections::HashSet<String> = self
            .active_players()
            .iter()
            .filter_map(|p| p.player.as_ref())
            .map(|p| p.pk_hex.0.clone())
            .collect();

        let remove_pks: Vec<GamePkHex> = self
            .mental_poker_game
            .players
            .iter()
            .filter(|(_, player_state)| !active_pks.contains(&player_state.pk_hex))
            .map(|(_, player_state)| GamePkHex::new(player_state.pk_hex.clone()))
            .collect();

        for pk in &remove_pks {
            let _ = self.mental_poker_game.leave_player(&pk);
        }
        remove_pks
    }

    pub fn register_waiting_players(&mut self) {
        let active_pk_hexs: std::collections::HashSet<String> = self
            .seats()
            .values()
            .filter_map(|seat| seat.player.as_ref())
            .map(|player| player.pk_hex.0.clone())
            .collect();

        let waiting_players_to_register: Vec<(GamePkHex, PlayerWithProof)> = self
            .waiting_players
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (pk_hex, waiting_info) in waiting_players_to_register {
            if active_pk_hexs.contains(&pk_hex.to_string()) {
                self.mental_poker_game.register_player(
                    pk_hex.to_string(),
                    waiting_info.pk,
                    waiting_info.pk_proof,
                );
                tracing::info!(
                    "[SHUFFLE] Waiting player {} registered to mental_poker_game",
                    pk_hex
                );
            } else {
                tracing::info!(
                    "[SHUFFLE] Waiting player {} left the table, skipping registration",
                    pk_hex
                );
            }
        }
        self.waiting_players.clear();
    }

    pub fn clear_waiting_flags(&mut self) {
        for seat in self.local_seats.values_mut() {
            if seat.is_waiting {
                seat.is_waiting = false;
                if let Some(player) = &seat.player {
                    tracing::info!(
                        "[SHUFFLE] Player {} is_waiting cleared, registered to shuffle",
                        player.pk_hex
                    );
                }
            }
        }
    }

    pub fn init_pending_players(
        &mut self,
        already_completed: &std::collections::HashSet<GamePkHex>,
    ) {
        // todo sitting_out 回来的玩家再加入洗牌(假如在洗牌阶段)
        self.shuffle_state.pending_players = self
            .mental_poker_game
            .players
            .keys()
            .map(|k| GamePkHex::new(k.clone()))
            .filter(|pk| !already_completed.contains(pk))
            .collect();
        tracing::info!(
            "[SHUFFLE] Init pending players: {:?}",
            self.shuffle_state.pending_players
        );
        // G8 修复：原 else if 分支不可达（pending 非空时 first() 必返回 Some）。
        // 将"所有玩家已完成洗牌则跳过"的逻辑移到 is_empty 分支内。
        if self.shuffle_state.pending_players.is_empty() {
            if self.complete_shuffle_player_count() >= MIN_START_NUM as usize {
                self.shuffle_state.phase = ShufflePhase::None;
                tracing::info!("[SHUFFLE] All players already completed shuffle, skipping");
            } else {
                tracing::warn!("[SHUFFLE] Init pending players is empty");
            }
            return;
        }
        if let Some(first_pk) = self.shuffle_state.pending_players.first() {
            self.set_current_shuffler(first_pk.clone());
        }
    }

    pub fn set_current_shuffler(&mut self, player_pk: GamePkHex) {
        self.shuffle_state.current_player_pk = Some(player_pk.clone());
        self.shuffle_state.timeout_start = Some(std::time::Instant::now());
        tracing::info!(
            "[SHUFFLE] Now waiting for player {} to shuffle (timeout: {}s)",
            player_pk,
            self.shuffle_state.timeout_seconds
        );
    }

    pub fn check_shuffle_timeout(&mut self) -> Option<GamePkHex> {
        if !self.shuffle_state.is_active() {
            return None;
        }
        let timeout_start = match self.shuffle_state.timeout_start {
            Some(t) => t,
            None => return None,
        };
        if timeout_start.elapsed().as_secs() >= self.shuffle_state.timeout_seconds {
            let timed_out_pk = self.shuffle_state.current_player_pk.clone()?;
            tracing::warn!(
                "[SHUFFLE] Player {} timed out after {}s!",
                timed_out_pk,
                self.shuffle_state.timeout_seconds
            );
            Some(timed_out_pk)
        } else {
            None
        }
    }

    /// 入座双模式（对齐 texas_poker_move main：join_and_shuffle / join）：
    /// - `round_json = Some` 且牌桌处于 Waiting/Shuffle 阶段 → 边买入边洗牌
    ///   （验证 remask + shuffle 证明后应用牌组层）；
    /// - `round_json = None`，或牌局进行中提交（服务端权威降级）→ 不动牌组，
    ///   以 waiting 身份入座，`reset_for_next_hand` 后在下一手参与洗牌。
    /// 牌局中绝不用客户端提交的轮次替换牌组——在场玩家会解不出手牌。
    pub fn join_player_and_shuffle(
        &mut self,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: Option<MaskAndShuffleRoundJson>,
        seat_id: u32,
        amount: u64,
    ) -> Result<JoinResult, JoinError> {
        let pk_hex = ecpoint_to_hex(&player_pk);

        if self
            .seats()
            .values()
            .any(|seat| seat.player.as_ref().map_or(false, |p| p.pk_hex.0 == pk_hex))
        {
            tracing::info!("Player {} is already in game", pk_hex);
            return Err(JoinError::PlayerAlreadyInGame);
        }

        let actual_seat_id = if seat_id == 0 {
            self.find_random_empty_seat()
                .ok_or(JoinError::InvalidSeatId)?
        } else {
            if seat_id < 1 || seat_id > self.max_players() {
                return Err(JoinError::InvalidSeatId);
            }
            if self.seats().contains_key(&seat_id) {
                return Err(JoinError::SeatAlreadyOccupied);
            }
            seat_id
        };

        // Waiting/Shuffling 阶段玩家可以加入游戏并洗牌
        // ShuffleComplete 及之后阶段，玩家只能等待下一手加入
        let is_join_before_start =
            self.round_state() == RoundState::Waiting || self.shuffle_state.is_active();

        let pk_proof = pk_proof_json.to_proof().map_err(|e| JoinError::Crypto(e))?;
        if !pk_proof.verify(&player_pk) {
            return Err(JoinError::InvalidPkProof);
        }
        tracing::info!(
            "[SHUFFLE] Player {} joined and shuffled, sat at seat {}, round state {:?}",
            pk_hex,
            actual_seat_id,
            self.round_state()
        );
        let player_for_seat = GamePlayer {
            name: truncate_name(&player.name, 12),
            bankroll: player.bankroll,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: player.wallet_address.clone(),
        };

        let wants_shuffle = is_join_before_start && round_json.is_some();
        if wants_shuffle {
            let round_json = round_json.expect("checked above");
            let shuffle_proof_json = round_json.shuffle_proof.clone();
            let round = round_json
                .to_mask_and_shuffle_round()
                .map_err(|e| JoinError::Crypto(e))?;
            // 2026-09 Poseidon epoch：remask + shuffle 共享生产域 transcript。
            let mut transcript = PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::MASK_SHUFFLE_V2_POSEIDON,
            );
            let input_cards = self
                .mental_poker_game
                .deck_encrypted
                .iter()
                .map(|c| c.clone())
                .collect::<Vec<_>>();
            if !round.remask_proof.verify(
                &input_cards,
                &round
                    .mask_cards
                    .iter()
                    .map(|c| c.clone())
                    .collect::<Vec<_>>(),
                &player_pk,
                &mut transcript,
            ) {
                return Err(JoinError::InvalidRemaskProof);
            }

            let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
            let share_pk = current_agg_pk + &player_pk;
            if round
                .proof
                .verify(
                    &round
                        .mask_cards
                        .iter()
                        .map(|c| c.clone())
                        .collect::<Vec<_>>(),
                    &round
                        .output_cards
                        .iter()
                        .map(|c| c.clone())
                        .collect::<Vec<_>>(),
                    &share_pk,
                    &mut transcript,
                )
                .is_err()
            {
                return Err(JoinError::InvalidShuffleProof);
            }

            let pk_hex_game = GamePkHex::new(pk_hex.clone());
            self.mental_poker_game
                .register_player(pk_hex.clone(), player_pk, pk_proof);
            // D1 留存需要输出牌组快照（deck 所有权随后移交给 mental_poker_game）。
            let deck_for_ledger = round.output_cards.clone();
            self.mental_poker_game.deck_encrypted = round.output_cards;
            let _ = self.add_player(
                GamePkHex::new(pk_hex.clone()),
                player.wallet_address.clone(),
            );
            let _ = self.sit_player(player_for_seat, actual_seat_id, amount, false);
            // D1 证明通道：join 洗牌层留存（须在 sit_player 之后——座位映射
            // 已落定；current_hand_id 为上一手/0 时进 pending 桶，开局创建
            // 本手条目时收编）。
            let global_challenge = squeeze_display_challenge(&mut transcript);
            self.record_shuffle_proof_layer(
                &pk_hex,
                &shuffle_proof_json,
                &deck_for_ledger,
                global_challenge,
            );

            if self.round_state() == RoundState::Waiting {
                self.shuffle_state
                    .completed_players
                    .push(pk_hex_game.clone());
                self.shuffle_state
                    .pending_players
                    .retain(|p| *p != pk_hex_game);
            }
            tracing::info!(
                "[SHUFFLE] Player {} joined and shuffled, sat at seat {}",
                pk_hex,
                actual_seat_id
            );
            Ok(JoinResult::JoinedAndShuffled)
        } else {
            // waiting 入座：牌局中买入的降级路径，或客户端显式选择不洗牌。
            self.waiting_players.insert(
                GamePkHex::new(pk_hex.clone()),
                PlayerWithProof {
                    pk: player_pk,
                    pk_proof,
                },
            );
            let _ = self.add_player(
                GamePkHex::new(pk_hex.clone()),
                player.wallet_address.clone(),
            );
            let _ = self.sit_player(player_for_seat, actual_seat_id, amount, true);
            tracing::info!(
                "[SHUFFLE] Player {} joined as waiting, sat at seat {}, will join next hand roundState{:?}",
                pk_hex,
                actual_seat_id,
                self.round_state()
            );
            Ok(JoinResult::JoinedWaiting)
        }
    }

    pub fn submit_verified_shuffle(
        &mut self,
        player_pk_hex: &GamePkHex,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: ShuffleProofJson,
    ) -> Result<(), String> {
        if !self.shuffle_state.is_active() {
            return Err("Shuffle not active".to_string());
        }
        if self.shuffle_state.current_player_pk != Some(player_pk_hex.clone()) {
            return Err("Not current player".to_string());
        }

        let _ = self
            .mental_poker_game
            .players
            .get(&**player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        let output_cards = output_cards
            .iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let proof = shuffle_proof.to_proof()?;
        let current_agg_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let input_cards = self.mental_poker_game.deck_encrypted.clone();
        // 2026-09 Poseidon epoch：Bayer--Groth V2 生产域 transcript。
        let mut transcript = PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
        );
        if proof
            .verify(
                &input_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
                &output_cards.iter().map(|c| c.clone()).collect::<Vec<_>>(),
                &current_agg_pk,
                &mut transcript,
            )
            .is_err()
        {
            return Err("Invalid shuffle proof".to_string());
        }
        // 方案A（重构后重洗进轨迹）：Reconstruct 相位的洗牌逐份 dispatch 到镜像
        // ——L1 对其重建牌组验证 BG 证明，同时天然校验两层重建 deck 的逐字节
        // 一致性（客户端证明生成自游戏层牌组，失配即被拒）。开局（BeforePreflop）
        // 洗牌不经 dispatch：镜像在 record_hand_start 时注入终局 deck。
        if self.shuffle_state.phase == ShufflePhase::Reconstruct {
            match self.vm_try_submit_shuffle(player_pk_hex, output_cards.clone(), proof.clone()) {
                Some(Ok(())) => {}
                Some(Err(e)) => return Err(format!("shuffle rejected by VM: {e}")),
                None => return Err("shuffle rejected: hand has no live VM mirror".to_string()),
            }
        }
        // D1 证明通道：验证成功即留存（V2 顺手 squeeze 全局挑战——完整
        // transcript 状态的确定性摘要，非协议独立字段）。
        let global_challenge = squeeze_display_challenge(&mut transcript);
        self.record_shuffle_proof_layer(
            player_pk_hex,
            &shuffle_proof,
            &output_cards,
            global_challenge,
        );
        self.mental_poker_game.deck_encrypted = output_cards;
        self.shuffle_state
            .completed_players
            .push(player_pk_hex.clone());
        self.shuffle_state
            .pending_players
            .retain(|p| p != player_pk_hex);
        Ok(())
    }

    /// 开手洗牌的 join 语义提交（waiting 入座玩家补层专用）。
    ///
    /// 背景：waiting 入座（plain join）的玩家从未把自己的密钥层加进牌组链，
    /// 开手时若只用 ClientPlayer::shuffle（纯 re_encrypt）补洗，牌组密文的
    /// 份额与全员公钥和对不上 → 全桌 decrypt_readable_card 失败、手牌无法
    /// 显示（2026-09-01 线上复现，texas e2e_mixed_join_paths_materializes）。
    /// 本方法要求提交 MaskAndShuffleRound（remask 自身层 + shuffle），
    /// remask 证明对 (当前牌组, player_pk) 验证，shuffle 证明对全量聚合公钥
    /// 验证（此时玩家已注册，agg 已含自身，等价于 join 的 agg_prev + pk）。
    pub fn submit_join_shuffle(
        &mut self,
        player_pk_hex: &GamePkHex,
        round: crate::pokergame::game_state::MaskAndShuffleRoundJson,
    ) -> Result<(), String> {
        // 2026-09-03 废弃开局补层（remask）语义：已注册玩家的密钥层由每手
        // start_preflop_shuffle 的 (G, m+agg) 基线预置包含，remask 是重复
        // 加层 → 牌组公钥超出 Σsk → 全桌 materialize 失败（双真人线上复现，
        // 诊断日志 tokens=registeredPlayers 且全牌组物化失败）。
        // 开局洗牌请走 submit_verified_shuffle（纯 shuffle 对 agg）。
        // 入座场景（未注册玩家）仍走 join_player_and_shuffle，不经此入口。
        // 保留函数与错误返回：旧客户端开局提交 join 轮时给出可诊断的错误
        // 而非静默污染牌组。
        let _ = (
            &self.mental_poker_game.deck_encrypted,
            player_pk_hex,
            &round,
        );
        Err(
            "join layer not needed at hand start: registered players' layers are pre-seeded in the deck baseline; submit a pure shuffle (shuffle_proof only)"
                .to_string(),
        )
    }

    /// 仅推进洗牌轮转指针（轻量版，勿与 [`Self::advance_shuffle`] 混用）：
    /// - `pending` 为空且完成人数 ≥ MIN_START_NUM → 仅把 `phase` 置 `None`；
    /// - 否则把 `current_shuffler` 指到 `pending[0]`。
    ///
    /// 刻意不发任何事件、不触发发牌/盲注/reveal——供 join 与洗牌提交路径在
    /// "人未凑够/尚未全部洗完" 时推进轮转。开局驱动统一走
    /// [`Self::advance_shuffle`]（Move 对齐，含 transition_to(PreFlop)、
    /// start_preflop_reveal_phase、record_hand_start 与事件广播）。
    pub fn advance_turn_pointer_only(&mut self) {
        if self.shuffle_state.pending_players.is_empty()
            && self.complete_shuffle_player_count() >= MIN_START_NUM as usize
        {
            self.shuffle_state.phase = ShufflePhase::None;
        } else if let Some(next_pk) = self.shuffle_state.pending_players.first() {
            let next_pk_clone = next_pk.clone();
            self.set_current_shuffler(next_pk_clone);
        }
    }

    pub fn get_shuffle_public_state(&self) -> Option<ShufflePublicState> {
        if self.shuffle_state.is_active() {
            // 开局洗牌统一纯 shuffle：已注册玩家的密钥层由每手
            // start_preflop_shuffle 的 (G, m+agg) 基线预置包含；remask 补层
            // （旧 submit_join_shuffle 语义）对已注册玩家是重复加层，会让
            // 牌组公钥超出 Σsk → 全桌 materialize 失败（2026-09-03 线上复现）。
            // needs_join_layer 字段保留（serde 兼容旧客户端），恒 false；
            // 客户端纯 shuffle 需要的 agg 由 aggregate_pk 字段提供。
            let needs_join_layer = false;
            let share_pk: Option<String> = None;
            Some(ShufflePublicState {
                phase: self.shuffle_state.phase,
                current_player_pk: self.shuffle_state.current_player_pk.clone(),
                completed_players: self.shuffle_state.completed_players.clone(),
                pending_players: self.shuffle_state.pending_players.clone(),
                deck_encrypted: self
                    .mental_poker_game
                    .deck_encrypted
                    .iter()
                    .map(ElGamalCiphertextJson::from_ciphertext)
                    .collect(),
                aggregate_pk: ecpoint_to_hex(
                    &self.mental_poker_game.key_manager.get_aggregated_pk(),
                ),
                needs_join_layer,
                share_pk,
                hand_id: self.current_hand_id,
            })
        } else {
            None
        }
    }

    // ================================================================
    // 对齐 Move 合约 shuffle 流程
    // ================================================================

    /// 镜像 Move advance_shuffle（table.move:2275-2325）：驱动洗牌流程推进。
    /// pending==0 → on_shuffle_complete → 根据 phase 启动 reveal
    /// pending>0 → 设 current_shuffler + reset shuffle_started_at
    ///
    /// 使用 shuffle_state.phase 字段判断阶段（对齐 Move）：
    /// - phase == BeforePreflop → 开局前洗牌
    /// - phase == Reconstruct → reconstruct 后洗牌
    pub fn advance_shuffle(&mut self) {
        // 对齐 Move：仅 BeforePreflop / Reconstruct 阶段推进
        if self.shuffle_state.phase != ShufflePhase::BeforePreflop
            && self.shuffle_state.phase != ShufflePhase::Reconstruct
        {
            return;
        }
        let curr_phase = self.shuffle_state.phase;

        if self.shuffle_state.pending_players.is_empty() {
            // 所有玩家完成洗牌
            self.on_shuffle_complete();

            if curr_phase == ShufflePhase::BeforePreflop {
                // BeforePreflop 完成 → 发牌 (move_button 已在 start_hand 中完成)
                // + transition_to(PreFlop) + start_preflop_reveal_phase
                // 盲注和下注轮在 on_reveal_complete(HandReveal) 中创建
                self.on_before_preflop_shuffle_complete();
                self.transition_to(RoundState::PreFlop);
                self.start_preflop_reveal_phase();
                // #20 Phase 2：deck 已终局（全部客户端洗牌已验证），此刻采集
                // HandStart 快照（参与者/盲注前 stack/button/deck）——实时镜像
                // （shadow.rs）据此 bootstrap 本手唯一 VM 状态；prove_log 本身
                // 只作结算对账基准，不再重放。
                crate::starknet::prove_log::record_hand_start(self);
            } else {
                // Reconstruct 完成 → 清空 reconstruct_state + reveal_token_state
                // + 根据 round_state 启动对应 reveal
                self.reconstruct_state.reset();
                self.reveal_token_state.reset();
                // 方案A：镜像 L1 restart_reveal_after_reconstruct——未揭示的旧
                // 公共牌废弃（密钥份额已缺、不可解），从新 deck 位置 0 重发缺失
                // 张数；发牌游标经哨兵 DealResult 与 L1 cards_dealt 对齐，
                // reconstruct 后的 redeal 因此可行。
                self.mirror_restart_community_redeal();
                match self.round_state() {
                    RoundState::PreFlop => self.start_preflop_reveal_phase(),
                    RoundState::Flop => self.start_community_reveal_phase(),
                    RoundState::Turn => self.start_community_reveal_phase(),
                    RoundState::River => self.start_community_reveal_phase(),
                    RoundState::Showdown => self.start_showdown_reveal_phase(),
                    _ => tracing::warn!(
                        "[advance_shuffle] unexpected round state after reconstruct: {:?}",
                        self.round_state()
                    ),
                }
            }

            // 通知前端洗牌完成
            self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
                message: Some("Shuffle complete".to_string()),
            });
            if self.reveal_token_state.is_active() {
                self.emit_event(crate::pokergame::table::events::TableEvent::RevealNotice);
            }
        } else {
            // 仍有待洗牌玩家 → 设 current_shuffler（对齐 Move：current_shuffler = pending[0]）
            if let Some(first_pk) = self.shuffle_state.pending_players.first() {
                let first_pk_clone = first_pk.clone();
                self.set_current_shuffler(first_pk_clone);
            }
            // 通知前端轮到下一玩家洗牌
            self.emit_event(crate::pokergame::table::events::TableEvent::ShuffleNotice);
        }
    }

    /// 镜像 Move on_shuffle_complete（table.move:1081-1090）：
    /// 仅重置 shuffle_state（phase → None），不 transition_to。
    fn on_shuffle_complete(&mut self) {
        tracing::info!(
            "[SHUFFLE] Shuffle complete (phase={}), resetting shuffle_state",
            self.shuffle_state.phase
        );
        self.shuffle_state.phase = ShufflePhase::None;
        self.shuffle_state.current_player_pk = None;
        self.shuffle_state.timeout_start = None;
        // 保留 completed_players 列表，清空 pending（已为空）
    }

    /// 镜像 Move on_shuffle_timeout（table.move:1211-1299）：处理洗牌超时。
    pub fn on_shuffle_timeout(&mut self) {
        let shuffler_pk = match &self.shuffle_state.current_player_pk {
            Some(pk) => pk.clone(),
            None => return,
        };
        let is_before_preflop = self.shuffle_state.phase == ShufflePhase::BeforePreflop;

        tracing::warn!(
            "[SHUFFLE] Player {} timed out during shuffle (phase={})",
            shuffler_pk,
            self.shuffle_state.phase
        );

        // kick 当前洗牌者
        self.remove_player_by_pk(&shuffler_pk);
        self.shuffle_state
            .pending_players
            .retain(|p| *p != shuffler_pk);

        // 立即清空当前洗牌者指针与计时器：下方任一提前返回路径（Waiting/
        // active_count==0/1/shuffle 已不活跃）都必须让 check_shuffle_timeout
        // 停止对同一玩家逐 tick 反复触发（否则 send_shuffle_notice 死循环、
        // 后续 join/bot 读到 identity-c1 的半初始化牌组直接 panic）。
        // 正常推进路径（rebuild_deck_and_shuffle + advance_shuffle 等）会
        // 重新指派下一个洗牌者并重置计时器。
        self.shuffle_state.current_player_pk = None;
        self.shuffle_state.timeout_start = None;

        // remove_player_by_pk → stand_player_by_pk 在 Reconstruct 阶段（is_playing()==true）
        // 剩 1 人时会自动调用 end_without_showdown。若手牌已结束，直接返回避免重复结算。
        if !is_before_preflop && self.round_state() == RoundState::Waiting {
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

        if is_before_preflop {
            // BeforePreflop: 如果 shuffle_state 已不活跃（kick 触发了完成），直接返回
            if !self.shuffle_state.is_active() {
                return;
            }
            // 重新初始化牌组并重新洗牌
            self.rebuild_deck_and_shuffle();
            self.advance_shuffle();
        } else {
            // Reconstruct: 如果 round_state 已变 Waiting（kick 触发了 reset），直接返回
            if self.round_state() == RoundState::Waiting {
                return;
            }
            // 如果 shuffle_state 已不活跃（kick 触发了完成），直接返回
            if !self.shuffle_state.is_active() {
                return;
            }
            // 从 reconstruct_state.player_deck 移除被踢玩家
            self.reconstruct_state.player_deck.remove(&shuffler_pk);
            // 重新构建牌组并重新洗牌
            self.on_reconstruct_shuffle_failed();
        }
    }

    /// 重新初始化牌组为 (identity, plaintext_i)，
    /// 等价于 Move 的 rebuild_deck_and_shuffle_on_timeout。
    /// 洗牌超时与开局孤儿层检测（start_preflop_shuffle）共用。
    pub(crate) fn rebuild_deck_and_shuffle(&mut self) {
        let plaintext = self.mental_poker_game.deck_plaintext.clone();
        let new_deck: Vec<ElGamalCiphertext> = plaintext
            .iter()
            .map(|p| ElGamalCiphertext {
                c1: EcPoint::identity(),
                c2: p.clone(),
            })
            .collect();
        self.mental_poker_game.deck_encrypted = new_deck;
        // 重新初始化 pending_players 为所有活跃玩家
        self.shuffle_state.pending_players = self
            .mental_poker_game
            .players
            .keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.shuffle_state.completed_players.clear();
        self.shuffle_state.current_player_pk = None;
    }

    /// 镜像 Move on_reconstruct_shuffle_failed（table.move:973-982）：
    /// 从 player_deck 重建牌组并重新洗牌。
    fn on_reconstruct_shuffle_failed(&mut self) {
        // 从 player_deck 重建牌组（与 submit_reconstruct_deck 中的逻辑一致）
        let init_deck = self.mental_poker_game.deck_plaintext.clone();
        let deck_len = init_deck.len();
        let mut reconstruct_deck: Vec<ElGamalCiphertext> = init_deck
            .iter()
            .map(|c| ElGamalCiphertext {
                c1: EcPoint::identity(),
                c2: c.clone(),
            })
            .collect();
        for (_, deck) in self.reconstruct_state.player_deck.iter() {
            for (i, card) in deck.iter().enumerate() {
                if i < deck_len {
                    reconstruct_deck[i].c1 = reconstruct_deck[i].c1 + card.c1;
                    reconstruct_deck[i].c2 = reconstruct_deck[i].c2 + card.c2 - init_deck[i];
                }
            }
        }
        self.mental_poker_game.deck_encrypted = reconstruct_deck;
        // 重新洗牌
        self.shuffle_state.pending_players = self
            .mental_poker_game
            .players
            .keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.shuffle_state.completed_players.clear();
        self.shuffle_state.current_player_pk = None;
        self.advance_shuffle();
    }
}
