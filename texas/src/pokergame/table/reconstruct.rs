use super::*;
use crate::pokergame::game_state::ShufflePhase;
use poker_protocol::crypto::DefaultCurve;
use poker_protocol::zk_shuffle::reconstruction::{ReconstructProof, ReconstructionStatement};

impl Table {
    pub fn start_reconstruct(&mut self) -> Result<(), String> {
        if self.reconstruct_state.is_active {
            return Err("Reconstruct already in progress".to_string());
        }
        // 方案A（重构进轨迹）：镜像 L1 必须已处于 Reconstructing——由游戏层
        // 超时路径先驱动 VM advance_deadline（L1 踢掉未交份额座位并进入收集，
        // 级联进证明轨迹）。epoch / context_digest / prior_state_digests /
        // residual_carriers 一律由镜像 L1 状态权威推导（poker_l1 同一实现；
        // 摘要材料绑定镜像 ObjectID，游戏层本地重算必不匹配），客户端据此
        // 构造 statement，L1 submit 时全字段重验才能通过。pending 集取 L1 的
        // 权威 pending_mask（活跃参与者），与游戏层旧"全部注册玩家"口径对齐。
        let ctx = match self.vm_reconstruct_context() {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(format!("reconstruct rejected by VM: {e}")),
            None => return Err("reconstruct rejected: hand has no live VM mirror".to_string()),
        };
        // epoch 跨手单调：L1 epoch 为进 Reconstructing 的共识毫秒时间戳。
        self.reconstruct_state.reconstruction_epoch = ctx.reconstruction_epoch;
        self.reconstruct_state.context_digest = ctx.context_digest;
        self.reconstruct_state.vm_aggregate_pk = ctx.aggregate_pk.clone();
        self.reconstruct_state.timeout_start = Some(std::time::Instant::now());
        self.reconstruct_state.timeout_seconds = 10;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players = ctx
            .pending_pks
            .iter()
            .map(|p| GamePkHex::new(p.clone()))
            .collect();
        self.reconstruct_state.cards = self.mental_poker_game.deck_plaintext.clone();
        self.reconstruct_state.player_residual_carriers.clear();
        self.reconstruct_state.prior_state_digests.clear();
        for (pk, digest) in &ctx.prior_state_digests {
            self.reconstruct_state
                .prior_state_digests
                .insert(GamePkHex::new(pk.clone()), *digest);
        }
        for (pk, carriers) in &ctx.residual_carriers {
            self.reconstruct_state.player_residual_carriers.insert(
                GamePkHex::new(pk.clone()),
                PlayerResidualCarriers {
                    residual_carriers: carriers.clone(),
                },
            );
        }
        self.reconstruct_state.player_deck.clear();
        // 收集窗口激活（原实现漏置 is_active——submit/execute/timeout 三个
        // 驱动点全部以它为门，窗口从未真正"开启"过，仅靠调用方各自为政）。
        self.reconstruct_state.is_active = true;
        tracing::info!(
            "[RECONSTRUCT] Reconstruct initiated for players {} (L1 epoch {})",
            self.reconstruct_state
                .pending_players
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(","),
            ctx.reconstruction_epoch
        );
        // 通知前端 reconstruct 阶段已开始
        self.emit_event(crate::pokergame::table::events::TableEvent::ReconstructNotice);
        Ok(())
    }

    pub fn execute_reconstruct_if_completed(&mut self) -> bool {
        if !self.reconstruct_state.is_active {
            return false;
        }
        // D1 fix: use pending_players.is_empty() instead of
        // completed_players.len() >= pending_players.len(), which is always
        // true when pending is empty but also true in other wrong cases.
        if self.reconstruct_state.pending_players.is_empty() {
            tracing::info!(
                "[RECONSTRUCT] Executing reconstruct for players: {:?}",
                self.reconstruct_state.completed_players
            );
            self.on_complete_reconstruct();
            return true;
        }
        false
    }

    pub fn submit_reconstruct_deck(
        &mut self,
        player_pk_hex: &GamePkHex,
        statement: ReconstructionStatement<DefaultCurve>,
        proof: ReconstructProof<DefaultCurve>,
    ) -> Result<bool, String> {
        if !self.reconstruct_state.is_active {
            return Err("Reconstruct not active".to_string());
        }
        if !self
            .reconstruct_state
            .pending_players
            .contains(player_pk_hex)
        {
            return Err("Not found player".to_string());
        }

        let player = self
            .mental_poker_game
            .players
            .get(&**player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        // statement 必须绑定服务端权威状态：statement 摘要字段一律服务端重算，
        // 客户端仅提供证明本体。
        let expected_carriers = self
            .reconstruct_state
            .player_residual_carriers
            .get(player_pk_hex)
            .ok_or("Player not found in reconstruct state")?;
        let expected_prior = self
            .reconstruct_state
            .prior_state_digests
            .get(player_pk_hex)
            .ok_or("Player not found in reconstruct state")?;
        if statement.version
            != poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_VERSION
        {
            return Err("Unsupported reconstruction statement version".to_string());
        }
        if statement.owner_pk != player {
            return Err("Statement owner key mismatch".to_string());
        }
        // 聚合公钥以镜像 contributor mask 派生值为单一真相（start_reconstruct
        // 时由 VM 上下文写入；客户端 notice 用的也是同一值）。
        let expected_aggregate = if self.reconstruct_state.vm_aggregate_pk.is_empty() {
            ecpoint_to_hex(&self.mental_poker_game.key_manager.get_aggregated_pk())
        } else {
            self.reconstruct_state.vm_aggregate_pk.clone()
        };
        if ecpoint_to_hex(&statement.aggregate_pk) != expected_aggregate {
            return Err("Statement aggregate key mismatch".to_string());
        }
        if statement.cards != self.reconstruct_state.cards {
            return Err("Statement card points mismatch".to_string());
        }
        if statement.residual_carriers != expected_carriers.residual_carriers {
            return Err("Statement residual carriers mismatch".to_string());
        }
        if statement.reconstruction_epoch != self.reconstruct_state.reconstruction_epoch {
            return Err("Statement epoch mismatch".to_string());
        }
        if statement.context_digest != self.reconstruct_state.context_digest {
            return Err("Statement context digest mismatch".to_string());
        }
        if statement.prior_state_digest != *expected_prior {
            return Err("Statement prior state digest mismatch".to_string());
        }
        statement
            .validate()
            .map_err(|e| format!("Invalid reconstruction statement: {e}"))?;

        let mut transcript =
            poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::RECONSTRUCT_POSEIDON,
            );
        proof
            .verify(&statement, &mut transcript)
            .map_err(|e| format!("Invalid reconstruct proof: {e}"))?;

        // 方案A（重构进轨迹）：statement 转发 L1 全字段重验并累计贡献
        // （与游戏层各验一次——单一状态 + fail-closed 的既定代价）。最后一份
        // 提交在 L1 normalize 内联完成 deck 重建 + 进入重构洗牌相位。
        match self.vm_try_submit_reconstruct_deck(
            &**player_pk_hex,
            statement.clone(),
            proof.clone(),
        ) {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(format!("reconstruct rejected by VM: {e}")),
            None => return Err("reconstruct rejected: hand has no live VM mirror".to_string()),
        }

        self.reconstruct_state
            .player_deck
            .insert(player_pk_hex.clone(), statement.contributions);
        self.reconstruct_state
            .pending_players
            .retain(|p| p != player_pk_hex);
        self.reconstruct_state
            .completed_players
            .push(player_pk_hex.clone());
        let is_all_complete = self.reconstruct_state.pending_players.is_empty();
        if is_all_complete {
            // 最后一份提交即完成：立即收口（L1 已在同一提交的 normalize 内联
            // 重建 deck + 开启重构洗牌；游戏层这里对齐执行自己的重建 + 洗牌
            // 窗口）。is_active 翻转由 on_complete_reconstruct/reset 统一处理。
            self.on_complete_reconstruct();
        }
        Ok(is_all_complete)
    }

    /// 镜像 Move on_complete_reconstruct：reconstruct 完成后重建牌组并重新洗牌。
    ///
    /// 新协议：从 canonical base deck（公牌点 × 聚合钥）出发，同态叠加每个
    /// 已验证玩家的 contributions。
    pub fn on_complete_reconstruct(&mut self) {
        let init_deck = self.mental_poker_game.deck_plaintext.clone();
        let aggregate_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let mut deck = match poker_protocol::zk_shuffle::reconstruction::canonical_base_deck(
            &init_deck,
            &aggregate_pk,
        ) {
            Ok(deck) => deck,
            Err(e) => {
                tracing::error!("[RECONSTRUCT] canonical base deck failed: {e}");
                return;
            }
        };
        for (_, contributions) in self.reconstruct_state.player_deck.iter() {
            match poker_protocol::zk_shuffle::reconstruction::apply_reconstruction_contributions(
                &deck,
                contributions,
            ) {
                Ok(next) => deck = next,
                Err(e) => {
                    tracing::error!("[RECONSTRUCT] apply contributions failed: {e}");
                    return;
                }
            }
        }
        self.mental_poker_game.deck_encrypted = deck;
        // 重建 + 全员重洗后的 deck 是全新发牌序列：发牌游标归零，
        // 此后 deal/redeal 从新 deck 位置 0 起步（z_poker todo 收口）。
        self.mental_poker_game.note_deck_reconstructed();

        // 仅重置状态字段，保留 player_deck 供后续 on_reconstruct_shuffle_failed 重建牌组使用。
        // 下次 start_reconstruct 会清空 player_deck，此处无需清空。
        self.reconstruct_state.is_active = false;
        self.reconstruct_state.timeout_start = None;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players.clear();
        self.reconstruct_state.cards.clear();
        self.reconstruct_state.player_residual_carriers.clear();

        // 进入洗牌阶段（RECONSTRUCT phase，对齐 Move shuffle_phase_reconstruct）
        self.shuffle_state.phase = ShufflePhase::Reconstruct;
        // 轮转顺序 = 座位升序（对齐 L1 derived_current_shuffler 的最小座位
        // 权威与开局洗牌的 get_active_seat_indices 口径；此前用 mental players
        // 的 HashMap 键序——随机序，重构后重洗的权威 dispatch 必然撞
        // "not shuffler's turn"）。
        let mut reshuffle_pks: Vec<GamePkHex> = self
            .mental_poker_game
            .players
            .keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        reshuffle_pks.sort_by_key(|pk| self.pk_to_seat.get(pk).copied().unwrap_or(u32::MAX));
        self.shuffle_state.pending_players = reshuffle_pks;
        self.shuffle_state.completed_players.clear();
        self.shuffle_state.current_player_pk = None;

        // 推进洗牌
        self.advance_shuffle();

        // 通知前端 reconstruct 完成
        self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
            message: None,
        });
    }

    /// 镜像 Move on_reconstruct_timeout：处理 reconstruct 超时
    pub fn on_reconstruct_timeout(&mut self) {
        if !self.reconstruct_state.is_active {
            return;
        }
        let pending_pks = self.reconstruct_state.pending_players.clone();
        tracing::warn!("[RECONSTRUCT] Timeout for players: {:?}", pending_pks);

        // 对齐 Move：kick all pending players（kick_player_internal 会处理退款/pot/状态清理）
        for pk in &pending_pks {
            self.remove_player_by_pk(pk);
        }

        let active_count = self.active_players().len();

        // 对齐 Move：没有活跃玩家 → refund + reset
        if active_count == 0 {
            self.refund_all_bets();
            self.reset_for_next_hand();
            return;
        }

        // 对齐 Move：只剩一人 → end_without_showdown
        if active_count == 1 {
            self.end_without_showdown();
            return;
        }

        // 对齐 Move：kick 可能已触发 reset_for_next_hand（活跃玩家不足）
        if self.round_state() == RoundState::Waiting {
            return;
        }

        // 对齐 Move：不清空 reconstruct_state，保留已提交的 player_decks 供 on_complete_reconstruct 重建牌组
        // 重置 pending_players（已全部 kick），保留 completed_players 和 player_deck
        self.reconstruct_state.is_active = false;
        self.reconstruct_state.timeout_start = None;
        self.reconstruct_state.pending_players.clear();

        // 调用 on_complete_reconstruct 用已提交的 deck 重建牌组
        self.on_complete_reconstruct();
    }

    pub fn get_reconstruct_public_state(&self) -> Option<ReconstructPublicState> {
        if self.reconstruct_state.is_active {
            Some(ReconstructPublicState {
                is_active: true,
                completed_players: self.reconstruct_state.completed_players.clone(),
                pending_players: self.reconstruct_state.pending_players.clone(),
                cards: self
                    .reconstruct_state
                    .cards
                    .iter()
                    .map(|c| ecpoint_to_hex(c))
                    .collect(),
                // 单一真相：镜像 contributor mask 派生的聚合公钥（客户端
                // statement 的 aggregate_pk 必须与 L1 校验值一致）。
                aggregate_pk: if self.reconstruct_state.vm_aggregate_pk.is_empty() {
                    ecpoint_to_hex(&self.mental_poker_game.key_manager.get_aggregated_pk())
                } else {
                    self.reconstruct_state.vm_aggregate_pk.clone()
                },
                context_digest: hex::encode(self.reconstruct_state.context_digest),
                reconstruction_epoch: self.reconstruct_state.reconstruction_epoch,
                prior_state_digests: self
                    .reconstruct_state
                    .prior_state_digests
                    .iter()
                    .map(|(k, v)| (k.clone(), hex::encode(v)))
                    .collect(),
                player_residual_carriers: self
                    .reconstruct_state
                    .player_residual_carriers
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            PlayerResidualCarriersJson {
                                residual_carriers: v
                                    .residual_carriers
                                    .iter()
                                    .map(ElGamalCiphertextJson::from_ciphertext)
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
            })
        } else {
            None
        }
    }
}
