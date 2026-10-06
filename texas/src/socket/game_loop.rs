use std::sync::Arc;

use super::*;
use crate::pokergame::actions::action_sig_required;
use crate::pokergame::game_state::PlayerResidualCarriersJson;
use crate::pokergame::table::now_ms;

pub(crate) async fn game_loop_task(io: SocketIo, state: Arc<SocketState>, table_id: u32, mut action_rx: tokio::sync::mpsc::Receiver<ActionRequest>, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
    tracing::info!("[GAME-LOOP] Started for table {}", table_id);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !process_tick(&io, &state, table_id).await {
                    tracing::info!("[GAME-LOOP] Table {} process_tick signaled stop", table_id);
                    break;
                }
            }
            action = action_rx.recv() => {
                match action {
                    Some(req) => {
                        tracing::info!("[GAME-LOOP] Table {} received action: {} from {}", table_id, req.action, req.pk_hex);
                        process_action(&io, &state, table_id, req).await;
                    }
                    None => {
                        tracing::info!("[GAME-LOOP] Channel closed for table {}", table_id);
                        break;
                    }
                }
            }
            _ = stop_rx.changed() => {
                tracing::info!("[GAME-LOOP] Stop signal received for table {}", table_id);
                break;
            }
        };
    }

    {
        let mut registry = state.game_loop_registry.write().await;
        registry.remove(table_id);
    }
    tracing::info!("[GAME-LOOP] Stopped for table {}", table_id);
}

// ---------------------------------------------------------------------------
// 广播辅助函数
// ---------------------------------------------------------------------------

/// 当 reveal_token_state 处于活跃状态时，广播 RevealNoticePayload 给桌上所有客户端。
/// 用于 advance_shuffle / advance_to_next_phase 启动 reveal 阶段后通知前端。
pub async fn broadcast_reveal_notice_if_active(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let reveal_notice = {
        let gs = state.state.read().await;
        gs.tables.get(&table_id)
            .filter(|t| t.reveal_token_state.is_active())
            .map(|t| {
                let phase = t.reveal_token_state.phase;
                let pending = t.reveal_token_state.pending_players.clone();
                let completed = t.reveal_token_state.completed_players.clone();
                let player_assignments = t.reveal_token_state.player_assignments.clone();
                RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
            })
    };
    if let Some(notice) = reveal_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::REVEAL_NOTICE, &notice).await;
    }
}

/// 当 reconstruct_state 处于活跃状态时，广播 ReconstructNoticePayload 给桌上所有客户端。
/// 用于 on_reveal_timeout 触发 reconstruct 后通知前端。
pub(crate) async fn broadcast_reconstruct_notice_if_active(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let reconstruct_notice = {
        let gs = state.state.read().await;
        gs.tables.get(&table_id)
            .filter(|t| t.reconstruct_state.is_active)
            .map(|t| {
                let completed_players = t.reconstruct_state.completed_players.clone();
                let pending_players = t.reconstruct_state.pending_players.clone();
                let cards = t.reconstruct_state.cards.iter().map(|c| ecpoint_to_hex(c)).collect();
                let aggregate_pk = ecpoint_to_hex(&t.mental_poker_game.key_manager.get_aggregated_pk());
                let context_digest = hex::encode(t.reconstruct_state.context_digest);
                let reconstruction_epoch = t.reconstruct_state.reconstruction_epoch;
                let prior_state_digests = t.reconstruct_state.prior_state_digests.iter()
                    .map(|(k, v)| (k.clone(), hex::encode(v)))
                    .collect();
                let player_residual_carriers = t.reconstruct_state.player_residual_carriers.iter()
                    .map(|(k, v)| {
                        (k.clone(), PlayerResidualCarriersJson {
                            residual_carriers: v.residual_carriers.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                        })
                    })
                    .collect();
                ReconstructNoticePayload { table_id, completed_players, pending_players, cards, aggregate_pk, context_digest, reconstruction_epoch, prior_state_digests, player_residual_carriers }
            })
    };
    if let Some(notice) = reconstruct_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_NOTICE, &notice).await;
    }
}

// ---------------------------------------------------------------------------
// 超时玩家 socket 清理辅助函数
// ---------------------------------------------------------------------------

/// 在调用 on_*_timeout 之前，记录待踢玩家的 pk_hex → socket_id 映射。
/// on_*_timeout 内部会调用 table.remove_player_by_pk，从 table.players 中移除玩家，
/// 之后便无法通过 table.players 查找 wallet_address → socket_id，所以必须提前记录。
async fn record_pk_to_socket_ids(state: &Arc<SocketState>, table_id: u32, pks: &[GamePkHex]) -> Vec<(GamePkHex, String)> {
    let gs = state.state.read().await;
    let Some(table) = gs.tables.get(&table_id) else { return Vec::new() };
    pks.iter()
        .filter_map(|pk| {
            let players = table.players();
            let wallet_addr = players.get(pk)?;
            let socket_id = gs.players.values()
                .find(|p| &p.wallet_address == wallet_addr)
                .map(|p| p.socket_id.clone())?;
            Some((pk.clone(), socket_id))
        })
        .collect()
}

/// on_*_timeout 调用后，对被踢玩家执行 socket 层清理：
/// 从 gs.players 移除、离开 table room、emit TABLE_LEFT。
async fn cleanup_player_sockets(
    io: &SocketIo,
    state: &Arc<SocketState>,
    table_id: u32,
    pk_socket_pairs: Vec<(GamePkHex, String)>,
    reason: Option<&str>,
) {
    if pk_socket_pairs.is_empty() {
        return;
    }
    let current_tables = state.get_current_tables().await;
    {
        let mut gs = state.state.write().await;
        for (_, socket_id) in &pk_socket_pairs {
            gs.players.remove(socket_id);
        }
    }
    for (_, socket_id) in &pk_socket_pairs {
        if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
            if let Some(socket) = io.get_socket(sid) {
                socket.leave(table_room_name(table_id));
                let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload {
                    tables: current_tables.clone(),
                    table_id,
                    reason: reason.map(|s| s.to_string()),
                });
            }
        }
    }
    // Broadcast global table/player updates so lobby UI syncs
    let players_info = state.get_current_players().await;
    let _ = io.emit(actions::TABLES_UPDATED, &current_tables).await;
    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
}

// ---------------------------------------------------------------------------
// process_tick — 严格对齐 Move 合约 tick 优先级
// ---------------------------------------------------------------------------

pub(crate) async fn process_tick(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    // 读取状态快照
    // 对齐 Move：时间戳使用 u64 ms（summary.state.*_at），0 表示未设置
    let (round_state, active_count, seated_count, hand_complete_at, ready_at, showdown_at,
         shuffle_active, reveal_active, reconstruct_active) = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            // 开局人数口径与 start_hand 一致：非 sitting_out 的在座玩家
            // （含 is_waiting 中途买入者），避免 waiting 玩家不算数导致永不开局。
            (table.round_state(),
             table.seats().values().filter(|s| s.player.is_some() && !s.sitting_out).count(),
             table.seats().values().filter(|s| s.player.is_some()).count(),
             table.hand_complete_at(), table.ready_at(), table.showdown_at(),
             table.shuffle_state.is_active(), table.reveal_token_state.is_active(), table.reconstruct_state.is_active)
        } else { return false }
    };

    // 循环停止规则：仅当桌上一个玩家都不剩时才停。
    // active_count 排除 sitting_out，会因刷新/短暂断线（DISCONNECT 标记
    // sitting_out）瞬时走低甚至归零——旧实现在此停掉循环且无人重启，
    // 玩家重连回来后牌桌永久冻结（2026-09-01 线上复现）。
    if seated_count == 0 {
        return false;
    }

    // #20 Phase 2：VM 派奖推进在实时镜像（shadow.rs）收尾时完成，tick 不
    // 持有第二份 VM 状态。tick 只负责：游戏手已结束（hand_over）而链上结算
    // 未成功时，有界重试上链。
    // 严禁在此恢复 fill/autoplay/replay 等事后追赶补丁（见计划文档禁止事项）。
    {
        let hand_over = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id).map(|t| t.summary.hand_over).unwrap_or(false)
        };
        if hand_over {
            crate::starknet::hooks::retry_pending_settlement(table_id).await;
        }
    }

    // ===== Priority 1: reconstruct =====
    if reconstruct_active {
        // 1a. 检查 reconstruct 是否完成
        let completed = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.execute_reconstruct_if_completed()
            } else { false }
        };
        if completed {
            broadcast::broadcast_to_table(io, state, table_id, Some("Reconstruct completed")).await;
            // on_complete_reconstruct 已在 execute_reconstruct_if_completed 内部调用，
            // 它会启动 shuffle(RECONSTRUCT) + advance_shuffle。
            // 广播 ReconstructResultPayload
            let reconstruct_payload = ReconstructResultPayload {
                table_id,
                completed_players: vec![],
                reconstructed: true,
            };
            let _ = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;
            // 广播 shuffle notice（advance_shuffle 可能已设置 current_shuffler）
            state.send_shuffle_notice(table_id).await;
            // 广播 reveal notice（如果 advance_shuffle 已启动 reveal）
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reconstruct complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Reconstruct,
                "".to_string(),
                None, true,
                Some("reconstruct complete".to_string()),
                None,
            ).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
            return true;
        }

        // 1b. 检查 reconstruct 超时
        let (is_timed_out, timed_out_pks) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                if !table.reconstruct_state.is_active {
                    (false, Vec::new())
                } else if let Some(timeout_start) = table.reconstruct_state.timeout_start {
                    if timeout_start.elapsed().as_secs() >= table.reconstruct_state.timeout_seconds
                        && !table.reconstruct_state.pending_players.is_empty() {
                        (true, table.reconstruct_state.pending_players.clone())
                    } else {
                        (false, Vec::new())
                    }
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        };
        if is_timed_out {
            // 提前记录 socket_id，因为 on_reconstruct_timeout 会从 table.players 移除玩家
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &timed_out_pks).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reconstruct_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_names: Vec<String> = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .map(|p| p.name.clone())
                    .collect()
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("reconstruct timeout")).await;
            let msg = if player_names.is_empty() {
                "Reconstruct timed out".to_string()
            } else {
                format!("{} timed out (reconstruct)", player_names.join(", "))
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            // 与 reconstruct 完成分支保持一致：广播 shuffle notice 和 reveal notice
            state.send_shuffle_notice(table_id).await;
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reconstruct timeout
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Reconstruct,
                "".to_string(),
                None, true,
                Some("reconstruct timeout".to_string()),
                None,
            ).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
        }
        // reconstruct 进行中或刚超时，不处理其他状态
        return true;
    }

    // ===== Priority 2: shuffle =====
    if shuffle_active {
        // 2a. 活跃玩家不足 → 回到 Waiting
        if active_count < MIN_START_NUM as usize {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.shuffle_state.phase = crate::pokergame::game_state::ShufflePhase::None;
                if round_state != RoundState::Waiting {
                    table.transition_to(RoundState::Waiting);
                }
            }
            return true;
        }

        // 2b. 所有玩家完成洗牌 → advance_shuffle
        let pending_empty = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id)
                .map(|t| t.shuffle_state.pending_players.is_empty())
                .unwrap_or(false)
        };
        if pending_empty {
            let reveal_started = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.advance_shuffle();
                    table.reveal_token_state.is_active()
                } else { false }
            };
            broadcast::broadcast_to_table(io, state, table_id, Some("Shuffle complete")).await;
            // crypto_event: shuffle round complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                "".to_string(),
                None, true,
                Some("shuffle round complete".to_string()),
                None,
            ).await;
            if reveal_started {
                broadcast_reveal_notice_if_active(io, state, table_id).await;
                // crypto_event: reveal phase started
                state.broadcast_crypto_event(
                    table_id,
                    broadcast::CryptoEventType::RevealToken,
                    "".to_string(),
                    None, true,
                    Some("reveal phase started".to_string()),
                    None,
                ).await;
            }
            return true;
        }

        // 2c. 检查 shuffle 超时（check_shuffle_timeout 只检查不修改状态）
        let timed_out_pk = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_shuffle_timeout()
            } else { None }
        };
        if let Some(timed_out_pk) = timed_out_pk {
            // 提前记录 socket_id
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &[timed_out_pk.clone()]).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_shuffle_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_name = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .next()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Unknown".to_string())
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("shuffle timeout")).await;
            let msg = format!("{} timed out (shuffle)", player_name);
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            state.send_shuffle_notice(table_id).await;
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
            return true;
        }
        // shuffle 进行中
        return true;
    }

    // ===== Priority 3: reveal =====
    if reveal_active {
        // 3a. 所有玩家完成 reveal → on_reveal_complete
        let all_pending_empty = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id)
                .map(|t| t.reveal_token_state.pending_players.is_empty())
                .unwrap_or(false)
        };
        if all_pending_empty {
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reveal_complete();
                }
            }
            broadcast::broadcast_to_table(io, state, table_id, None).await;
            // crypto_event: reveal phase complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase complete".to_string()),
                None,
            ).await;
            return true;
        }

        // 3b. 检查 reveal 超时（手动检查，不调用 check_reveal_timeout 以免它 reset 状态）
        let (is_timed_out, timed_out_pks) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                if !table.reveal_token_state.is_active() {
                    (false, Vec::new())
                } else if let Some(timeout_start) = table.reveal_token_state.timeout_start {
                    if timeout_start.elapsed().as_secs() >= table.reveal_token_state.timeout_seconds
                        && !table.reveal_token_state.pending_players.is_empty() {
                        (true, table.reveal_token_state.pending_players.clone())
                    } else {
                        (false, Vec::new())
                    }
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        };
        if is_timed_out {
            // 提前记录 socket_id
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &timed_out_pks).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reveal_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_names: Vec<String> = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .map(|p| p.name.clone())
                    .collect()
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("reveal timeout")).await;
            let msg = if player_names.is_empty() {
                "Reveal timeout".to_string()
            } else {
                format!("{} timed out (reveal)", player_names.join(", "))
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            // on_reveal_timeout 可能触发了 reconstruct，广播 reconstruct notice
            broadcast_reconstruct_notice_if_active(io, state, table_id).await;
            return true;
        }
        // reveal 进行中：周期性重播 REVEAL_NOTICE（每 10s）。刷新/重连的客户端
        // 错过 phase 启动时的首播后，靠重播在 45s 超时前补交 reveal token，
        // 避免无谓的 timeout 踢人（踢人会连锁触发 reconstruct 失败、整手作废）。
        let should_rebroadcast = {
            let mut gs = state.state.write().await;
            gs.tables.get_mut(&table_id)
                .filter(|t| t.reveal_token_state.is_active() && !t.reveal_token_state.pending_players.is_empty())
                .filter(|t| t.reveal_token_state.last_notice_at
                    .map(|t| t.elapsed().as_secs() >= 10)
                    .unwrap_or(true))
                .map(|t| {
                    t.reveal_token_state.last_notice_at = Some(std::time::Instant::now());
                    true
                })
                .unwrap_or(false)
        };
        if should_rebroadcast {
            broadcast_reveal_notice_if_active(io, state, table_id).await;
        }
        return true;
    }

    // ===== Priority 4+: match round_state =====
    match round_state {
        RoundState::Waiting => {
            // 保留 hand_complete_at 清理逻辑：reset_for_next_hand 后的玩家移除
            if hand_complete_at != 0 {
                let elapsed = now_ms().saturating_sub(hand_complete_at) / 1000;
                if elapsed >= state.config.hand_complete_wait_secs as u64 {
                    // Leave grace: 若仍有 sitting_out 玩家（正在完成链上 leave 交易），
                    // 延迟清理以给他们更多时间。所有 sitting_out 玩家被移除后（链上 tx 完成 +
                    // relayer 同步），下一 tick has_sitting_out 为 false，立即推进清理。
                    // 上限为 hand_complete_wait_secs + leave_grace_secs，避免无限等待。
                    let sitting_out_count = {
                        let gs = state.state.read().await;
                        gs.tables.get(&table_id)
                            .map(|t| t.seats().values().filter(|s| s.sitting_out).count())
                            .unwrap_or(0)
                    };
                    if sitting_out_count > 0
                        && elapsed < state.config.hand_complete_wait_secs as u64
                            + state.config.leave_grace_secs as u64
                    {
                        tracing::debug!(
                            "[TICK] Table {} Waiting: {} sitting_out players, leave grace {}/{}s",
                            table_id, sitting_out_count, elapsed,
                            state.config.hand_complete_wait_secs as u64 + state.config.leave_grace_secs as u64
                        );
                        return true;
                    }
                    let cleanup = {
                        // First pass: collect wallet->player_id mappings with read lock
                        let wallet_to_player_id: std::collections::HashMap<String, String> = {
                            let gs = state.state.read().await;
                            let mut map = std::collections::HashMap::new();
                            if let Some(table) = gs.tables.get(&table_id) {
                                for seat in table.seats().values() {
                                    let is_broke = seat.stack == 0;
                                    let is_sitting_out = seat.sitting_out;
                                    if is_broke || is_sitting_out {
                                        if let Some(player) = &seat.player {
                                            if let Some(p) = gs.players.values().find(|p| p.wallet_address.0 == player.wallet_address.0) {
                                                map.insert(player.wallet_address.to_string(), p.id.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            map
                        };

                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            // #33 离桌快解锁要绑定"该玩家最后一手"：在
                            // reset_for_next_hand 可能清零前先取 current_hand_id。
                            let hand_at_removal = table.current_hand_id;
                            let mut to_remove = Vec::new();
                            for seat in table.local_seats.values_mut() {
                                let is_broke = seat.stack == 0;
                                let is_sitting_out = seat.sitting_out;
                                if is_broke || is_sitting_out {
                                    if let Some(player) = &seat.player {
                                        let stack = if is_sitting_out { seat.stack } else { 0 };
                                        to_remove.push((player.wallet_address.to_string(), stack));
                                    }
                                }
                            }
                            // Return chips to sitting_out players（锁内仅收集额度，
                            // DB await 统一移到写锁块外执行）
                            let chips_to_unlock: Vec<(String, i64)> = to_remove
                                .iter()
                                .filter(|(_, stack)| *stack > 0)
                                .filter_map(|(address, stack)| {
                                    wallet_to_player_id.get(address).map(|pid| (pid.clone(), *stack as i64))
                                })
                                .collect();
                            // Remove players from table
                            for (wallet_addr,_) in to_remove.iter() {
                                tracing::info!("remove_player_by_pk: {}", wallet_addr);
                                if let Some(pk_hex) = table.get_pk_hex_by_wallet_address(wallet_addr) {
                                    table.remove_player_by_pk(&pk_hex);
                                }
                            }
                            table.reset_for_next_hand();
                            (table.active_players().len(), to_remove, chips_to_unlock, hand_at_removal)
                        } else { (0, Vec::new(), Vec::new(), 0) }
                    };
                    let (active, removed_players, chips_to_unlock, hand_at_removal) = cleanup;

                    // DB 退还筹码必须在写锁外执行：state 是覆盖所有桌的全局单锁，
                    // 跨 await 会冻结全服的 tick 与 socket handler。
                    for (pid, stack) in chips_to_unlock {
                        let _ = state.db.unlock_chips(&pid, stack).await;
                    }

                    let tables_info = state.get_current_tables().await;
                    let players_info = state.get_current_players().await;
                    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;


                    for (wallet_address, _) in removed_players.iter() {
                        let gs = state.state.read().await;
                        let socket_id = gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.socket_id.clone());
                        drop(gs);
                        if let Some(sid_str) = socket_id {
                            if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                                if let Some(socket) = io.get_socket(sid) {
                                    let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info.clone(), table_id, reason: None });
                                }
                            }
                        }
                    }

                    for (wallet_address, _) in removed_players.iter() {
                        let player_name = {
                            let gs = state.state.read().await;
                            gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.name.clone())
                        };
                        if let Some(name) = player_name {
                            broadcast::broadcast_to_table(&io, &state, table_id, Some(&format!("{} left the table.", name))).await;
                        }
                    }

                    // #33 离桌快解锁：手尾清理移除的玩家（破产/坐观离桌）。
                    // 手刚结束、settle 大概率还在飞——挂起等该手结算成功后
                    // flush 释放；链上操作 spawn 出去不阻塞 tick。
                    for (wallet_address, _) in removed_players.iter() {
                        let seated_elsewhere = {
                            let gs = state.state.read().await;
                            gs.tables.values().any(|t| t.find_player_by_wallet(wallet_address).is_some())
                        };
                        if seated_elsewhere {
                            continue;
                        }
                        let settled = crate::starknet::hooks::settle_ok_already(table_id, hand_at_removal);
                        let wallet = wallet_address.clone();
                        tokio::spawn(async move {
                            crate::starknet::lock::schedule_leave_release(&wallet, hand_at_removal, settled).await;
                        });
                    }

                    tracing::info!("[TICK] Table {} Waiting: cleanup after hand_complete, {} active, {} players removed", table_id, active, removed_players.len());
                    if active < MIN_START_NUM as usize {
                        broadcast::broadcast_to_table(io, state, table_id, Some("Waiting for more players")).await;
                        // 人不够不停循环：保持 tick，等玩家回来后自动重新起手。
                        return true;
                    }
                    // hand_complete_at already cleared by reset_for_next_hand; proceed to auto-start
                } else {
                    // Not timed out yet, wait
                    return true;
                }
            }

            // Auto-start logic (do_start_hand: start_shuffle)
            if active_count >= MIN_START_NUM as usize {
                // 关桌闸（终态）："关桌后不开新手"的服务端权威执行点——
                // 已关闭的桌跳过倒计时与开局，循环保持存活（已进行中的手
                // 会正常打完并结算， Waiting 分支自然停在这里）。
                let closed = { state.state.read().await.tables.get(&table_id).is_some_and(|t| t.is_closed()) };
                if closed {
                    if ready_at != 0 {
                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.set_ready_at(0);
                        }
                    }
                    return true;
                }
                let io_c = io.clone();
                let state_c = state.clone();
                if ready_at != 0 {
                    let elapsed = now_ms().saturating_sub(ready_at) / 1000;
                    if elapsed <= state.config.ready_countdown_secs as u64 {
                        tracing::debug!("[TICK] Table {} Waiting: {} active, ready countdown {}/5s", table_id, active_count, elapsed);
                        return true;
                    }
                    tracing::info!("[TICK] Table {} Waiting → starting hand ({} active)", table_id, active_count);

                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            let seated_ready = table.seats().values()
                                .filter(|s| s.player.is_some() && !s.sitting_out)
                                .count();
                            if seated_ready >= MIN_START_NUM as usize {
                                // 对齐 Move tick → do_start_hand：start_hand 内部会
                                // move_button + start_preflop_shuffle + advance_shuffle
                                let _ = table.start_shuffle();
                            }
                        }
                    }
                    state_c.send_shuffle_notice(table_id).await;
                    broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("--- New hand started ---")).await;
                } else {
                    tracing::info!("[TICK] Table {} Waiting: setting ready_at, starting 5s countdown", table_id);
                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.set_ready_at(now_ms());
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, Some("---New hand starting in 5 seconds---")).await;
                }
            } else {
                // 活跃玩家不足（含刷新断线被标记 sitting_out 的瞬态）：保持循环存活。
                // 旧实现 return false 永久停掉循环且无人重启，玩家重连后牌桌冻结。
                // 同时清掉过期的 ready 倒计时，等人齐后重新走完整 5s 起手流程。
                if ready_at != 0 {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.set_ready_at(0);
                    }
                }
                return true;
            }
        }
        RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River => {
            // Priority 5: betting round
            let timeout_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.check_betting_timeout(state.config.betting_timeout_secs)
                } else { None }
            };
            if let Some(res) = timeout_result {
                tracing::info!("[TICK] Table {} {:?}: betting timeout → {}", table_id, round_state, res.message);
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                handle_turn_advance(io, state, table_id).await;
                return true;
            }

            let auto_folded = handle_auto_fold(io, state, table_id).await;

            // 修复：handle_auto_fold 内部 fold 后已调用 handle_turn_advance，
            // 此处不再重复检查 is_complete，避免双重推进 turn（导致连续行动/阶段跳进）。
            if !auto_folded {
                let is_complete = {
                    let gs = state.state.read().await;
                    if let Some(table) = gs.tables.get(&table_id) {
                        table.is_betting_round_complete()
                    } else { false }
                };

                if is_complete {
                    tracing::info!("[TICK] Table {} {:?}: betting round complete, advancing", table_id, round_state);
                    handle_turn_advance(io, state, table_id).await;
                }
            }
        }
        RoundState::Showdown => {
            // Priority 6: showdown
            if showdown_at != 0 {
                let elapsed = now_ms().saturating_sub(showdown_at) / 1000;
                if elapsed >= state.config.showdown_display_secs as u64 {
                    tracing::info!("[TICK] Table {} Showdown: display time elapsed, finishing showdown", table_id);
                    // on_reveal_complete(ShowdownReveal) 已确定赢家并设置 showdown_at，
                    // 此处只需 finish_showdown 重置牌桌。使用 settle_hand 会重复分配底池。
                    {
                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.finish_showdown();
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, None).await;
                } else {
                    tracing::debug!("[TICK] Table {} Showdown: displaying results {}/{}s", table_id, elapsed, state.config.showdown_display_secs);
                }
            } else {
                // showdown_at 未设置，设置它（下一轮 tick 再检查超时）
                tracing::info!("[TICK] Table {} Showdown: setting showdown_at", table_id);
                {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.set_showdown_at(now_ms());
                    }
                }
            }
        }
    }
    true
}

pub(crate) async fn handle_auto_fold(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    // 超时自动行动：
    // 超时自动行动按游戏规则：可 check（无需跟注）→ Check；
    // 面对 raise/all-in 无法 check → Fold。不按 socket 连接状态判断
    // （网络抖动下"断连"误判会把在线玩家连弃带踢出局）。
    enum AutoAction { Fold(String), Check(String), Call(String) }
    let action = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            // 自动行动闸门：下注轮开始后至少等待 AUTO_ACT_DELAY_SECS 秒才
            // 替当前行动者行动，给真实玩家（与 mirror/客户端的相位同步）
            // 留出操作窗口；否则 500ms tick 会把整手牌在数秒内推完。
            const AUTO_ACT_DELAY_MS: u64 = 5_000;
            let started = table.betting_started_at();
            if started == 0
                || now_ms().saturating_sub(started) < AUTO_ACT_DELAY_MS
            {
                return false;
            }
            if let Some(turn_id) = table.turn() {
                table.seats().get(&turn_id).and_then(|seat| {
                    if seat.folded {
                        return None;
                    }
                    let pk_hex = seat.player.as_ref().map(|p| p.pk_hex.clone())?;
                    let call_amount = table.summary.call_amount.unwrap_or(0);
                    let my_bet = seat.bet;
                    // 大盲 = 2×min_bet（summary.meta.big_blind 是陈旧值 2，会把盲注
                    // 跟注误判为 raise 而自动弃牌）
                    let big_blind = table.summary.min_bet.saturating_mul(2);
                    // 规则源：legal_auto_action（#18 纯函数，与未来 §8.2 电路
                    // 合法性表达式共用同一规则——改规则先改这里与测试）。
                    use crate::pokergame::actions::{legal_auto_action, AutoActionKind};
                    match legal_auto_action(call_amount, my_bet, big_blind)? {
                        AutoActionKind::Check => Some(AutoAction::Check(pk_hex.to_string())),
                        AutoActionKind::Call => Some(AutoAction::Call(pk_hex.to_string())),
                        AutoActionKind::Fold => Some(AutoAction::Fold(pk_hex.to_string())),
                    }
                })
            } else {
                None
            }
        } else {
            None
        }
    };
    match action {
        Some(AutoAction::Fold(pk_hex)) => {
            let fold_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.handle_fold(&GamePkHex(pk_hex.clone()))
                } else {
                    None
                }
            };
            if let Some(res) = fold_result {
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                // #17 auto 默认动作标记：服务器代打入日志（seq 服务器分配）
                let auto_receipt = {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        if let Some(seat) = table.find_player_by_pk(&GamePkHex(pk_hex.clone())).map(|x| x.id) {
                            let seq = table.accepted_seq_of(seat) + 1;
                            table.record_action(seat, seq, "fold", 0, true, false, None);
                            Some(build_action_receipt_payload(table_id, &GamePkHex(pk_hex.clone()), seq, "fold", 0, "autoAccepted", ""))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(p) = &auto_receipt {
                    if !p.is_null() {
                        super::broadcast::broadcast_action_receipt(io, state, table_id, p).await;
                    }
                }
                handle_turn_advance(io, state, table_id).await;
                // 已 fold 并推进 turn，调用方不应再次检查 is_complete（避免双重推进）
                return true;
            }
            false
        }
        Some(AutoAction::Check(pk_hex)) => {
            let check_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.handle_check(&GamePkHex(pk_hex.clone()))
                } else {
                    None
                }
            };
            if let Some(res) = check_result {
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                // #17 auto 默认动作标记：服务器代打入日志（seq 服务器分配）
                let auto_receipt = {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        if let Some(seat) = table.find_player_by_pk(&GamePkHex(pk_hex.clone())).map(|x| x.id) {
                            let seq = table.accepted_seq_of(seat) + 1;
                            table.record_action(seat, seq, "check", 0, true, false, None);
                            Some(build_action_receipt_payload(table_id, &GamePkHex(pk_hex.clone()), seq, "check", 0, "autoAccepted", ""))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(p) = &auto_receipt {
                    if !p.is_null() {
                        super::broadcast::broadcast_action_receipt(io, state, table_id, p).await;
                    }
                }
                handle_turn_advance(io, state, table_id).await;
                return true;
            }
            false
        }
        Some(AutoAction::Call(pk_hex)) => {
            let call_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.handle_call(&GamePkHex(pk_hex.clone()))
                } else {
                    None
                }
            };
            if let Some(res) = call_result {
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                // #17 auto 默认动作标记：服务器代打入日志（seq 服务器分配）
                let auto_receipt = {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        if let Some(seat) = table.find_player_by_pk(&GamePkHex(pk_hex.clone())).map(|x| x.id) {
                            let seq = table.accepted_seq_of(seat) + 1;
                            table.record_action(seat, seq, "call", 0, true, false, None);
                            Some(build_action_receipt_payload(table_id, &GamePkHex(pk_hex.clone()), seq, "call", 0, "autoAccepted", ""))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some(p) = &auto_receipt {
                    if !p.is_null() {
                        super::broadcast::broadcast_action_receipt(io, state, table_id, p).await;
                    }
                }
                handle_turn_advance(io, state, table_id).await;
                return true;
            }
            false
        }
        None => false,
    }
}

pub(crate) async fn handle_turn_advance(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.reveal_token_state.is_active() {
                // 揭牌仪式进行中不推进 turn/phase。此时 betting_round 是上一街
                // 的陈旧轮（street 完成从不清掉），is_betting_round_complete 在
                // tick/兜底路径上会误判为 true 而二次 advance_to_next_phase——
                // 多发一张公共牌并跳街（2026-09-07 线上复现：hand 1788801359
                // 重复 check 触发二次推进，证明日志无法被镜像 VM 重放）。
                // 仪式的推进由 on_reveal_complete 链条独立驱动。
                tracing::debug!(
                    "[handle_turn_advance] table {} reveal ceremony active — skip",
                    table_id
                );
            } else if table.unfolded_players().len() <= 1 {
                table.end_without_showdown();
            } else if table.is_betting_round_complete() {
                // 单一状态重构：街道推进的唯一触发是 VM dispatch 内的
                // normalize（收注 + 推街）→ 视图同步（apply_betting_view /
                // refresh_from_vm 的相位联锁）→ advance_to_next_phase。
                // 此处的游戏层"轮次完成即推街"分支已删除——它与 VM 推进
                // 并存正是双重推街（2026-09-14 活锁）与多发公共牌
                // （2026-09-07）的根因。走到这里仍认为轮次完成 = 视图
                // 滞后于 VM，从 VM 重派生一次（含必要的相位联锁）。
                tracing::warn!(
                    "[handle_turn_advance] table {table_id} betting round looks complete — \
                     refreshing view from VM (street advance is VM-authoritative)"
                );
                table.refresh_from_vm();
                if table.reveal_token_state.is_active() {
                    // VM 已推街且联锁已执行发牌仪式。
                } else {
                    table.set_betting_started_at(now_ms());
                }
            } else {
                // turn 轮转由 VM 视图同步负责（refresh_from_vm /
                // apply_betting_view）；本地手动轮转分支已随 fail-closed
                // 删除（不可证明手不存在下注轮）。
                table.set_betting_started_at(now_ms());
            }
            Some(())
        } else { None }
    };
    if result.is_some() {
        broadcast::broadcast_to_table(io, state, table_id, None).await;
        broadcast_reveal_notice_if_active(io, state, table_id).await;
        // crypto_event: reveal phase started (if active)
        state.broadcast_crypto_event(
            table_id,
            broadcast::CryptoEventType::RevealToken,
            "".to_string(),
            None, true,
            Some("reveal phase started".to_string()),
            None,
        ).await;
    }
}

/// #17：构建回签收据 payload（operator 无密钥时退化为未签名通知）。
/// **同步、无锁**——必须在 process_action 的状态写锁释放后广播。
#[allow(clippy::too_many_arguments)]
fn build_action_receipt_payload(
    table_id: u32,
    player_pk_hex: &crate::pokergame::player::GamePkHex,
    seq: u64,
    action: &str,
    amount: u64,
    decision: &str,
    reason: &str,
) -> serde_json::Value {
use crate::pokergame::receipts;
    let Some((_, operator_pk)) = receipts::operator() else {
        return serde_json::Value::Null;
    };
    let receipt = receipts::ActionReceipt {
        table_id,
        player_pk: player_pk_hex.0.clone(),
        seq,
        action: action.to_string(),
        amount,
        decision: decision.to_string(),
        reason: reason.to_string(),
        operator_pk,
    };
    let Some((r_hex, s_hex)) = receipts::sign_receipt_with_operator(&receipt) else {
        return serde_json::Value::Null;
    };
    serde_json::json!({ "receipt": receipt, "rHex": r_hex, "sHex": s_hex })
}

pub(crate) async fn process_action(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, req: ActionRequest) {
    // C2 防重放入口查重：带 seq 的动作若已被接受过，直接丢弃（覆盖
    // enforcement off 迁移窗口；enforcement on 时 seq 单调校验本已兜底）。
    if let Some(seq) = req.seq {
        if state.is_action_processed(table_id, &req.pk_hex.0, seq) {
            tracing::info!("[process_action] duplicate action dropped: table={table_id} pk={} seq={seq}", req.pk_hex.0);
            return;
        }
    }
    // #17：在状态写锁内只收集回执 payload，锁释放后统一广播
    //（此前在锁内 await 读锁 → 死锁，表现为下注面板点击无响应）。
    let mut pending_receipts: Vec<serde_json::Value> = Vec::new();
    // 入口轮次校验是否通过——check 失败兜底推进仅在此为 true 时生效，
    // 否则仪式/非本回合被拒的 check 也会推进 turn/phase（陈旧下注轮上
    // 会二次 advance，多发公共牌并跳街）。
    let mut gate_passed = false;
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            // F8 fix: validate that it's the requesting player's turn and
            // the game is in a betting phase before processing any action.
            let is_betting_phase = matches!(table.round_state(),
                RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River);
            // 揭牌仪式（翻前底牌/公共牌/摊牌）期间拒绝一切下注动作：该窗口内
            // betting_round 是上一街的陈旧轮、turn 仍指向上一个行动人，仅凭
            // 轮次校验会误放行——动作会带着陈旧轮语义改写底池并被记入证明日志，
            // 镜像 VM（严格轮转）无法重放 → 结算 build failed。
            let ceremony_active = table.reveal_token_state.is_active();
            let is_valid_turn = !ceremony_active && is_betting_phase && table.turn().map_or(false, |turn_id| {
                table.seats().get(&turn_id).map_or(false, |seat| {
                    seat.player.as_ref().map_or(false, |p| p.pk_hex == req.pk_hex)
                        && !seat.folded
                        && !seat.sitting_out
                        && seat.stack > 0
                })
            });

            if !is_valid_turn {
                tracing::warn!(
                    "[process_action] Rejected action {} from pk={}: not their turn or not betting phase (turn={:?}, state={:?})",
                    req.action, req.pk_hex, table.turn(), table.round_state()
                );
                pending_receipts.push(build_action_receipt_payload(table_id, &req.pk_hex, req.seq.unwrap_or(0), &req.action, req.amount.unwrap_or(0), "rejected", "not_turn_or_phase"));
                None
            } else {
                gate_passed = true;
                // F9 fix: only clear sitting_out after turn validation passes.
                // (A valid turn implies the player is not sitting_out, but we
                // keep this for safety in case of race conditions.)
                if let Some(seat) = table.find_player_by_pk_mut(&req.pk_hex) {
                    seat.sitting_out = false;
                }
                // ===== #16/#17 抗审查：动作签名验证 + seq 单调 + 动作日志 =====
                // 签名域 = (table_id, seq, action, amount)；pk = 座位牌局公钥。
                let seat_id = table.find_player_by_pk(&req.pk_hex).map(|s| s.id);
                let amount_for_sig = req.amount.unwrap_or(0);
                let (sig_ok, seq_ok) = match (req.seq, req.sig.as_ref(), seat_id) {
                    (Some(seq), Some(sig), Some(seat)) => {
                        let sig_ok = table.verify_action_sig(
                            &req.pk_hex, seq, &req.action, amount_for_sig, sig,
                        );
                        let seq_ok = seq > table.accepted_seq_of(seat);
                        (sig_ok, seq_ok)
                    }
                    // 迁移期兼容：未签名动作（enforcement off 时放行）
                    _ => (true, true),
                };
                let enforcement = action_sig_required();
                let reject = (!sig_ok || !seq_ok) && enforcement;
                if reject {
                    let reason = if !sig_ok { "invalid_sig" } else { "seq_not_monotonic" };
                    tracing::warn!(
                        "[process_action] REJECT action {} seat {:?} seq {:?}: {reason} (enforcement on)",
                        req.action, seat_id, req.seq
                    );
                    if seat_id.is_some() {
                        pending_receipts.push(build_action_receipt_payload(table_id, &req.pk_hex, req.seq.unwrap_or(0), &req.action, amount_for_sig, "rejected", reason));
                    }
                    None
                } else {
                    if !sig_ok || !seq_ok {
                        // 区分性诊断：验签失败 vs seq 回退，附服务端视角的
                        // 域值（座位已接受 seq / 证明日志 hand_id）——客户端
                        // 签名域任一值不一致都会表现为 sig_ok=false
                        // （2026-09-08 hand 1788808419 seq 82 线上排查）。
                        tracing::warn!(
                            "[process_action] action {} seat {:?} seq {:?}: sig_ok={sig_ok} seq_ok={seq_ok} (server accepted_seq={}, proof_log_hand_id={:?}, table_id={}) — accepted unsigned (enforcement off)",
                            req.action,
                            seat_id,
                            req.seq,
                            seat_id.map(|s| table.accepted_seq_of(s)).unwrap_or(0),
                            table.hand_proof_log_start_hand_id(),
                            table_id
                        );
                    }
                    let action_result = match req.action.as_str() {
                        "fold" => table.handle_fold(&req.pk_hex),
                        "check" => table.handle_check(&req.pk_hex),
                        "call" => table.handle_call(&req.pk_hex),
                        "raise" => table.handle_raise(&req.pk_hex, req.amount.unwrap_or(0)),
                        "allin" => table.handle_allin(&req.pk_hex), // D2 fix
                        _ => None,
                    };
                    if action_result.is_some() {
                        if let Some(seat) = seat_id {
                            // seq 只前进不回退（未签名迁移动作保持 accepted 单调）
                            let seq = req.seq.unwrap_or(0).max(table.accepted_seq_of(seat));
                                                        // 留存签名本体（sig_ok 时）——递归证明 action-sig
                            // 批次与结算可审计性的数据源；验签失败不落签名。
                            let kept_sig = if sig_ok {
                                req.sig.clone()
                            } else {
                                None
                            };
                            table.record_action(seat, seq, &req.action, amount_for_sig, false, sig_ok, kept_sig);
                            // C2：接受点标记，入口查重据此拦截同 (table, pk, seq) 重放
                            state.mark_action_processed(table_id, &req.pk_hex.0, seq);
                            pending_receipts.push(build_action_receipt_payload(table_id, &req.pk_hex, seq, &req.action, amount_for_sig, "accepted", ""));
                        }
                    }
                    // 方案A：下注动作的 mirror 派发已移入 betting.rs 各 handle_*
                    // 的接受点（含超时自动行动路径），此处不再重复派发。
                    action_result
                }
            }
        } else { None }
    };
    // 状态锁已释放：统一广播回执
    for payload in pending_receipts.iter().filter(|p| !p.is_null()) {
        super::broadcast::broadcast_action_receipt(io, state, table_id, payload).await;
    }
    if let Some(res) = result {
        broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
        handle_turn_advance(io, state, table_id).await;
    } else if gate_passed && req.action == "check" {
        // check 成功但无消息（handle_check 返回 None）：仍需推进 turn/round，
        // 否则两人互相 check 时 turn 永不轮转、30 秒下注超时废掉整手。
        handle_turn_advance(io, state, table_id).await;
    }
}

pub(crate) async fn clear_for_one_player(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.clear_win_messages();
        }
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut gs = state_c.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.clear_seat_hands();
                table.reset_board_and_pot();
            }
        }

        broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("Waiting for more players")).await;
    });
}
