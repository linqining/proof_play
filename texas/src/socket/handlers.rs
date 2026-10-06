use std::sync::Arc;

use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};

use crate::auth;
use crate::pokergame::player::truncate_name;
use super::*;

/// shuffle 提交错误里的状态机拒绝类（重复/迟到提交、非当前洗牌者）——
/// 非密码学失败，zk 面板按"state rejected"而非"proof failed"展示。
fn shuffle_state_rejection(err: &str) -> bool {
    err.contains("not active") || err.contains("Not current player")
}


/// 获取用户可用筹码（PokerVault 链上筹码 - locked_chips）。
/// 链上查询不可用（dev 模式）时返回 0 可用。
async fn get_available_chips(state: &Arc<SocketState>, user: &crate::models::User) -> i64 {
    // 嵌入式/monad 会话：appchain note 是余额权威（dev faucet 与 L1Bridge
    // 存款都铸 note）；Starknet PokerVault 仍是遗留 Starknet 桌面的权威。
    if let Some(wei) = crate::starknet::appchain::runtime::note_balance_wei_of_address(&user.address) {
        let _ = state;
        let chips =
            i64::try_from(wei / crate::starknet::config::WEI_PER_CHIP).unwrap_or(i64::MAX);
        return chips.saturating_sub(user.locked_chips).max(0);
    }
    // Starknet-only：筹码余额来自 PokerVault 链上筹码（dev 模式无 vault 时返回 0 可用）。
    let _ = state;
    match crate::starknet::chips::vault_chip_balance_wei(&user.address).await {
        Some(wei) => {
            // u128→i64 截断与减法下溢防护（audit H2）：玩家可绕过服务器直接
            // withdraw，链上余额可能低于 locked_chips；异常大余额钳到 i64::MAX。
            let chips = i64::try_from(wei / crate::starknet::config::WEI_PER_CHIP)
                .unwrap_or(i64::MAX);
            chips.saturating_sub(user.locked_chips).max(0)
        }
        None => {
            tracing::warn!("[get_available_chips] vault chip balance unavailable for {}", user.address);
            0
        }
    }
}



/// 把前端上送的 reveal token JSON 批量解析为协议层 `RevealToken`。
///
/// WS `REVEAL_SUBMIT` 与 HTTP `submit_reveal_token`（handlers.rs）共用；
/// 错误文案带 `Token[idx]` 前缀，两条路径逐字一致。
pub(crate) fn parse_reveal_tokens(
    player_pk: EcPoint,
    items: &[SubmitRevealTokenJson],
) -> Result<Vec<poker_protocol::z_poker::protocol::RevealToken>, String> {
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let encrypted_card = item.encrypted_card.to_ciphertext()
                .map_err(|e| format!("Token[{}]: Invalid encrypted_card: {}", idx, e))?;
            let reveal_token = poker_protocol::z_poker::convert::hex_to_ecpoint(&item.reveal_token_hex)
                .map_err(|e| format!("Token[{}]: Invalid reveal_token_hex: {}", idx, e))?;
            let proof = item.reveal_token_proof.to_proof()
                .map_err(|e| format!("Token[{}]: Invalid reveal_token_proof: {}", idx, e))?;
            Ok(poker_protocol::z_poker::protocol::RevealToken {
                user_public_key: player_pk,
                encrypted_card,
                proof,
                reveal_token,
            })
        })
        .collect()
}

/// A3 修复：验证 socket 发送者拥有所声称的 pk_hex。
///
/// 通过 socket_id 查找 player 的 wallet_address，再通过 table 查找该 wallet_address 对应的 pk_hex，
/// 与请求中声称的 pk_hex 比较。验证失败时 emit error 事件并返回 false。
async fn verify_socket_sender(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    claimed_pk_hex: &GamePkHex,
) -> bool {
    let socket_id = socket.id.to_string();
    let expected_pk = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        wallet.and_then(|wa| {
            gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
        })
    };
    match expected_pk {
        Some(pk) if &pk == claimed_pk_hex => true,
        Some(pk) => {
            tracing::warn!(
                "[verify_socket_sender] pk_hex mismatch: socket_id={}, table_id={}, expected={}, claimed={}",
                socket_id, table_id, pk, claimed_pk_hex
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "pk_hex does not belong to sender"}));
            false
        }
        None => {
            tracing::warn!(
                "[verify_socket_sender] cannot resolve pk_hex for socket_id={}, table_id={}",
                socket_id, table_id
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "Cannot verify sender identity"}));
            false
        }
    }
}

/// A3 修复：验证 socket 发送者拥有所声称的 seat_id。
///
/// 用于 REBUY 等不带 pk_hex 的事件：通过 socket_id 查找 player 的 wallet_address，
/// 再验证 table 中 seat_id 的 player.wallet_address 与之一致。
async fn verify_socket_sender_seat(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
) -> bool {
    let socket_id = socket.id.to_string();
    let wallet_match = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        match wallet {
            Some(wa) => {
                gs.tables.get(&table_id)
                    .map_or(false, |t| {
                        t.seats().get(&seat_id)
                            .and_then(|seat| seat.player.as_ref())
                            .map_or(false, |gp| gp.wallet_address.0 == wa.0)
                    })
            }
            None => false,
        }
    };
    if !wallet_match {
        tracing::warn!(
            "[verify_socket_sender_seat] seat ownership mismatch: socket_id={}, table_id={}, seat_id={}",
            socket_id, table_id, seat_id
        );
        let _ = socket.emit("error", &serde_json::json!({"msg": "Seat does not belong to sender"}));
        false
    } else {
        true
    }
}

// ============================================================================
// SIT_DOWN_V2 helpers
// ============================================================================

/// Validates SIT_DOWN_V2 request: auth, amount, pk, player, balance.
/// Returns `Some((player, player_pk))` if valid, `None` if error already emitted.
async fn validate_sit_down_request(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &SitDownV2Payload,
) -> Option<(Player, EcPoint)> {
    let socket_id = s.id.to_string();

    let claims = match auth::verify_token(&payload.token, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Token verification failed for socket_id: {}, error: {}", socket_id, e);
            let _ = s.emit("error", &serde_json::json!({"msg": "Authentication failed, please reconnect your wallet"}));
            return None;
        }
    };
    let user_id = claims.user.id.clone();
    tracing::info!("[SIT_DOWN_V2] Received from {}: table_id={}, seat_id={}, amount={}, pk_hex={}, user_id={}",
        socket_id, payload.table_id, payload.seat_id, payload.amount, payload.pk_hex, user_id);

    // E3 修复：校验 amount > 0，避免 0 或负值导致的逻辑错误
    if payload.amount == 0 {
        tracing::warn!("[SIT_DOWN_V2] Invalid amount=0 from socket_id={}", socket_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
        return None;
    }

    // 买入下限：入座买入须 ≥ 大盲（min_bet×2）。下限只在买入入座这一次
    // 校验——VM join_table 不设下限，已入座的续座玩家允许以不足大盲的
    // 筹码继续参与（split-pot 半盲筹码是常规路径，真实规则）。
    let big_blind = {
        let gs = state.state.read().await;
        gs.tables
            .get(&payload.table_id)
            .map(|t| t.summary.min_bet.saturating_mul(2))
    };
    if let Some(big_blind) = big_blind {
        if payload.amount < big_blind {
            tracing::warn!(
                "[SIT_DOWN_V2] buy-in below big blind: amount={}, big_blind={}",
                payload.amount,
                big_blind
            );
            let _ = s.emit(
                "error",
                &serde_json::json!({"msg": format!("Buy-in must be at least the big blind ({big_blind})")}),
            );
            return None;
        }
    }

    // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
    let deduct = match i64::try_from(payload.amount) {
        Ok(v) => -v,
        Err(_) => {
            tracing::warn!("[SIT_DOWN_V2] Amount too large for i64: {}", payload.amount);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
            return None;
        }
    };

    let player_pk = match hex_to_ecpoint(&**payload.pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Invalid pk_hex: {}", e);
            return None;
        }
    };

    let player = {
        let gs = state.state.read().await;
        gs.players.get(&socket_id).cloned()
    };

    let player = match player {
        Some(p) if p.id == user_id => p,
        Some(p) => {
            tracing::warn!("[SIT_DOWN_V2] Player id mismatch: socket_id={}, token_user_id={}, player_id={}", socket_id, user_id, p.id);
            return None;
        }
        None => {
            let db_user = state.db.find_user_by_id(&user_id).await;
            match db_user {
                Some(user) => {
                    let bankroll = get_available_chips(&state, &user).await;
                    let mut gs = state.state.write().await;
                    let p = Player {
                        socket_id: socket_id.clone(),
                        id: user.id,
                        name: user.name,
                        bankroll,
                        wallet_address: WalletAddress::new(user.address.clone()),
                    };
                    gs.players.insert(socket_id.clone(), p.clone());
                    p
                }
                None => {
                    tracing::warn!("[SIT_DOWN_V2] User not found in DB for user_id: {}", user_id);
                    return None;
                }
            }
        }
    };

    let player_id = player.id.clone();

    // E3 修复：检查用户余额是否足够（PokerVault 链上筹码 - locked_chips）
    // #验收修复：携带 deposit_tx_hash 时**跳过该预检**——钱包返回哈希≠上链
    // 确认，latest 余额读数会抢先拒绝（用户实测 "Insufficient chips"）。
    // 权威校验由下方 verify_deposit 轮询回执 + 筹码覆盖完成。
    let has_deposit_tx = payload
        .deposit_tx_hash
        .as_deref()
        .is_some_and(|h| !h.trim().is_empty());
    let db_user = state.db.find_user_by_id(&player_id).await;
    if let Some(ref user) = db_user {
        if !has_deposit_tx {
            let available = get_available_chips(&state, user).await;
            if available < payload.amount as i64 {
                tracing::warn!(
                    "[SIT_DOWN_V2] Insufficient chips: user_id={}, available={}, required={}",
                    player_id,
                    available,
                    payload.amount
                );
                let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
                return None;
            }
        } else {
            // monad 桌面：EVM deposit 哈希走 L1Bridge 存证核验（回执成功 +
            // DepositInitiated.to==买家 + 面额覆盖）并即时铸 note；Starknet
            // 桌面的权威校验在 VM join 侧（verify_deposit），此处维持跳过。
            let is_monad = crate::starknet::appchain::runtime::runtime()
                .is_some_and(|rt| rt.config.provider == "monad");
            let looks_evm = payload
                .deposit_tx_hash
                .as_deref()
                .is_some_and(|h| h.starts_with("0x") && h.len() == 66);
            if is_monad && looks_evm {
                let tx_hash = payload.deposit_tx_hash.clone().unwrap_or_default();
                // 差额买入：先算已可用余额（note − locked），服务端核验
                // "available + 存款面额 ≥ 买入额"。
                let available = get_available_chips(&state, user).await;
                match crate::starknet::appchain::monad_bridge::verify_deposit_and_mint(
                    &tx_hash,
                    &user.address,
                    payload.amount as i64,
                    available,
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            "[SIT_DOWN_V2] monad deposit verified & minted: tx={tx_hash}"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[SIT_DOWN_V2] monad deposit verification failed: {e}"
                        );
                        let _ = s.emit(
                            "error",
                            &serde_json::json!({"msg": format!("Monad buy-in verification failed: {e}")}),
                        );
                        return None;
                    }
                }
            } else {
                tracing::info!(
                    "[SIT_DOWN_V2] deposit tx present — deferring balance check to buy-in verification"
                );
            }
        }
    }

    let _ = deduct; // suppress unused warning (preserved from original)
    Some((player, player_pk))
}



/// Broadcasts the sit down result (success or failure) and starts game loop if all complete.
async fn broadcast_sit_down(
    io: &SocketIo,
    s: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
    pk_hex: &GamePkHex,
    amount: u64,
    player_id: &str,
    player_name: &str,
    result: Result<(bool, JoinResult), JoinError>,
) {
    match result {
        Ok((all_complete, join_result)) => {
            // 锁定筹码（入座时扣除可用余额）
            let _ = state.db.lock_chips(player_id, amount as i64).await;

            let msg = match join_result {
                JoinResult::JoinedAndShuffled => format!("{} sat down in Seat {} and shuffled", player_name, seat_id),
                JoinResult::JoinedWaiting => format!("{} sat down in Seat {}, waiting for next hand", player_name, seat_id),
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;

            // ZK 可视化：shuffle 证明验证成功（join_and_shuffle_verified 中 shuffle 已验证）
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                true,
                Some("shuffle proof verified".to_string()),
                None,
            ).await;

            // 无条件确保 game loop 运行（start_game_loop 内部按 registry 去重）。
            // 此前仅 all_complete（入座即完成末次洗牌）时拉起；若上一手结束后
            // loop 已退出且新入座玩家不是末次洗牌者，牌桌会永久停在 Waiting。
            let _ = all_complete;
            tracing::info!("[SIT_DOWN_V2] ensuring game loop running for table {}", table_id);
            state.start_game_loop(io.clone(), state.clone(), table_id).await;
        }
        Err(e) => {
            // 入座失败回传发起者（deck 竞态/证明失败），客户端据此提示或重试
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("Sit down failed: {e}. Please try again."),
                "action": "sit_down",
            }));
            tracing::warn!("[SIT_DOWN_V2] Failed to join and shuffle: {}", e);
            // ZK 可视化：区分状态机拒绝（重复/迟到提交，非密码学问题）与
            // 真正的证明验证失败——2026-09-07 前 "Shuffle not active" 这类
            // 状态拒绝被误标为"证明失败"造成面板误报 ✗。
            let err_text = format!("{e}");
            let rejection = shuffle_state_rejection(&err_text);
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                false,
                Some(if rejection {
                    format!("shuffle submit rejected (state): {}", e)
                } else {
                    format!("shuffle proof verification failed: {}", e)
                }),
                None,
            ).await;
        }
    }
}

// ============================================================================
// STAND_UP helpers
// ============================================================================



/// Handles STAND_UP local mode: verifies leave proof, removes player, broadcasts.
async fn handle_stand_up_local(
    state: &Arc<SocketState>,
    io: &SocketIo,
    payload: &StandUpPayload,
    pk_hex: &GamePkHex,
    player_pk: &EcPoint,
    table_id: u32,
    socket_id: &str,
) {
    // Verify LeaveProof and remove player
    let player_id = {
        let gs = state.state.read().await;
        gs.players.get(socket_id).map(|p| p.id.clone())
    };

    // 幂等检查：若玩家已不在 table.players 和 pk_to_seat 中，说明已被移除
    // （relayer 已同步 PlayerLeft 事件、或 reset_for_next_hand 清理、或重复 STAND_UP）。
    // 直接返回成功，避免 "Player not found" 警告。
    {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            if !table.players().contains_key(pk_hex) && !table.pk_to_seat.contains_key(pk_hex) {
                tracing::info!(
                    "[STAND_UP] player {} already removed from table {}, idempotent skip",
                    pk_hex, table_id
                );
                drop(gs);
                // 广播最新状态，让前端同步
                let tables_info = state.get_current_tables().await;
                let players_info = state.get_current_players().await;
                let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
                return;
            }
        } else {
            tracing::warn!("[STAND_UP] table {} not found", table_id);
            return;
        }
    }

    // 注：on-chain 模式已在上方提前 return，以下为 off-chain 模式的本地处理路径。
    // 持写锁块内禁止 await：state 是覆盖所有桌的全局单锁，跨 await 会冻结
    // 全服的 tick 与 socket handler。DB 退还筹码移到锁外执行，锁内只同步
    // 收集待退还额度（必须在 remove_player 之前读取 seat.stack）。
    let (stand_msg, need_clear, leave_proof_verified, chips_to_unlock) = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            let msg = table.find_player_by_pk(pk_hex)
                .and_then(|seat| {
                    seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                });

            // Return chips before removing（锁内仅记录额度，锁外执行 DB await）
            let chips_to_unlock = match (&player_id, table.find_player_by_pk(pk_hex)) {
                (Some(pid), Some(seat)) => Some((pid.clone(), seat.stack as i64)),
                _ => None,
            };

            // Verify leave proof and remove player
            // off-chain 模式下 leave_round 可能为 None（例如客户端未生成 proof），
            // 此时直接走 remove_player_by_pk 回退路径。
            let verified = match payload.leave_round.as_ref() {
                Some(lr) => match table.leave_player_with_proof(pk_hex, player_pk, lr) {
                    Ok(()) => {
                        tracing::info!("[STAND_UP] Leave proof verified, player {} removed", pk_hex);
                        true
                    }
                    Err(e) => {
                        tracing::warn!("[STAND_UP] Leave proof verification failed: {}, falling back to remove_player_by_pk", e);
                        table.remove_player_by_pk(pk_hex);
                        false
                    }
                },
                None => {
                    tracing::info!("[STAND_UP] No leave_round provided, removing player {} by pk", pk_hex);
                    table.remove_player_by_pk(pk_hex);
                    false
                }
            };

            let clear = table.active_players().len() == 1;
            (msg, clear, verified, chips_to_unlock)
        } else { (None, false, false, None) }
    };
    if let Some((pid, stack)) = chips_to_unlock {
        let _ = state.db.unlock_chips(&pid, stack).await;
    }

    broadcast::broadcast_to_table(io, state, table_id, stand_msg.as_deref()).await;

    // ZK 可视化：leave 证明验证结果
    state.broadcast_crypto_event(
        table_id,
        broadcast::CryptoEventType::Leave,
        pk_hex.0.clone(),
        None,
        leave_proof_verified,
        Some(if leave_proof_verified {
            "leave proof verified".to_string()
        } else {
            "leave proof verification failed".to_string()
        }),
        None,
    ).await;

    let tables_info = state.get_current_tables().await;
    let players_info = state.get_current_players().await;
    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

    if need_clear {
        state.stop_game_loop(table_id).await;
        game_loop::clear_for_one_player(io, state.clone(), table_id).await;
    }
}






/// 统一 payload 解析：socketioxide 的 `Data::<T>` 解析失败是静默的
/// （handler 不执行、无任何日志），两端字段命名漂移时表现为“消息消失”。
/// 所有 handler 统一先收 `serde_json::Value`，再用本宏显式解析并记录
/// 失败原因与原始 JSON。
macro_rules! parse_payload {
    ($event:expr, $raw:expr, $ty:ty) => {
        match serde_json::from_value::<$ty>($raw.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[{}] payload parse failed: {}, raw: {}", $event, e, $raw);
                return;
            }
        }
    };
}

pub fn register_handlers(io: &SocketIo) {
    io.ns("/", async move |socket: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        on_connect(socket, io, state);
    });
}

fn on_connect(socket: SocketRef, _io: SocketIo, _state: Arc<SocketState>) {
    socket.on(actions::FETCH_LOBBY_INFO, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let token = match payload_raw.as_str() {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("[FETCH_LOBBY_INFO] payload parse failed: expected string, raw: {}", payload_raw);
                return;
            }
        };
        let claims = match auth::verify_token(&token, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => return,
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());
        let new_socket_id = s.id.to_string();
        let user_id = claims.user.id.clone();

        let old_player = {
            let gs = state.state.read().await;
            gs.players.values().find(|t| t.id == user_id).cloned()
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

        // 这个替换seat里面的player
        let (table_ids_to_broadcast, is_reconnect, reconnect_wallet) = if let Some(old_player) = old_player {
            tracing::info!("[RECONNECT] user {} found disconnected seat, old_sid={}, new_sid={}", user_id, old_player.socket_id.clone(), new_socket_id);
            let reconnect_wallet = old_player.wallet_address.clone();
            {
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
            }
            let reconnected_table_ids = {
                let mut gs = state.state.write().await;
                let mut ids = Vec::new();
                for table in gs.tables.values_mut() {
                    if table.reconnect_player(&old_player.wallet_address.0) {
                        ids.push(table.summary.id);
                    }
                }
                ids
            };

            let db_user = state.db.find_user_by_id(&user_id).await;
            if let Some(user) = db_user {
                let bankroll = get_available_chips(&state, &user).await;
                let mut gs = state.state.write().await;
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: user.id,
                    name: user.name,
                    bankroll,
                    wallet_address: WalletAddress::new(user.address.clone()),
                });
                gs.players.remove(&old_player.socket_id);
            }

            (reconnected_table_ids, true, Some(reconnect_wallet))
        }else{
            (Vec::new(), false, None)
        };

        // 这个替换players里面的player
        {
            let old_player = {
                let gs = state.state.read().await;
                gs.players.values().find(|p| p.id == user_id).cloned()
            };
            // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

            if let Some(ref old_player) = old_player {
                tracing::info!("[RECONNECT] user {} found active session in players, replacing old_sid={}", user_id, old_player.socket_id.clone());
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
                gs.players.remove(&old_player.socket_id);
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: old_player.id.clone(),
                    name: old_player.name.clone(),
                    wallet_address: old_player.wallet_address.clone(),
                    bankroll: old_player.bankroll,
                });
                for table in gs.tables.values_mut() {
                    table.reconnect_player(&old_player.wallet_address.0);
                }
            }
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());


        for tid in &table_ids_to_broadcast {
            if let Some(wallet) = reconnect_wallet.as_ref() {
                // 重连单次快照：一条 TABLE_UPDATED 携带该玩家的私人可读
                // 底牌（其余 socket 收普通视图）——底牌只在事件流里、错过
                // 即永久不可见（2026-09-08 线上"手牌看不见"），不做二次推送。
                broadcast::broadcast_to_table_with_snapshot(&io, &state, *tid, wallet).await;
            } else {
                broadcast::broadcast_to_table(&io, &state, *tid, None).await;
            }
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                // tracing::info!("on_connect FETCH_LOBBY_INFO: {} user={:?}", claims.user.id.clone(), user);
                let bankroll = get_available_chips(&state, &user).await;
                state.state.write().await.players.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    wallet_address: WalletAddress::new(user.address.clone()),
                    bankroll,
                });
            }
        }

        let lobby = LobbyInfo {
            tables: state.get_current_tables().await,
            players: state.get_current_players().await,
            socket_id: s.id.to_string(),
        };
        let _ = s.emit(actions::RECEIVE_LOBBY_INFO, &lobby);
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
    });

    socket.on(actions::JOIN_TABLE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::JOIN_TABLE, payload_raw, JoinTablePayload);
        let table_id = payload.table_id;
        s.join(table_room_name(table_id));
        tracing::info!("join_table: {} {}", payload.pk_hex, table_id);
        // 客户端（重新）进房即重投该桌待上链的待结算手（legacy 重投，
        // 上一手结算失败后进房即触发补偿）。
        tokio::spawn(crate::starknet::hooks::retry_pending_settlement(table_id));
        let socket_id = s.id.to_string();
        // let join_msg = {
        //     let mut gs = state.state.write().await;

        //     let player_data = gs.players.get(&socket_id).map(|p| (p.clone(), truncate_name(&p.name, 12)));

        //     if let Some(table) = gs.tables.get_mut(&table_id) {
        //         if let Some((player_clone, player_name)) = player_data {
        //             table.add_player(payload.pk_hex.clone(), player_clone.wallet_address.clone());
        //             tracing::info!("add_player: {}", socket_id);
        //             Some(format!("{} joined the table.", player_name))
        //         } else { None }
        //     } else { None }
        // };

        // let tables_info = state.get_current_tables().await;
        // {
        //     let gs = state.state.read().await;
        //     if let Some(table) = gs.tables.get(&table_id) {
        //         let wallet_addr = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        //         let table_view = wallet_addr.map(|wa| hide_opponent_cards(&table.to_client(), &wa));
        //         if let Some(table_view) = table_view {
        //             let _ = s.emit(actions::TABLE_JOINED, &TableUpdatePayload {
        //                 table: table_view,
        //                 message: join_msg.clone(),
        //                 from: None,
        //             });
        //         }
        //     }
        // }
        // let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;

        let wallet = {
            let gs = state.state.write().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone()).unwrap_or_else(|| WalletAddress::new("".to_string()))
        };

        broadcast::join_table_push(&io, &state, table_id, wallet).await;
        // 通知桌上所有已有玩家：新玩家加入后刷新各自的 table view
        // broadcast_to_table 会为每个玩家定制 view（hide_opponent_cards），
        // join_table_push 只发给新加入的 socket，已有玩家不会收到更新。
        broadcast::broadcast_to_table(&io, &state, table_id, Some("player joined")).await;
    });

    socket.on(actions::LEAVE_TABLE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::LEAVE_TABLE, payload_raw, LeaveTablePayload);
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let wallet_address = { state.state.read().await.players.get(&socket_id).map(|p| p.wallet_address.clone()) };
        tracing::info!("leave_table: {} {} {:?}", payload.pk_hex, table_id, wallet_address);
        // Derive pk_hex: prefer client-provided value, fallback to wallet_address lookup
        let pk_hex: Option<GamePkHex> = {
            let gs = state.state.read().await;
            if payload.pk_hex.0.is_empty() {
                // Client didn't provide pk_hex, lookup from table.players
                wallet_address.as_ref().and_then(|wa| {
                    gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
                })
            } else {
                // Verify client-provided pk_hex matches wallet_address
                if let Some(ref wa) = wallet_address {
                    if let Some(table) = gs.tables.get(&table_id) {
                        if let Some(looked_up) = table.get_pk_hex_by_wallet_address(&wa.0) {
                            if looked_up != payload.pk_hex {
                                tracing::warn!("[LEAVE_TABLE] pk_hex mismatch: client={}, server={}", payload.pk_hex, looked_up);
                            }
                        }
                    }
                }
                Some(payload.pk_hex.clone())
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                let name = wallet_address.as_ref().and_then(|wa| table.find_player_by_wallet(wa))
                    .and_then(|_| gs.players.get(&socket_id).map(|p| truncate_name(&p.name, 12)));
                (table.is_playing(), name)
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[LEAVE_TABLE] Table {}: {} is leaving while hand in progress, marking sitting_out", table_id, socket_id);
            if let Some(ref wallet_address) = wallet_address {
                state.mark_player_sitting_out(table_id, wallet_address).await;
            }
            let msg = player_name.map(|n| format!("{} is sitting out.", n));
            broadcast::broadcast_to_table(&io, &state, table_id, msg.as_deref()).await;
            // 通知客户端：手牌进行中，离开已延迟到手牌结束后再处理
            let _ = s.emit(actions::LEAVE_DEFERRED, &LeaveDeferredPayload {
                table_id,
                reason: "hand_in_progress".to_string(),
            });
            return;
        }
        s.leave(table_room_name(table_id));

        let chips_update = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                pk_hex.as_ref().and_then(|pk| table.find_player_by_pk(pk))
                    .and_then(|seat| {
                        gs.players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_update {
            let _ = state.db.unlock_chips(&pid, stack as i64).await;
        }

        let (leave_msg, need_clear, last_hand_id) = {
            let mut guard = state.state.write().await;
            let gs = &mut *guard;
            let name = gs.players.get(&socket_id).map(|p| p.name.clone());
            if let Some(table) = gs.tables.get_mut(&table_id) {
                if let Some(ref pk) = pk_hex {
                    tracing::info!("remove_player_by_pk: {}", pk);
                    table.leave_talbe_and_clear_shuffle(pk);
                } else {
                    tracing::warn!("[LEAVE_TABLE] No pk_hex found for socket_id={}, cannot remove player", socket_id);
                }
                let msg = name.map(|n| format!("{n} left the table."));
                let clear = table.active_players().len() == 1;
                (msg, clear, table.current_hand_id)
            } else { (None, false, 0) }
        };

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id, reason: None });

        if let Some(msg) = &leave_msg {
            broadcast::broadcast_to_table(&io, &state, table_id, Some(msg)).await;
        }

        // #33 离桌快解锁：不在其他桌 + 最后一手已结算 → 立即 force_unlock；
        // 最后一手还没结算（本分支无手牌进行中，但 settle 是异步的）→ 挂起，
        // 该手结算成功后由 settle 钩子 flush。链上操作不阻塞 socket 流程。
        if let Some(ref wa) = wallet_address {
            let seated_elsewhere = {
                let gs = state.state.read().await;
                gs.tables.values().any(|t| t.find_player_by_wallet(&wa.0).is_some())
            };
            if !seated_elsewhere {
                let wallet = wa.0.clone();
                let settled = crate::starknet::hooks::settle_ok_already(table_id, last_hand_id);
                tokio::spawn(async move {
                    crate::starknet::lock::schedule_leave_release(&wallet, last_hand_id, settled).await;
                });
            }
        }

        if need_clear {
            state.stop_game_loop(table_id).await;
            game_loop::clear_for_one_player(&io, state.clone(), table_id).await;
        }
    });

    socket.on(actions::FOLD, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        // #16：兼容两种载荷（裸 tableId / 带 seq+sig 的对象）
        let simple = parse_payload!(actions::FOLD, payload_raw, SimpleActionPayload);
        let table_id = simple.table_id;
        send_simple_action_signed(&s, &state, table_id, "fold", simple.seq, simple.sig).await;
    });

    socket.on(actions::CHECK, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let simple = parse_payload!(actions::CHECK, payload_raw, SimpleActionPayload);
        let table_id = simple.table_id;
        send_simple_action_signed(&s, &state, table_id, "check", simple.seq, simple.sig).await;
    });

    socket.on(actions::CALL, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let simple = parse_payload!(actions::CALL, payload_raw, SimpleActionPayload);
        let table_id = simple.table_id;
        send_simple_action_signed(&s, &state, table_id, "call", simple.seq, simple.sig).await;
    });

    socket.on(actions::RAISE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RAISE, payload_raw, RaisePayload);
        let socket_id = s.id.to_string();
        let pk_hex = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id)
                .and_then(|p| gs.tables.get(&payload.table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
        };
        if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(payload.table_id).await) {
            let req = ActionRequest { pk_hex, action: "raise".to_string(), amount: Some(payload.amount), seq: payload.seq, sig: payload.sig.map(|s| crate::pokergame::actions::ActionSig { r_hex: s.r_hex, s_hex: s.s_hex }) };
            if let Err(reason) = crate::socket::send_action_with_timeout(&sender, req).await {
                let _ = s.emit("error", &serde_json::json!({
                    "code": "GAME_LOOP_UNRESPONSIVE",
                    "msg": "桌面无响应，请稍后重试",
                    "detail": reason,
                    "action": "raise",
                    "table_id": payload.table_id
                }));
            }
        }
    });

    socket.on(actions::TABLE_MESSAGE, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::TABLE_MESSAGE, payload_raw, TableMessagePayload);
        let socket_ids = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id).map(|t| {
                t.players().iter()
                    .filter_map(|(_game_pk, wallet_addr)| {
                        gs.players.values()
                            .find(|p| p.wallet_address.0 == wallet_addr.0)
                            .map(|p| p.socket_id.clone())
                    })
                    .collect::<Vec<_>>()
            })
        };

        if let Some(sids) = socket_ids {
            for sid_str in sids {
                let table_view = {
                    let gs = state.state.read().await;
                    let wallet_addr = gs.players.get(&sid_str).map(|p| p.wallet_address.clone());
                    gs.tables.get(&payload.table_id).and_then(|t| wallet_addr.map(|wa| hide_opponent_cards(&t.to_client(), &wa)))
                };
                if let Some(table_view) = table_view {
                    let update = TableUpdatePayload {
                        table: table_view,
                        message: Some(payload.message.clone()),
                        from: Some(payload.from.clone()),
                        readable_cards: None,
                        deck_plaintext: None,
                    };
                    if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                        if let Some(socket) = io.get_socket(sid) {
                            let _ = socket.emit(actions::TABLE_UPDATED, &update);
                        }
                    }
                }
            }
        }
    });

    socket.on(actions::SIT_DOWN, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, _state: State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SIT_DOWN, payload_raw, SitDownPayload);
        let socket_id = s.id.to_string();
        tracing::warn!("[SIT_DOWN] Deprecated SIT_DOWN action received from {}, please use SIT_DOWN_V2. table_id={}, seat_id={}", socket_id, payload.table_id, payload.seat_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "SIT_DOWN is deprecated, please use SIT_DOWN_V2"}));
    });

    socket.on(actions::SIT_DOWN_V2, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SIT_DOWN_V2, payload_raw, SitDownV2Payload);

        // 关桌闸：终态桌不再接受入座（"关桌后不开新手"——入座本身不动钱，
        // 但拒绝入座避免玩家锁进一张永远不开局的桌）。
        {
            let gs = state.state.read().await;
            if gs.tables.get(&payload.table_id).is_some_and(|t| t.is_closed()) {
                let _ = s.emit("error", &serde_json::json!({
                    "code": "TABLE_CLOSED",
                    "msg": "本桌已关闭，不再接受入座",
                    "action": "sit_down",
                    "table_id": payload.table_id
                }));
                return;
            }
        }

        // 1. Validate request (auth, amount, pk, player, balance)
        let (player, player_pk) = match validate_sit_down_request(&s, &state, &payload).await {
            Some(v) => v,
            None => return,
        };

        // 1.5 Starknet 买入校验：PokerVault.deposit 交易回执必须成功，
        //     且（配置了 vault 时）vault 筹码余额覆盖买入数量。dev 模式自动放行。
        if let Some(ref deposit_tx_hash) = payload.deposit_tx_hash {
            let buyer = payload.wallet_address.clone().unwrap_or_else(|| player.wallet_address.0.clone());
            if let Err(e) = crate::starknet::chips::verify_deposit(deposit_tx_hash, &buyer, payload.amount as i64).await {
                tracing::warn!("[SIT_DOWN_V2] STRK20 buy-in verification failed, user={}, tx={}: {}", player.id, deposit_tx_hash, e);
                // #错误标准：按失败种类映射用户可读提示（detail 保留技术信息）
                let (code, msg) = if e.contains("not confirmed") {
                    ("BUYIN_TX_PENDING", "买入交易确认中，请稍候几秒重试")
                } else if e.contains("reverted") {
                    ("BUYIN_TX_REVERTED", "买入交易失败：请检查钱包交易记录")
                } else if e.contains("coverage") || e.contains("chip_balance") {
                    ("INSUFFICIENT_CHIPS", "vault 筹码余额不足：请确认买入已上链")
                } else {
                    ("BUYIN_VERIFY_FAILED", "买入校验未通过：请稍后重试，或联系支持")
                };
                let _ = s.emit("error", &serde_json::json!({
                    "code": code,
                    "msg": msg,
                    "detail": format!("{e}"),
                    "action": "sit_down",
                    "table_id": payload.table_id
                }));
                return;
            }
            tracing::info!("[SIT_DOWN_V2] STRK20 buy-in verified: user={}, amount={}, tx={}", player.id, payload.amount, deposit_tx_hash);
            // #33 在局锁定：入座成功即锁买入筹码（owner=operator，异步尽力
            // 而为）。player.id 形如 "wallet:0x..."，截取钱包 felt 地址。
            match i64::try_from(payload.amount) {
                Ok(lock_amount) => {
                    let lock_wallet =
                        player.id.strip_prefix("wallet:").unwrap_or(&player.id).to_string();
                    tokio::spawn(async move {
                        crate::starknet::lock::lock_player_chips(&lock_wallet, lock_amount).await;
                    });
                }
                Err(_) => {
                    tracing::error!("[SIT_DOWN_V2] amount too large to lock: {}", payload.amount);
                }
            }
        }

        // 2.5 #20 Phase 2：缓冲 join 证明（下一手 HandStart 快照消费；
        //     join_table 会验证 pk 所有权证明）
        {
            let pk_proof_bytes = payload.pk_proof.to_proof()
                .map(|p| crate::relayer::proof_bytes::serialize_pk_ownership_proof(&p))
                .unwrap_or_default();
            // P1-2 会话委托核验：客户端声明的会话交易公钥必须与链上 vault
            // 登记（买入同笔 multicall `set_session_tx_pk[_for]`）完全一致，
            // 核验通过的钥随 join 缓冲进入座位状态（VM 签名验证锚）。
            // 不一致/未登记 → None（该参与者签名路径未激活，仅告警——
            // 过渡期旧客户端；runtime 接线后升级为硬拒）。
            let verified_tx_pk = crate::starknet::lock::verify_session_tx_pk(
                &player.wallet_address.0,
                payload.session_tx_pk.as_deref(),
            )
            .await;
            crate::starknet::prove_log::record_join(
                payload.table_id,
                &player.wallet_address.0,
                &payload.pk_hex.0,
                pk_proof_bytes,
                verified_tx_pk,
            );
        }

        // 3. Local mode: init seat and shuffle
        let player_id = player.id.clone();
        let player_name = truncate_name(&player.name, 12);
        let result = state.join_player_and_shuffle(
            payload.table_id,
            player,
            player_pk,
            payload.pk_proof,
            payload.mask_and_shuffle_round,
            payload.seat_id,
            payload.amount,
        ).await;

        // 4. Broadcast result
        broadcast_sit_down(
            &io, &s, &state, payload.table_id, payload.seat_id, &payload.pk_hex,
            payload.amount, &player_id, &player_name, result,
        ).await;
    });

    socket.on(actions::REBUY, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REBUY, payload_raw, RebuyPayload);
        let socket_id = s.id.to_string();

        // E3 修复：校验 amount > 0
        if payload.amount == 0 {
            tracing::warn!("[REBUY] Invalid amount=0 from socket_id={}", socket_id);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
            return;
        }

        // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
        let _deduct = match i64::try_from(payload.amount) {
            Ok(v) => -v,
            Err(_) => {
                tracing::warn!("[REBUY] Amount too large for i64: {}", payload.amount);
                let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
                return;
            }
        };

        // A3 修复：验证发送者拥有该 seat_id
        if !verify_socket_sender_seat(&s, &state, payload.table_id, payload.seat_id).await {
            return;
        }

        let chips_deduct = {
            let mut gs = state.state.write().await;

            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.rebuy_player(payload.seat_id, payload.amount);
                gs.players.get(&socket_id).map(|p| p.id.clone())
            } else { None }
        };

        if let Some(pid) = chips_deduct {
            // E3 修复：检查余额（PokerVault 链上筹码 - locked_chips）
            let db_user = state.db.find_user_by_id(&pid).await;
            if let Some(ref user) = db_user {
                let available = get_available_chips(&state, user).await;
                if available < payload.amount as i64 {
                    tracing::warn!(
                        "[REBUY] Insufficient chips: user_id={}, available={}, required={}",
                        pid,
                        available,
                        payload.amount
                    );
                    let _ = s.emit("error", &serde_json::json!({
                        "code": "INSUFFICIENT_CHIPS",
                        "msg": crate::pokergame::errors::user_message("INSUFFICIENT_CHIPS"),
                        "detail": format!("available={available}, required={}", payload.amount)
                    }));
                    // 余额不足，回滚 rebuy_player 的座位状态变更
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                        // 简单回滚：从 seat stack 中减去刚加的 amount
                        if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                            seat.stack = seat.stack.saturating_sub(payload.amount);
                        }
                    }
                    // 必须先释放写锁再广播：broadcast_to_table 内部会对同一
                    // RwLock 取读锁，tokio RwLock 不可重入，持写锁广播会
                    // 永久自锁且该桌写锁永不释放（实锤死锁点）。
                    drop(gs);
                    broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                    return;
                }
            }
            // 锁定筹码（rebuy 时扣除可用余额）
            let _ = state.db.lock_chips(&pid, payload.amount as i64).await;
        }

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::STAND_UP, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::STAND_UP, payload_raw, StandUpPayload);
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[STAND_UP] Received from {}: table_id={}, pk_hex={}", socket_id, table_id, pk_hex);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, table_id, &pk_hex).await {
            return;
        }

        let player_pk = match hex_to_ecpoint(&**pk_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[STAND_UP] Invalid pk_hex: {}", e);
                return;
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                (table.is_playing(), table.find_player_by_pk(&pk_hex)
                    .and_then(|seat| seat.player.as_ref().map(|p| truncate_name(&p.name, 12))))
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[STAND_UP] Table {}: {} standing up while hand in progress, marking sitting_out", table_id, socket_id);
            {
                let wallet_addr = {
                    let gs = state.state.read().await;
                    gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
                };
                if let Some(wa) = wallet_addr {
                    state.mark_player_sitting_out(table_id, &wa).await;
                }
            }
            broadcast::broadcast_to_table(&io, &state, table_id, player_name.map(|n| format!("{} is sitting out.", n)).as_deref()).await;
            // 手牌进行中：不调用 handle_stand_up_on_chain（包括 folded 玩家，
            // 因为 leave_with_proof_verified 要求 round_state == Waiting，
            // 而 fold 不会提交 reveal tokens，链上交易会失败）。
            // 仅 emit LEAVE_DEFERRED，让客户端展示"等待手牌结束"UI。
            let _ = s.emit(actions::LEAVE_DEFERRED, &LeaveDeferredPayload {
                table_id,
                reason: "hand_in_progress".to_string(),
            });
            return;
        }

        // Local mode: verify leave proof, remove player, broadcast
        handle_stand_up_local(&state, &io, &payload, &pk_hex, &player_pk, table_id, &socket_id).await;
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SITTING_OUT, payload_raw, SittingPayload);
        {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = true;
                }
            }
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::SITTING_IN, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SITTING_IN, payload_raw, SittingPayload);
        let should_start = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.summary.hand_over && table.active_players().len() == MIN_START_NUM as usize
            } else { false }
        };

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SHUFFLE_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(data), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload: Result<ShuffleSubmitPayload, _> = serde_json::from_value(data.clone());
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[SHUFFLE_SUBMIT] Failed to parse payload: {}, raw: {:?}", e, data);
                return;
            }
        };

        let socket_id = s.id.to_string();
        tracing::info!("[SHUFFLE_SUBMIT] request received, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            tracing::warn!("[SHUFFLE_SUBMIT] Failed to verify socket sender, pk_hex={}, table_id={}", pk_hex, payload.table_id);
            return;
        }

        let player = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).cloned()
        };

        let player = match player {
            Some(p) => p,
            None => {
                tracing::warn!("[SHUFFLE_SUBMIT] Player not found for socket_id: {}", socket_id);
                return;
            }
        };

        let result = state.submit_verified_shuffle_for_pk(payload.table_id, &pk_hex, player, payload.output_cards.clone(), payload.shuffle_proof.clone(), payload.mask_and_shuffle_round.clone()).await;

        match result {
            Ok(reveal_started) => {
                tracing::debug!("[SHUFFLE_SUBMIT] shuffle submitted and verified, pk_hex={}, table_id={}, reveal_started={}", pk_hex, payload.table_id, reveal_started);
                state.send_shuffle_notice(payload.table_id).await;
                broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                // ZK 可视化：shuffle 证明验证成功
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Shuffle,
                    pk_hex.0.clone(),
                    None,
                    true,
                    Some("shuffle proof verified".to_string()),
                    None,
                ).await;
            }
            Err(e) => {
                tracing::warn!("[SHUFFLE_SUBMIT] shuffle verification failed, pk_hex={}, table_id={}, error={}", pk_hex, payload.table_id, e);
                // ZK 可视化：状态机拒绝（重复/迟到提交）与证明失败分开展示
                let rejection = shuffle_state_rejection(&e);
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Shuffle,
                    pk_hex.0.clone(),
                    None,
                    false,
                    Some(if rejection {
                        format!("shuffle submit rejected (state): {}", e)
                    } else {
                        format!("shuffle proof verification failed: {}", e)
                    }),
                    None,
                ).await;
            }
        }
    });



    socket.on(actions::RECONSTRUCT_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RECONSTRUCT_SUBMIT, payload_raw, ReconstructSubmitPayload);
        let socket_id = s.id.to_string();
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[RECONSTRUCT_SUBMIT] request received, pk_hex={}, table_id={}", pk_hex, payload.table_id);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            return;
        }

        let _wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        }.unwrap_or_default();


        let (all_complete, reconstruct_payload, proof_verified) = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {

                let (is_complete, verified) = match payload.statement.to_statement().and_then(|st| payload.proof.to_proof().map(|pf| (st, pf))).and_then(|(st, pf)| table.submit_reconstruct_deck(&pk_hex, st, pf)) {
                    Ok(complete) => (complete, true),
                    Err(e) => {
                        tracing::error!("[RECONSTRUCT_SUBMIT] Error: {}", e);
                        (false, false)
                    }
                };
                if is_complete {
                    let reconstruct_payload = ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: table.reconstruct_state.completed_players.clone(),
                        reconstructed: true,
                    };
                    let _ = table.start_shuffle();
                    (is_complete, Some(reconstruct_payload), verified)
                } else {
                    (is_complete, None, verified)
                }
            } else {
                (false, None, false)
            }
        };

        if let Some(reconstruct_payload) = reconstruct_payload {
            let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;
        }
        state.send_shuffle_notice(payload.table_id).await;
        if all_complete {
            tracing::info!("[RECONSTRUCT_SUBMIT] All players completed reconstruct for table {}", payload.table_id);
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        // ZK 可视化：reconstruct 证明验证结果
        state.broadcast_crypto_event(
            payload.table_id,
            broadcast::CryptoEventType::Reconstruct,
            pk_hex.0.clone(),
            None,
            proof_verified,
            Some(if proof_verified {
                "reconstruct proof verified".to_string()
            } else {
                "reconstruct proof verification failed".to_string()
            }),
            None,
        ).await;
    });

    socket.on(actions::REVEAL_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REVEAL_SUBMIT, payload_raw, RevealSubmitPayload);
        // tracing::info!("[REVEAL_SUBMIT] Received RevealSubmitPayload: {:?}", payload);
        let socket_id = s.id.to_string();
        let wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        };
        let wallet_address = match wallet_address {
            Some(w) => w,
            None => {
                tracing::warn!("[REVEAL_SUBMIT] Player {} not found", socket_id);
                return;
            }
        };

        // Task 5: 若 payload 携带 reveal_tokens，则按 on-chain / 本地模式分别处理
        if let Some(reveal_tokens) = payload.reveal_tokens.as_ref() {
            // 解析 pk_hex：优先使用 payload.pk_hex，否则通过 wallet_address 查找
            let pk_hex = match payload.pk_hex.clone() {
                Some(p) => p,
                None => {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id)
                        .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                        .unwrap_or_default()
                }
            };

            if pk_hex.0.is_empty() {
                tracing::warn!(
                    "[REVEAL_SUBMIT] cannot resolve pk_hex for socket_id={}, table_id={}",
                    socket_id, payload.table_id
                );
                let _ = s.emit("error", &serde_json::json!({"msg": "Cannot resolve pk_hex for reveal"}));
                return;
            }

            // A3 修复：验证发送者拥有所声称的 pk_hex
            if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
                return;
            }

            // 本地模式：复用 HTTP submit_reveal_token 逻辑
            let player_pk = match poker_protocol::z_poker::convert::hex_to_ecpoint(&pk_hex.0) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] invalid pk_hex: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Invalid pk_hex: {}", e)}));
                    return;
                }
            };

            let tokens_len = reveal_tokens.len();
            if tokens_len == 0 {
                tracing::warn!("[REVEAL_SUBMIT] no reveal tokens provided");
                let _ = s.emit("error", &serde_json::json!({"msg": "No reveal tokens provided"}));
                return;
            }

            let tokens = match parse_reveal_tokens(player_pk, reveal_tokens) {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] token parse error: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Token parse error: {}", e)}));
                    return;
                }
            };

            if let Err(e) = state.submit_reveal_tokens_for_pk(payload.table_id, &pk_hex, tokens.clone()).await {
                // 良性幂等：同一玩家重复提交（同账号多浏览器、REVEAL_NOTICE 与
                // TABLE_UPDATED fallback 并发、服务器重播）到达时首次提交已推进
                // 状态机。info 记录后直接返回——不广播误导性的 "proof verification
                // failed"，也不回 error（UI 会当成真错误展示）。
                if Table::is_benign_reveal_error(&e) {
                    tracing::info!(
                        "[REVEAL_SUBMIT] idempotent duplicate submit ignored, table_id={}, pk_hex={}",
                        payload.table_id, pk_hex
                    );
                    return;
                }
                tracing::warn!("[REVEAL_SUBMIT] submit failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::RevealToken,
                    pk_hex.0.clone(),
                    None,
                    false,
                    Some(format!("reveal_token proof verification failed: {}", e)),
                    None,
                ).await;
                let _ = s.emit("error", &serde_json::json!({"msg": format!("Reveal token submit failed: {}", e)}));
                return;
            }

            // ZK 可视化：reveal_token 证明验证成功
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_hex.0.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;

            let _all_complete = match state.mark_reveal_complete_for_pk(payload.table_id, &pk_hex).await {
                Ok(result) => {
                    tracing::info!("[REVEAL_SUBMIT] reveal marked, table_id={}, pk_hex={}, all_complete={}", payload.table_id, pk_hex, result);
                    result
                }
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] mark reveal failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Mark reveal failed: {}", e)}));
                    return;
                }
            };

            // reveal 结果广播已下沉到 on_reveal_complete 的单点（TableEvent::RevealResult），
            // 这里不再重复分发。
            broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
            return;
        }

        // 旧路径：reveal_tokens 为 None，保持原有行为（仅标记完成）
        let pk_hex_str = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id)
                .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                .map(|pk| pk.0.clone())
        };
        // ZK 可视化：reveal_token 证明验证成功（与 HTTP 路径一致）
        if let Some(pk_str) = pk_hex_str.as_ref() {
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_str.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;
        }
        let _all_complete = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                let pk_hex = table.get_pk_hex_by_wallet_address(&wallet_address);
                pk_hex.map_or(false, |pk| table.mark_player_reveal_complete(&pk))
            } else {
                false
            }
        };
        // reveal 结果广播已下沉到 on_reveal_complete 的单点（TableEvent::RevealResult）。
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::REDEAL_REQUEST, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REDEAL_REQUEST, payload_raw, RedealRequestPayload);
        let player_pk = GamePkHex::new(payload.player_pk.to_lowercase());
        tracing::info!("[REDEAL_REQUEST] Player {} requests redeal for {} failed cards on table {}",
            player_pk, payload.failed_card_indices.len(), payload.table_id);

        // A3 修复：验证发送者拥有所声称的 player_pk
        if !verify_socket_sender(&s, &state, payload.table_id, &player_pk).await {
            return;
        }

        // 执行 redeal
        let redealt_indices = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                match table.redeal_cards_for_player(&player_pk, payload.failed_card_indices.clone()) {
                    Ok(indices) => indices,
                    Err(e) => {
                        tracing::error!("[REDEAL_REQUEST] Redeal failed: {}", e);
                        vec![]
                    }
                }
            } else {
                vec![]
            }
        };

        if !redealt_indices.is_empty() {
            // 启动 redeal reveal 阶段
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                    table.start_redeal_reveal_phase(&player_pk, redealt_indices);
                }
            }

            // 广播 redeal notice 给所有玩家
            state.broadcast_redeal_notice(payload.table_id).await;
            broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Redeal requested, new cards being dealt")).await;
        }
    });

    socket.on(actions::RECONSTRUCT_INITIATE, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RECONSTRUCT_INITIATE, payload_raw, ReconstructInitiatePayload);
        let result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.start_reconstruct()
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(()) => {
                let reconstruct_payload = {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id).map(|t| ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: t.reconstruct_state.completed_players.clone(),
                        reconstructed: false,
                    })
                };
                if let Some(p) = reconstruct_payload {
                    let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &p).await;
                }
                broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Reconstruct vote initiated")).await;
            }
            Err(e) => {
                tracing::warn!("[RECONSTRUCT_INITIATE] Failed: {}", e);
            }
        }
    });

    socket.on_disconnect(async move |s: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let wallet_address_str = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
        };
        let (auto_fold_table_ids, _user_id, affected_table_ids, _need_cleanup, sitting_out_table_ids): (Vec<u32>, Option<String>, Vec<u32>, bool, Vec<u32>) = {
            let mut gs = state.state.write().await;

            let uid = gs.players.get(&socket_id).map(|p| p.id.clone());
            let wallet_address = gs.players.get(&socket_id).map(|p| p.wallet_address.to_string());
            let mut fold_tables = Vec::new();
            let mut affected = Vec::new();
            let mut should_cleanup = false;
            let sitting_out_tables = Vec::new();

            for (table_id, table) in gs.tables.iter_mut() {
                if wallet_address.as_ref().map_or(true, |wallet_address| table.find_player_by_wallet(wallet_address).is_none()) {
                    continue;
                }
                let pk = wallet_address.as_ref().and_then(|wa| table.get_pk_hex_by_wallet_address(wa));
                if table.is_playing() {
                    tracing::info!("[DISCONNECT] Table {}: {} disconnecting while hand in progress, marking disconnected (stays in hand; timeout folds)", table_id, socket_id);
                    // 局中断线只记 disconnected——见 mark_player_disconnected_mid_hand：
                    // 局中 sitting_out 会让 tick 判 unfolded≤1 直接重置手牌，无 fold
                    // 记录 → 结算 build failed、上手牌消失（2026-09-08 hand 1788804569）。
                    if let Some(ref pk_str) = pk {
                        table.mark_player_disconnected_mid_hand(pk_str);
                    }
                    affected.push(*table_id);
                } else {
                    if let Some(ref pk_str) = pk {
                        if table.mark_player_disconnected(pk_str).is_some() {
                            fold_tables.push(*table_id);
                        }
                        if table.is_player_disconnected_by_pk(pk_str) {
                            affected.push(*table_id);
                        }
                    }
                    should_cleanup = true;
                }
            }

            (fold_tables, uid, affected, should_cleanup, sitting_out_tables)
        };

        if let Some(ref wa) = wallet_address_str {
            for tid in &sitting_out_table_ids {
                state.mark_player_sitting_out(*tid, wa).await;
            }
        }

        for table_id in &auto_fold_table_ids {
            broadcast::broadcast_to_table(&io, &state, *table_id, Some("auto-folds (disconnected)")).await;
            game_loop::handle_turn_advance(&io, &state, *table_id).await;
        }

        for tid in &affected_table_ids {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        // if need_cleanup {
        //     if let Some(ref uid) = user_id {
        //         schedule_disconnect_cleanup(io, state, uid.clone(), socket_id);
        //     }
        // }
    });
}
