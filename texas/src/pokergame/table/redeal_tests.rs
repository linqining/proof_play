//! Reconstruction 后 identity card 的换牌（redeal）+ reveal token 重触发流程测试。
//!
//! 场景（参考实现 texas_poker_move table.move::submit_player_reveal_tokens 的
//! identity_card_indices → emit_identity_redeal → redeal assignments）：reconstruct
//! 重建 deck 后重洗，重洗会把"死槽"（解出非规范明文 = identity 的牌）随机打散进
//! 新 deck（poker_protocol note_deck_reconstructed 已知边界）——持有者本地解密
//! 失败 → 客户端 REDEAL_REQUEST → 服务端换牌 → RedealReveal 阶段重新收集他人
//! reveal token → 牌局继续。
//!
//! 方案 A（所有核心逻辑进 trace）：换牌本身是 L1 dispatch（`redeal_hole_card`）——
//! L1 校验后挂起下注轮、开启 Redealing 令牌窗口；RedealReveal 阶段的 token 经
//! 权威门（vm_try_reveal）进入同一窗口；窗口消化后 L1 原样恢复 round/turn。游戏层
//! assignment 只覆盖换掉的牌（旧牌上已有他人 HandReveal 份额，重复出份额会令摊牌
//! 物化明文必错）。重构协议本身也已进轨迹：超时 → VM AdvanceDeadline（进入
//! Reconstructing）→ 各客户端 prove 重构份额经权威门提交 → 重洗经
//! submit_verified_shuffle 逐份 dispatch → restart 补发。
//!
//! 三个测试分工：
//! - redeal_e2e：真实洗牌 + 实时 VM 镜像，identity 死槽 → 权威换牌 → 权威
//!   token 提交 → 恢复下注 → 打到摊牌，断言换牌进 trace、账本换绑、全部底牌
//!   物化、赢家判定。
//! - redeal_cursor：协议层换牌的新纪元游标语义 + RedealReveal assignment/pending
//!   形态（不经 VM；VM 权威编排由 e2e 覆盖）。
//! - reconstruct_e2e：reveal 超时 → 重构全链路（全部 dispatch 进轨迹）→
//!   restart 补发公共牌（两层牌组逐字节一致）→ 新纪元重开揭示窗口。

use super::*;
use crate::pokergame::game_state::ShufflePhase;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use poker_protocol::crypto::EcPoint;
use poker_protocol::z_poker::protocol::{ClientPlayer, RevealToken, ShuffleRound};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;
use rand_core::OsRng;

struct RedealPlayer {
    pk_hex: GamePkHex,
    client: ClientPlayer,
}

fn seat_players(table: &mut Table, n: u64) -> Vec<RedealPlayer> {
    let mut players = Vec::new();
    for idx in 1..=n {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        // record_join：record_hand_start 采集 HandStart 快照、挂载实时 VM 镜像的前置
        //（真实流程由 join_table 写入；测试直连写同一缓冲）。
        crate::starknet::prove_log::record_join(
            table.summary.id,
            &format!("0x{:064x}", idx),
            &pk_hex,
            crate::relayer::proof_bytes::serialize_pk_ownership_proof(&proof),
            None,
        );
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), client.pk, proof);
        let player = GamePlayer {
            name: format!("p{idx}"),
            bankroll: 100000,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: WalletAddress(format!("0x{:064x}", idx)),
        };
        table.sit_player(player, idx as u32, 100000, false);
        if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
            seat.folded = false;
        }
        players.push(RedealPlayer {
            pk_hex: GamePkHex::new(pk_hex),
            client,
        });
    }
    players
}

fn submit_real_shuffle(table: &mut Table, player: &RedealPlayer) {
    assert_eq!(
        table.shuffle_state.current_player_pk,
        Some(player.pk_hex.clone())
    );
    let deck = table.mental_poker_game.deck_encrypted.clone();
    let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
    let mut transcript = PoseidonFeltTranscript::new_domain(
        poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
    );
    let round = ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
        .expect("random shuffle round");
    table
        .mental_poker_game
        .submit_shuffle(&player.pk_hex, round)
        .expect("real shuffle proof must verify");
    table
        .shuffle_state
        .completed_players
        .push(player.pk_hex.clone());
    table
        .shuffle_state
        .pending_players
        .retain(|p| p != &player.pk_hex);
    if let Some(next) = table.shuffle_state.pending_players.first().cloned() {
        table.set_current_shuffler(next);
    }
}

/// 为一名玩家按给定密文集合生成全部 reveal token（真实 RevealTokenProof）。
fn build_tokens(player: &RedealPlayer, cards: &[ElGamalCiphertext]) -> Vec<RevealToken> {
    let mut tokens = Vec::new();
    for ct in cards {
        let token = ct.gen_reveal_token(&player.client.sk);
        let proof = RevealTokenProof::prove(
            &player.client.sk,
            &player.client.pk,
            ct,
            &token,
            &mut OsRng,
            &mut PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
            ),
        );
        tokens.push(RevealToken {
            encrypted_card: ct.clone(),
            proof,
            reveal_token: token,
            user_public_key: player.client.pk,
        });
    }
    tokens
}

/// 推进当前 reveal 阶段：每个 pending 玩家对其 assignment 出真实 token，经
/// 权威路径（Table::submit_player_reveal_tokens → VM 窗口）提交。
fn drive_reveal_phase(table: &mut Table, players: &[RedealPlayer]) -> RevealPhase {
    assert!(
        table.reveal_token_state.is_active(),
        "reveal phase must be active to drive"
    );
    let phase = table.reveal_token_state.phase;
    let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
    for pk_hex in pending {
        let player = players
            .iter()
            .find(|p| p.pk_hex == pk_hex)
            .expect("pending player");
        let assign = table
            .reveal_token_state
            .player_assignments
            .get(&pk_hex)
            .cloned()
            .expect("assignment for pending player");
        let cards: Vec<ElGamalCiphertext> = match phase {
            RevealPhase::HandReveal | RevealPhase::RedealReveal | RevealPhase::ShowdownReveal => {
                assign.hand_card
            }
            RevealPhase::CommunityReveal => assign.community_card,
            RevealPhase::None => unreachable!(),
        };
        let tokens = build_tokens(player, &cards);
        table
            .submit_player_reveal_tokens(&pk_hex, tokens)
            .unwrap_or_else(|e| panic!("{phase:?} token submit failed for {pk_hex}: {e}"));
        // WS handler 同款收尾：登记完成并在最后一人时触发 on_reveal_complete。
        table.mark_player_reveal_complete(&pk_hex);
    }
    assert!(
        !table.reveal_token_state.is_active(),
        "reveal phase must complete after all submissions"
    );
    phase
}

/// 当前行动者 check（无人下注时）或 call（面对下注时）。街道推进由
/// apply_betting_view 的相位联锁完成（VM 下注轮完成时已在 dispatch 内收集筹码
/// 并开下一街窗口，游戏层随之执行发牌仪式）——这里不能手动
/// advance_to_next_phase（会双层各推一街）。fold-win 终局同。
fn act_and_advance(table: &mut Table, players: &[RedealPlayer]) {
    let turn_seat = table.turn().expect("betting must have a current turn");
    let turn_pk = {
        let seat = table.local_seats.get(&turn_seat).expect("turn seat");
        seat.player.as_ref().expect("seat occupied").pk_hex.clone()
    };
    let player = players
        .iter()
        .find(|p| p.pk_hex == turn_pk)
        .expect("turn player");

    let others_max_bet = table
        .local_seats
        .values()
        .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
        .map(|s| s.total_bet)
        .max()
        .unwrap_or(0);
    let my_bet = table
        .local_seats
        .get(&turn_seat)
        .map(|s| s.total_bet)
        .unwrap_or(0);
    if my_bet < others_max_bet {
        table.handle_call(&player.pk_hex).expect("call");
    } else {
        table.handle_check(&player.pk_hex);
    }

    if table.unfolded_players().len() <= 1 {
        table.end_without_showdown();
    }
}

/// 把一名玩家指定槽位的底牌密文改写为"持有者解出 identity"的死槽：
/// c2 := Σ_{他人已交 token} + c1·sk_owner。持有者视角
/// plaintext = c2 − Σ_{他人 token} − c1·sk_owner = identity（不在 deck 明文域）。
/// 服务端 hole 卡物化要求 pending 全清（牌主永不交 own token），故该破坏
/// 只对持有者可见——与线上"客户端解密失败 → REDEAL_REQUEST"的发现路径一致。
fn corrupt_to_identity_slot(table: &mut Table, owner: &RedealPlayer, slot: usize) {
    let (sum_tokens, own, c1) = {
        let card = &table
            .mental_poker_game
            .players
            .get(&**owner.pk_hex)
            .expect("owner registered")
            .hand_encrypted[slot];
        (
            card.reveal_state
                .reveal_tokens
                .iter()
                .map(|t| t.reveal_token.clone())
                .sum::<EcPoint>(),
            card.encrypted_card.gen_reveal_token(&owner.client.sk),
            card.encrypted_card.c1.clone(),
        )
    };
    let card = &mut table
        .mental_poker_game
        .players
        .get_mut(&**owner.pk_hex)
        .expect("owner registered")
        .hand_encrypted[slot];
    card.encrypted_card.c2 = sum_tokens + own;
    card.encrypted_card.c1 = c1;
    card.playing_card = None;
}

/// E2E（真实洗牌 + 实时 VM 镜像）：HandReveal 完成后持有者解出 identity 死槽 →
/// REDEAL_REQUEST → 权威换牌（L1 挂起下注轮、开 Redealing 窗口，进 trace）→
/// RedealReveal token 经权威门提交（VM 窗口接受）→ 窗口消化恢复下注 →
/// 打到摊牌：换入的牌正确物化、全部底牌公开、赢家判定。
#[test]
fn redeal_e2e_identity_card_triggers_redeal_and_reveal_restart() {
    let mut table = Table::new(990_201, "redeal-e2e".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, 3);
    let p1 = &players[0];

    table.mental_poker_game.encrypt_deck();
    table.start_hand();
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("seated shuffler");
        submit_real_shuffle(&mut table, player);
    }
    table.advance_shuffle();
    assert_eq!(table.round_state(), RoundState::PreFlop);
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);

    // ---- HandReveal：他人交 token（权威路径，VM DealHole 窗口接受） ----
    drive_reveal_phase(&mut table, &players);

    // 持有者解密在破坏前必须成功（fixture 自检，对齐 run_full_hand 的锚点）。
    let holders = table.mental_poker_game.get_player_residual_carriers();
    for p in &players {
        let rcs = holders.get(&**p.pk_hex).expect("readable cards");
        assert_eq!(rcs.len(), 2);
        for rc in rcs.iter() {
            let own = rc.gen_reveal_token(&p.client.sk);
            assert!(
                table
                    .mental_poker_game
                    .deck_plaintext
                    .contains(&(rc.c2 - own))
            );
        }
    }

    // ---- p1 的 0 号底牌成为 identity 死槽（持有者解密失败） ----
    corrupt_to_identity_slot(&mut table, p1, 0);
    let holders = table.mental_poker_game.get_player_residual_carriers();
    let rc0 = &holders.get(&**p1.pk_hex).unwrap()[0];
    let own0 = rc0.gen_reveal_token(&p1.client.sk);
    assert!(
        (rc0.c2 - own0).is_identity(),
        "fixture: holder decrypt must yield identity for the dead slot"
    );

    // ---- 客户端 REDEAL_REQUEST → 权威换牌：L1 挂起下注轮 + 开 Redealing 窗口 ----
    let redealt = table
        .redeal_cards_for_player(&p1.pk_hex, vec![0])
        .expect("authoritative redeal must pass the VM gate");
    assert_eq!(redealt, vec![0]);
    {
        let hand = &table
            .mental_poker_game
            .players
            .get(&**p1.pk_hex)
            .unwrap()
            .hand_encrypted;
        assert_eq!(
            hand[0].card_index, 6,
            "redeal 从 deck 游标（3 人 × 2 张）取新牌"
        );
        assert_eq!(
            hand[0].reveal_state.pending_players.len(),
            3,
            "换牌后 reveal_state 全量重置：所有活跃玩家（含牌主）都待交 token"
        );
        assert!(hand[0].reveal_state.reveal_tokens.is_empty());
        assert!(hand[0].playing_card.is_none());
    }
    table.start_redeal_reveal_phase(&p1.pk_hex, redealt.clone());
    assert_eq!(table.reveal_token_state.phase, RevealPhase::RedealReveal);
    assert_eq!(
        table.round_state(),
        RoundState::PreFlop,
        "redeal 不改变 round_state"
    );
    let p2_pk = players[1].pk_hex.clone();
    let p3_pk = players[2].pk_hex.clone();
    assert!(table.reveal_token_state.pending_players.contains(&p2_pk));
    assert!(table.reveal_token_state.pending_players.contains(&p3_pk));
    assert!(!table.reveal_token_state.pending_players.contains(&p1.pk_hex));
    assert!(
        !table
            .reveal_token_state
            .player_assignments
            .contains_key(&p1.pk_hex),
        "牌主不为换牌交 token（他人交齐后牌主本地解密）"
    );
    let new_ct = table
        .mental_poker_game
        .players
        .get(&**p1.pk_hex)
        .unwrap()
        .hand_encrypted[0]
        .encrypted_card
        .clone();
    for pk in [&p2_pk, &p3_pk] {
        let assign = &table.reveal_token_state.player_assignments[pk];
        assert_eq!(
            assign.hand_card.len(),
            1,
            "assignment 只覆盖换掉的牌——旧牌重复出份额会令摊牌物化明文必错"
        );
        assert_eq!(assign.hand_card[0], new_ct);
    }

    // ---- RedealReveal token 经权威门提交：VM Redealing 窗口接受 ----
    drive_reveal_phase(&mut table, &players);

    // 未换的旧牌不再被重复出份额（修复后语义：HandReveal 份额原样保留）。
    let hand = &table
        .mental_poker_game
        .players
        .get(&**p1.pk_hex)
        .unwrap()
        .hand_encrypted;
    assert_eq!(
        hand[1].reveal_state.reveal_tokens.len(),
        2,
        "旧牌份额原样保留"
    );
    assert_eq!(hand[0].reveal_state.reveal_tokens.len(), 2, "新牌每人一份");
    assert_eq!(
        hand[0].reveal_state.pending_players.len(),
        1,
        "只剩牌主待本地解密"
    );

    // ---- 换牌进证明轨迹：VM trace 含 redeal_hole_card dispatch ----
    let traces = table
        .vm_session
        .as_ref()
        .expect("live VM mirror")
        .vm_traces();
    let redeal_trace = traces
        .iter()
        .find(|t| {
            t.selector
                == poker_l1::contracts::texas_poker::dispatch::selectors::redeal_hole_card()
        })
        .expect("redeal dispatch must be captured in the VM trace");
    assert_eq!(
        redeal_trace.pre.round_state(),
        poker_l1::contracts::texas_poker::constants::ROUND_PREFLOP
    );
    assert_eq!(
        redeal_trace.post.round_state(),
        poker_l1::contracts::texas_poker::constants::ROUND_PREFLOP
    );

    // ---- 窗口消化后牌局继续：round_state 保持，下注轮仍可行动 ----
    let turn_seat = table
        .turn()
        .expect("betting turn preserved after redeal reveal");
    let turn_pk = table
        .local_seats
        .get(&turn_seat)
        .expect("turn seat")
        .player
        .as_ref()
        .expect("occupied")
        .pk_hex
        .clone();
    let _ = players
        .iter()
        .find(|p| p.pk_hex == turn_pk)
        .expect("turn player");
    let others_max = table
        .local_seats
        .values()
        .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
        .map(|s| s.total_bet)
        .max()
        .unwrap_or(0);
    let my_bet = table
        .local_seats
        .get(&turn_seat)
        .map(|s| s.total_bet)
        .unwrap_or(0);
    if my_bet < others_max {
        assert!(
            table.handle_call(&turn_pk).is_some(),
            "betting must continue"
        );
    } else {
        assert!(
            table.handle_check(&turn_pk).is_some(),
            "betting must continue"
        );
    }

    // ---- 打到摊牌：换入的牌与全部底牌正确物化、赢家判定 ----
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 400, "game did not terminate (stuck)");
        if table.reveal_token_state.is_active() {
            let phase_done = drive_reveal_phase(&mut table, &players);
            if phase_done == RevealPhase::ShowdownReveal {
                table.settle_hand();
                break;
            }
            continue;
        }
        if table.summary.hand_over || table.round_state() == RoundState::Waiting {
            break;
        }
        if table.turn().is_some() {
            act_and_advance(&mut table, &players);
            continue;
        }
        break;
    }
    assert!(table.summary.went_to_showdown || table.summary.hand_over);
    for p in &players {
        let revealed = table
            .mental_poker_game
            .players
            .get(&**p.pk_hex)
            .map(|ps| {
                ps.hand_encrypted
                    .iter()
                    .filter(|c| c.playing_card.is_some())
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            revealed, 2,
            "showdown publishes every live hand ({})",
            p.pk_hex
        );
    }
    assert!(
        !table.summary.win_messages.is_empty(),
        "winner determined with messages"
    );
}

/// 协议层换牌的新纪元游标语义 + RedealReveal 形态不变量。
///
/// note_deck_reconstructed 归零发牌游标后，redeal 从新 deck 的未消费位置 0 取牌
/// （未归零则取 6）。本测试不经 VM（换牌的 VM 权威编排由 e2e 测试覆盖），直接
/// 驱动协议层与游戏层状态以钉住游标/形态语义。
#[test]
fn redeal_after_deck_reconstruction_pulls_from_new_era_cursor() {
    let mut table = Table::new(990_202, "redeal-cursor".to_string(), 10000, 9, String::new());
    // 仅协议层注册（本测试不驱动 VM/权威路径，无需 join 证明）。
    let mut clients = Vec::new();
    for _idx in 1..=3 {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), client.pk, proof);
        clients.push((pk_hex, client));
    }
    table.mental_poker_game.encrypt_deck();

    // 旧纪元：每人 2 张（deck 位置 0..5 已消费）。
    for (pk_hex, _) in &clients {
        table
            .mental_poker_game
            .deal_to_player(pk_hex, 2)
            .expect("era-0 deal");
    }
    // reconstruct 完成：deck 重建 + 全员重洗（这里只换掉位置 0 模拟重洗后的新密文）
    // + 宿主 note_deck_reconstructed 归零游标。
    let reshuffled0 = ElGamalCiphertext {
        c1: EcPoint::identity(),
        c2: table.mental_poker_game.deck_encrypted[0].c2,
    };
    table.mental_poker_game.deck_encrypted[0] = reshuffled0.clone();
    table.mental_poker_game.note_deck_reconstructed();

    // 持有者报告 identity 死槽 → 协议层换牌：新纪元第一张未消费牌 = deck[0]。
    let (p1, p2, p3) = (clients[0].0.clone(), clients[1].0.clone(), clients[2].0.clone());
    let new_ct = table
        .mental_poker_game
        .redeal_to_player_unchecked(&p1, 0)
        .expect("protocol redeal ok");
    assert_eq!(new_ct, reshuffled0, "换入重洗后新 deck 位置 0 的牌");
    {
        let hand = &table.mental_poker_game.players.get(&p1).unwrap().hand_encrypted;
        assert_eq!(hand[0].card_index, 0, "新纪元游标从 0 起步（未 note 则为 6）");
        assert_eq!(hand[0].encrypted_card, reshuffled0);
        assert_eq!(hand[0].reveal_state.pending_players.len(), 3);
        assert!(hand[0].reveal_state.reveal_tokens.is_empty());
    }

    // 重触发 reveal token：RedealReveal 形态不变量。
    table.start_redeal_reveal_phase(&GamePkHex::new(p1.clone()), vec![0]);
    assert_eq!(table.reveal_token_state.phase, RevealPhase::RedealReveal);
    let pending = &table.reveal_token_state.pending_players;
    assert_eq!(pending.len(), 2);
    assert!(pending.contains(&GamePkHex::new(p2.clone())));
    assert!(pending.contains(&GamePkHex::new(p3.clone())));
    assert!(!pending.contains(&GamePkHex::new(p1.clone())));
    let hand = &table.mental_poker_game.players.get(&p1).unwrap().hand_encrypted;
    for pk in [&p2, &p3] {
        let assign = &table.reveal_token_state.player_assignments[&GamePkHex::new(pk.clone())];
        assert_eq!(
            assign.hand_card.len(),
            1,
            "assignment 只覆盖换掉的牌（RedealReveal 收窄）"
        );
        assert_eq!(assign.hand_card[0], hand[0].encrypted_card);
    }
    assert!(
        !table
            .reveal_token_state
            .player_assignments
            .contains_key(&GamePkHex::new(p1))
    );
}

/// E2E（方案A 全链路）：reveal 超时 → VM AdvanceDeadline（L1 进入 Reconstructing，
/// 进轨迹）→ start_reconstruct 取 L1 权威上下文 → pending 客户端各 prove 重构
/// 份额并经权威门提交（最后一份内联完成 L1 deck 重建 + 重洗窗口开启）→ 重洗
/// 经 submit_verified_shuffle 逐份 dispatch（两层重建牌组逐字节一致性的自然
/// 校验）→ restart 补发公共牌（游标对齐）→ 新纪元重开揭示窗口。
///
/// 4 人桌面：turn 揭示窗口 p1/p2 先交份额，超时后 L1 只踢 p3/p4（active=2 才能进
/// Reconstructing；全员不交会被正确地退款重开——L1 语义的另一半）。
#[test]
fn reconstruct_after_reveal_timeout_full_traced_chain_and_redeal() {
    use poker_l1::contracts::texas_poker::dispatch::selectors;
    use poker_protocol::zk_shuffle::reconstruction::ReconstructProof;

    let mut table = Table::new(990_203, "reconstruct-e2e".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, 4);

    table.mental_poker_game.encrypt_deck();
    table.start_hand();
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("seated shuffler");
        submit_real_shuffle(&mut table, player);
    }
    table.advance_shuffle();
    assert_eq!(table.round_state(), RoundState::PreFlop);
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
    drive_reveal_phase(&mut table, &players);

    // ---- 街道推进到 turn：必须经 VM 权威的下注轮（VM 相位驱动游戏层 ceremony；
    // 直接 advance_to_next_phase 会让两层街道失配）----
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 60, "did not reach turn (stuck)");
        // 到达 turn 且揭示窗口已开：立即停——这个窗口就是超时重构的靶子。
        if table.round_state() == RoundState::Turn && table.reveal_token_state.is_active() {
            break;
        }
        if table.reveal_token_state.is_active() {
            drive_reveal_phase(&mut table, &players);
            continue;
        }
        if table.round_state() == RoundState::Turn {
            break;
        }
        if table.turn().is_some() {
            act_and_advance(&mut table, &players);
            continue;
        }
        panic!("no betting turn and no reveal window before turn");
    }
    assert_eq!(table.round_state(), RoundState::Turn);
    assert_eq!(
        table.reveal_token_state.phase,
        RevealPhase::CommunityReveal,
        "turn reveal window must be open before the timeout"
    );
    let board_before = table.mental_poker_game.community_cards_encrypted.len();

    // ---- turn 揭示窗口：p1/p2 先交份额（部分提交），其余等超时踢 ----
    {
        let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
        for pk_hex in pending.iter().take(2) {
            let player = players
                .iter()
                .find(|p| p.pk_hex == *pk_hex)
                .expect("pending player");
            let assign = table
                .reveal_token_state
                .player_assignments
                .get(pk_hex)
                .cloned()
                .expect("assignment");
            let tokens = build_tokens(player, &assign.community_card);
            table
                .submit_player_reveal_tokens(pk_hex, tokens)
                .unwrap_or_else(|e| panic!("partial turn submit failed: {e}"));
            table.mark_player_reveal_complete(pk_hex);
        }
        assert_eq!(table.reveal_token_state.pending_players.len(), 2);
    }

    // ---- turn reveal 超时：镜像时钟快进过 reveal deadline（10s），随后驱动
    // VM AdvanceDeadline（L1 踢未交份额者并进入 Reconstructing）----
    table.vm_advance_test_clock(11_000);
    table.on_reveal_timeout();
    assert!(
        table.reconstruct_state.is_active,
        "timeout must start reconstruct"
    );
    // 游戏层 pending 与 L1 权威 pending 对齐（超时玩家已被 L1 踢出 pending）。
    let l1_pending = table
        .vm_reconstruct_context()
        .map(|c| c.expect("context").pending_pks)
        .expect("mirror context");
    assert_eq!(
        l1_pending.len(),
        table.reconstruct_state.pending_players.len(),
        "game pending must mirror the L1 authoritative pending set"
    );

    // ---- 各 pending 客户端 prove 重构份额并经权威门提交（statement 字段由
    // VM 上下文权威提供；最后一份提交在 L1 normalize 内联完成 deck 重建）----
    let mut submits = 0;
    while table.reconstruct_state.is_active && submits < 12 {
        // 快照本轮 pending（提交会把玩家从列表移除；最后一份提交后 context
        // 随之失效——必须逐份取用）。
        let pending: Vec<GamePkHex> = table.reconstruct_state.pending_players.clone();
        for pk_hex in pending {
            if !table.reconstruct_state.is_active {
                break;
            }
            submits += 1;
            let ctx = table
                .vm_reconstruct_context()
                .expect("mirror context")
                .unwrap_or_else(|e| panic!("context for {pk_hex}: {e}"));
            let player = players
                .iter()
                .find(|p| p.pk_hex == pk_hex)
                .expect("pending player");
            let cards = table.reconstruct_state.cards.clone();
            let readable = table
                .reconstruct_state
                .player_residual_carriers
                .get(&pk_hex)
                .cloned()
                .expect("carriers for pending player")
                .residual_carriers;
            let aggregate_pk =
                poker_protocol::z_poker::convert::hex_to_ecpoint(&ctx.aggregate_pk).expect("agg pk");
            let mut transcript = PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::RECONSTRUCT_POSEIDON,
            );
            let (statement, proof) = ReconstructProof::prove(
                ctx.context_digest,
                ctx.reconstruction_epoch,
                ctx.prior_state_digests[&**pk_hex],
                cards,
                readable,
                &player.client.sk,
                &player.client.pk,
                &aggregate_pk,
                &mut OsRng,
                &mut transcript,
            )
            .expect("client proves reconstruction");
            table
                .submit_reconstruct_deck(&pk_hex, statement, proof)
                .unwrap_or_else(|e| panic!("reconstruct submit failed for {pk_hex}: {e}"));
        }
    }
    assert!(
        !table.reconstruct_state.is_active,
        "reconstruct must complete (deck rebuilt via the last L1 submit)"
    );

    // ---- 重洗窗口开启（Reconstruct 相位）：经权威路径 submit_verified_shuffle
    // 提交（游戏层验证 + VM dispatch 对镜像重建牌组验证 BG 证明——两层牌组
    // 一致性的自然校验）----
    assert_eq!(table.shuffle_state.phase, ShufflePhase::Reconstruct);
    {
        let mut shuffled = 0;
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            shuffled += 1;
            assert!(shuffled < 12, "reshuffle did not converge");
            let current = table
                .shuffle_state
                .current_player_pk
                .clone()
                .expect("shuffler set");
            let player = players
                .iter()
                .find(|p| p.pk_hex == current)
                .expect("seated shuffler");
            let deck = table.mental_poker_game.deck_encrypted.clone();
            let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
            let mut transcript = PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
            );
            let round = ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
                .expect("random shuffle round");
            let proof_json = super::full_hand_tests::bg_proof_to_json(&round.proof);
            let outputs = round
                .output_cards
                .iter()
                .map(crate::pokergame::game_state::ElGamalCiphertextJson::from_ciphertext)
                .collect();
            table
                .submit_verified_shuffle(&player.pk_hex, outputs, proof_json)
                .unwrap_or_else(|e| panic!("post-reconstruct shuffle submit failed: {e}"));
            if let Some(next) = table.shuffle_state.pending_players.first().cloned() {
                table.set_current_shuffler(next);
            }
        }
        table.advance_shuffle();
        assert!(!table.shuffle_state.is_active());
    }

    // ---- restart：turn 缺失的公共牌从新 deck 重发；两层牌组逐字节一致 ----
    assert_eq!(table.round_state(), RoundState::Turn);
    assert_eq!(
        table.mental_poker_game.community_cards_encrypted.len(),
        board_before,
        "missing turn card re-dealt from the new deck era"
    );
    for (i, g) in table.mental_poker_game.deck_encrypted.iter().enumerate() {
        let vm = table
            .vm_session
            .as_ref()
            .map(|sh| sh.current_deck_card(i))
            .flatten()
            .expect("mirror deck card");
        assert_eq!(
            *g, vm,
            "game/mirror deck divergence at {i} after reconstruct+reshuffle"
        );
    }

    // ---- 新纪元重开的揭示窗口照常工作（权威门接受）----
    assert_eq!(table.reveal_token_state.phase, RevealPhase::CommunityReveal);
    drive_reveal_phase(&mut table, &players);
    assert!(!table.reveal_token_state.is_active());

    // ---- trace 完整性：advance_deadline / reconstruct / shuffle 三类 dispatch
    // 全部进证明轨迹 ----
    let traces = table
        .vm_session
        .as_ref()
        .expect("live mirror")
        .vm_traces();
    assert!(
        traces
            .iter()
            .any(|t| t.selector == selectors::advance_deadline()),
        "timeout advance_deadline must be traced"
    );
    assert!(
        traces
            .iter()
            .any(|t| t.selector == selectors::submit_reconstruct_deck()),
        "reconstruct contribution must be traced"
    );
    assert!(
        traces
            .iter()
            .any(|t| t.selector == selectors::submit_shuffle_v2()),
        "post-reconstruct shuffle must be traced"
    );
}
