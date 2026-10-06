//! 完整一手牌全流程测试（Plan D 验收补全）。
//!
//! N 个玩家（9 人满桌 / 2 人最低），StarkCurve（DefaultCurve）：
//! 每人各洗一次（真实 Bayer-Groth V2 证明逐个验证）→ 发两张手牌 →
//! 翻牌前 HandReveal（他人 token + 持有者本地解密）→ 下注轮（check/
//! call 推进）→ 翻牌/转牌/河牌 CommunityReveal → 摊牌 ShowdownReveal
//!（各自交出自己的份额）→ 边池/主池判胜 → 手牌评估。
//!
//! 这覆盖真实对局需要的全部 reveal token 形态（他人手牌、公共牌、
//! 自己手牌），此前测试只覆盖认可批次（用户指出的缺口）。

use super::*;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::protocol::ShuffleRound;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;
use rand_core::OsRng;

struct Player {
    pk_hex: GamePkHex,
    client: ClientPlayer,
}

fn seat_players(table: &mut Table, n: u64) -> Vec<Player> {
    let mut players = Vec::new();
    for idx in 1..=n {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        // pk_hex = pk 点的十六进制（与真实客户端 get_pk_hex 一致；
        // submit_reveal_token 会从它反解点做校验）。
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        // join 证明缓冲（record_hand_start 采集 HandStart 快照的前置——
        // 真实流程由 join_table 写入；测试直连写同一缓冲）。
        crate::starknet::prove_log::record_join(
            table.summary.id,
            // 有效 felt 钱包：实时 VM 镜像的 addr_from_starknet 必须可解析
            &format!("0x{:064x}", idx),
            &pk_hex,
            crate::relayer::proof_bytes::serialize_pk_ownership_proof(&proof),
            // 会话交易公钥走 vault 登记核验路径，测试直连缓冲不携带（None）。
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
        players.push(Player { pk_hex: GamePkHex::new(pk_hex), client });
    }
    players
}

/// 用真实证明提交一次洗牌（与 submit_verified_shuffle 同验证强度：
/// mental_poker_game.submit_shuffle 内部跑 BG V2 Fiat-Shamir 验证）。
fn submit_real_shuffle(table: &mut Table, player: &Player) {
    assert_eq!(
        table.shuffle_state.current_player_pk,
        Some(player.pk_hex.clone()),
        "shuffle turn must be {}",
        player.pk_hex
    );
    let deck = table.mental_poker_game.deck_encrypted.clone();
    let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
    let mut transcript = PoseidonFeltTranscript::new_domain(
        poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
    );
    // 测试为服务端视角：代理/自随机洗牌（玩家洗牌走客户端传入置换）。
    let round =
        ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
            .expect("random shuffle round");
    table
        .mental_poker_game
        .submit_shuffle(&player.pk_hex, round)
        .expect("real shuffle proof must verify");
    table.shuffle_state.completed_players.push(player.pk_hex.clone());
    table
        .shuffle_state
        .pending_players
        .retain(|p| p != &player.pk_hex);
    if let Some(next) = table.shuffle_state.pending_players.first().cloned() {
        let next = next.clone();
        table.set_current_shuffler(next);
    }
}

/// 推进当前 reveal 阶段：每个 pending 玩家对其 assignment 的全部卡出
/// 真实 token（RevealTokenProof），提交后阶段完成时触发 on_reveal_complete。
/// `captured` 累计真实 token 数（hand-batch 向量的 reveal 方程计数）。
fn drive_reveal_phase(table: &mut Table, players: &[Player]) -> RevealPhase {
    drive_reveal_phase_capture(table, players, &mut None)
}

fn drive_reveal_phase_capture(
    table: &mut Table,
    players: &[Player],
    captured: &mut Option<&mut usize>,
) -> RevealPhase {
    assert!(
        table.reveal_token_state.is_active(),
        "reveal phase must be active to drive"
    );
    let phase = table.reveal_token_state.phase;
    // 快照 pending 列表（submit 中会原地修改）。
    let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
    for pk_hex in pending {
        let player = players
            .iter()
            .find(|p| p.pk_hex == pk_hex)
            .expect("pending player must be seated");
        let assign = table
            .reveal_token_state
            .player_assignments
            .get(&pk_hex)
            .cloned()
            .expect("assignment for pending player");
        let cards: Vec<ElGamalCiphertext> = match phase {
            RevealPhase::HandReveal | RevealPhase::RedealReveal | RevealPhase::ShowdownReveal => assign.hand_card,
            RevealPhase::CommunityReveal => assign.community_card,
            RevealPhase::None => unreachable!(),
        };
        let mut tokens = Vec::new();
        for ct in cards {
            let token = ct.gen_reveal_token(&player.client.sk);
            if let Some(cap) = captured.as_deref_mut() {
                *cap += 1;
            }
            let proof = RevealTokenProof::prove(
                &player.client.sk,
                &player.client.pk,
                &ct,
                &token,
                &mut OsRng,
                &mut PoseidonFeltTranscript::new_domain(poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON),
            );
            tokens.push(poker_protocol::z_poker::protocol::RevealToken {
                encrypted_card: ct,
                proof,
                reveal_token: token,
                user_public_key: player.client.pk,
            });
        }
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

/// 当前行动者 check（无人下注时）或 call（面对下注时），随后镜像
/// game_loop::handle_turn_advance 的推进逻辑（无 socket 层）。
fn act_and_advance(table: &mut Table, players: &[Player]) {
    let turn_seat = table
        .turn()
        .expect("betting must have a current turn");
    let turn_pk = {
        let seat = table.local_seats.get(&turn_seat).expect("turn seat");
        seat.player.as_ref().expect("seat occupied").pk_hex.clone()
    };
    let player = players.iter().find(|p| p.pk_hex == turn_pk).expect("turn player");

    let others_max_bet = table
        .local_seats
        .values()
        .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
        .map(|s| s.total_bet)
        .max()
        .unwrap_or(0);
    let my_bet = table.local_seats.get(&turn_seat).map(|s| s.total_bet).unwrap_or(0);
    if my_bet < others_max_bet {
        table.handle_call(&player.pk_hex).expect("call");
    } else {
        table.handle_check(&player.pk_hex);
    }

    // handle_turn_advance 的纯表镜像（权威模式：turn 轮转由 VM 视图同步
    // 负责，街道仪式在 apply_betting_view 内触发）。
    if table.unfolded_players().len() <= 1 {
        table.end_without_showdown();
    } else if table.is_betting_round_complete() {
        table.advance_to_next_phase();
    }
}

fn run_full_hand(table_id: u32, n: u64) {
    // limit=10000 -> min_bet=50 (limit/200)，盲注 50/100 实际入池；
    // 否则奖池恒 0、win_messages 不产生（determine 仅在奖池>0 时写消息）。
    // table_id 必须全局唯一：join 缓冲/实时镜像按桌键控，并行测试共用
    // 同一 id 会互相串流（2026-09-09 两次复现）。
    let mut table = Table::new(table_id, "full-flow".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, n);

    // 在全量聚合公钥下重加密明文牌组（真实对局由 join 掩码层完成同样
    // 的事：把初始牌组拉进正确的密钥谱系；初始牌组在空聚合密钥=恒等元
    // 下加密，直接叠加洗牌层会破坏 Σsk·c1 = c2 − m 的可解性）。
    table.mental_poker_game.encrypt_deck();

    // ---- 开局 + 每人洗一次 ----
    table.start_hand();
    assert!(table.shuffle_state.is_active(), "shuffle phase active");
    let mut shuffled = 0;
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("current shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("current shuffler seated");
        submit_real_shuffle(&mut table, player);
        shuffled += 1;
    }
    assert_eq!(shuffled, n as usize, "every player shuffles exactly once");
    table.advance_shuffle();
    assert!(
        !table.shuffle_state.is_active(),
        "shuffle phase closed after all players"
    );
    assert_eq!(table.round_state(), RoundState::PreFlop, "preflop after shuffle");

    // ---- 发牌 + 翻牌前手牌 reveal（他人 token → 持有者本地解密） ----
    for p in &players {
        let hand = table
            .mental_poker_game
            .get_hand_encrypted(&p.pk_hex)
            .expect("dealt hand");
        assert_eq!(hand.len(), 2, "two hole cards per player");
    }
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
    drive_reveal_phase(&mut table, &players);

    // 持有者本地解密（真实客户端流程）：HandReveal 后服务器把
    // readable_cards（c2 − 他人份额）发给持有者，持有者补自己的份额
    // （sk·c1）得到明文——服务器全程看不到明文。
    let readable_map = table.mental_poker_game.get_player_residual_carriers();
    for p in &players {
        let rcs = readable_map
            .get(&*p.pk_hex)
            .expect("holder has readable cards after HandReveal");
        assert_eq!(rcs.len(), 2, "two readable hole cards for {}", p.pk_hex);
        for rc in rcs {
            let own_token = rc.gen_reveal_token(&p.client.sk);
            let plaintext = rc.c2 - own_token;
            assert!(
                table.mental_poker_game.deck_plaintext.contains(&plaintext),
                "holder-decrypted card must be a deck plaintext ({})",
                p.pk_hex
            );
        }
    }

    // ---- 四条街：reveal → betting，直到摊牌 ----
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 400, "game did not terminate (stuck)");

        if table.reveal_token_state.is_active() {
            let phase_done = drive_reveal_phase(&mut table, &players);
            if phase_done == RevealPhase::ShowdownReveal {
                // 生产路径：摊牌展示后 settle_hand 判定赢家 + 收尾
                //（hand_over、回 Waiting）。
                table.settle_hand();
                break;
            }
            continue;
        }
        if table.summary.hand_over || table.round_state() == RoundState::Waiting {
            break;
        }
        if table.turn().is_some() {
            eprintln!("[step {steps}] state={:?} turn={:?} acted={:?} win={:?} hand_over={}",
                table.round_state(), table.turn(),
                table.local_seats.values().map(|s| (s.id, s.has_acted)).collect::<Vec<_>>(),
                table.summary.win_messages, table.summary.hand_over);
            act_and_advance(&mut table, &players);
            continue;
        }
        // 既无 reveal 也无行动权（摊牌判定后）——退出
        break;
    }

    // ---- 终局断言 ----
    let board = table.mental_poker_game.list_revealed_community_cards();
    assert_eq!(board.len(), 5, "board reaches river (5 community cards)");
    assert!(
        table.summary.went_to_showdown,
        "check/call line goes to showdown"
    );
    assert!(
        !table.summary.win_messages.is_empty(),
        "winner determined with messages"
    );
    // 摊牌后所有未弃牌玩家的手牌均已公开（playing_card 已解出）。
    for p in &players {
        let revealed = table
            .mental_poker_game
            .players
            .get(&*p.pk_hex)
            .map(|ps| ps.hand_encrypted.iter().filter(|c| c.playing_card.is_some()).count())
            .unwrap_or(0);
        assert_eq!(revealed, 2, "showdown publishes every live hand ({})", p.pk_hex);
    }
    assert_eq!(
        table.mental_poker_game.shuffle_rounds.len(),
        n as usize,
        "N real shuffle rounds recorded"
    );
}

/// 2026-09-19 hand 1789813453（千手长跑）复现的盲注反向回归：
/// 计划冻结（record_hand_start）与盲注计算（HandReveal 完成）之间，
/// 计划外座位被 reconnect_player 翻回 active（无条件清 sitting_out）——
/// 修复前 set_blinds 按翻转后的 3 座走非单挑路径发盲，与 VM 按冻结 2 人
/// 计划所发盲注反向：本手全部动作被 VM 以 "not player's turn" /
/// "cannot check: bet < current_bet" 拒绝且永不收敛（超时代打被拒后
/// 强吃 fold 也无法对齐），桌面永久卡死。
#[test]
fn reconnect_flap_between_plan_freeze_and_blinds_cannot_invert_blinds() {
    let table_id = 981_345u32;
    let mut table = Table::new(table_id, "flap".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, 3);
    table.mental_poker_game.encrypt_deck();

    table.start_hand();
    // 开局断线转换：seat1 转 sitting_out（deal 与 record_hand_start 都会
    // 跳过它 → 冻结计划只剩 seat2/seat3 两人单挑）。它的 pk 仍在洗牌
    // 注册表且照常完成洗牌——与事故现场一致。
    if let Some(seat) = table.local_seats.get_mut(&1) {
        seat.sitting_out = true;
    }
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("current shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("current shuffler seated");
        submit_real_shuffle(&mut table, player);
    }
    table.advance_shuffle();
    assert_eq!(table.round_state(), RoundState::PreFlop);
    // 冻结计划 = 2 人（seat1 被跳过）。
    assert_eq!(
        table
            .hand_proof_log
            .start
            .as_ref()
            .expect("hand start recorded")
            .participants
            .len(),
        2,
        "frozen plan must exclude the sitting-out seat"
    );

    // 事故现场的重连抖动：计划冻结后、盲注计算前，websocket 重连把
    // sitting_out 清掉（reconnect_player 无条件清除）。
    let seat1_wallet = table
        .local_seats
        .get(&1)
        .and_then(|s| s.player.as_ref())
        .map(|p| p.wallet_address.0.clone())
        .expect("seat1 player");
    assert!(table.reconnect_player(&seat1_wallet), "reconnect must hit seat1");
    assert!(
        !table.local_seats.get(&1).unwrap().sitting_out,
        "flap clears sitting_out (pre-fix divergence vector)"
    );

    // HandReveal：只有计划内 2 人有 assignment。
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
    drive_reveal_phase(&mut table, &players);

    // ===== 修复断言：盲注账本以 VM 为权威 =====
    let vm_view = table
        .vm_session
        .as_ref()
        .expect("live mirror bootstrapped")
        .current_view();
    assert!(vm_view.in_betting, "VM posted blinds at bootstrap");
    let vm_turn_pk = vm_view.current_turn_pk.clone().expect("VM current turn");
    let turn_seat = table.turn().expect("game-layer turn after blinds");
    let turn_pk = table
        .local_seats
        .get(&turn_seat)
        .and_then(|s| s.player.as_ref())
        .map(|p| p.pk_hex.0.clone())
        .expect("turn seat player");
    assert_eq!(turn_pk, vm_turn_pk, "game-layer turn must equal VM authority");
    // HU 翻牌前 SB 先行动：行动者 street bet == 小盲 50。
    assert_eq!(
        table.local_seats.get(&turn_seat).unwrap().bet,
        50,
        "first actor is the small blind"
    );
    // 计划外座位被钉回 sitting_out，且无幻影注额/turn 残影。
    let s1 = table.local_seats.get(&1).unwrap();
    assert!(s1.sitting_out, "non-plan seat pinned out for this hand");
    assert_eq!(s1.bet, 0, "no phantom blind on non-plan seat");
    assert!(!s1.turn, "no phantom turn on non-plan seat");
    assert!(
        table.hand_excluded_seats.contains(&1),
        "exclusion recorded for next-hand re-admission"
    );

    // ===== 收敛性：首行动者 call → 另一家 check → 进翻牌圈 =====
    // （修复前：游戏层 turn 与 VM 反向，handle_call 被 VM 拒绝返回 None，
    //  expect("call") 直接 panic——即事故现场的永久卡死。）
    act_and_advance(&mut table, &players);
    act_and_advance(&mut table, &players);
    assert_eq!(
        table.round_state(),
        RoundState::Flop,
        "hand must progress past preflop (permanent livelock before fix)"
    );
}

#[test]
fn full_hand_2_players_everyone_shuffles_and_reveals() {
    run_full_hand(9101, 2);
}

#[test]
fn full_hand_9_players_everyone_shuffles_and_reveals() {
    run_full_hand(9102, 9);
}

// ============================================================
// 满手 Hand-batch 批次向量生成（可折叠 reveal 纪元）：
// cargo +nightly test -p texas print_full_hand_batch -- --ignored --nocapture
//
// 跑完整一手（真实洗牌/reveal 流量），捕获全部 reveal token，为每个
// token 铸造可折叠证明（t1 = ω·G, t2 = ω·c1, s = ω + c·sk，c =
// handbatch_reveal_challenge——与合约 reveal_equations 复刻同式），连同
// N 条 ownership 认可组成满手批次，host_fold_check 通过后打印
// Cairo 测试向量。
// ============================================================
#[cfg(test)]
mod full_hand_vector_gen {
    use super::*;
    use crate::starknet::dual_settle::{HandBatchEquation, host_fold_check, parse_batch_terms};

    #[test]
    #[ignore = "vector generator: prints cairo literal"]
    fn print_full_hand_batch() {
        print_full_hand_batch_n(9111, 2, "full_hand_n2");
        print_full_hand_batch_n(9112, 9, "full_hand_n9");
    }

    fn print_full_hand_batch_n(table_id: u32, n: u64, label: &str) {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        let mut table = Table::new(table_id, "full-flow".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, n);
        table.mental_poker_game.encrypt_deck();
        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().unwrap();
            let player = players.iter().find(|p| p.pk_hex == current).unwrap();
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();

        // 捕获全部 reveal token 计数
        let mut captured: usize = 0;
        drive_reveal_phase_capture(&mut table, &players, &mut Some(&mut captured));
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 400);
            if table.reveal_token_state.is_active() {
                let phase_done = drive_reveal_phase_capture(&mut table, &players, &mut Some(&mut captured));
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

        // hand_binding：用确定性值（与 ownership 向量同源方式）
        let mut hand_binding = [0x5Bu8; 32];
        hand_binding[0] = 0x02;

        // ---- ownership 认可（确定性 sk，同 print_stark_batch_vector）----
        use poker_protocol::crypto::curve::StarkCurve;
        type SSC = <StarkCurve as Curve>::Scalar;
        type SPT = <StarkCurve as Curve>::Point;
        let g_stark: SPT = <StarkCurve as Curve>::base_g();
        // 满手含 leave：一条 leave（2 卡：1 剥层 + 1 防亮牌排除槽）
        let mut words: Vec<[u8; 32]> = vec![
            u256_word_pub(n),
            u256_word_pub(0), // n_shuffle（BG 桶待链上 CK/MSM）
            u256_word_pub(captured as u64),
            u256_word_pub(1), // n_leave
            u256_word_pub(0), // n_recon（Hand-batch v2.8 五词头）
        ];
        let mut equations: Vec<HandBatchEquation> = Vec::new();
        for i in 0..n {
            use poker_protocol::crypto::curve::CurveScalar;
            let sk = <crate::starknet::dual_settle::Sc as CurveScalar>::from_u64(7000 + i);
            let pk = g_stark * sk;
            let e = crate::starknet::dual_settle::mint_endorsement(&sk, &pk, &hand_binding);
            let (pk_x, pk_y) = crate::starknet::dual_settle::point_xy(&e.pk);
            let (r_x, r_y) = crate::starknet::dual_settle::point_xy(&e.r);
            let mut s_w = [0u8; 32];
            s_w.copy_from_slice(&e.s.as_bytes());
            words.push(pk_x); words.push(pk_y); words.push(r_x); words.push(r_y); words.push(s_w);
            equations.push(HandBatchEquation::Ownership { s: e.s, pk: e.pk, r: e.r });
        }

        // ---- 可折叠 reveal 证明（StarkCurve，计数/相位来自真实流量）----
        // texas 构建当前在 legacy-bls 下，流程捕获的点是 BLS——gas 成本
        // 只由方程数量与点运算决定（曲线局部），故按真实计数在 StarkCurve
        // 上以同构语句铸造：ct_j 在聚合公钥下加密、token = sk_j·c1_j、
        // 两联方程与 reveal_token_proof 同形（挑战换 dapv 式）。
        let n_reveals = captured;
        for j in 0..n_reveals {
            let sk_j: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let pk_j: SPT = g_stark * sk_j;
            // 确定性密文（在 pk_j 下）与 token
            let msg = <StarkCurve as Curve>::hash_to_curve(
                format!("full-hand-fold/reveal-{j}").as_bytes(),
            );
            let r_j: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let ct_j = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
                &msg, &pk_j, &r_j,
            );
            let token_j = ct_j.c1 * sk_j;
            // 可折叠证明
            let omega: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let t1 = g_stark * omega;
            let t2 = ct_j.c1 * omega;
            let nonce: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let c = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
                &hand_binding, &pk_j, &ct_j.c1, &ct_j.c2, &token_j, &t1, &t2, &nonce,
            );
            let s = omega + c * sk_j;
            let (pk_x, pk_y) = crate::starknet::dual_settle::point_xy(&pk_j);
            let (c1x, c1y) = crate::starknet::dual_settle::point_xy(&ct_j.c1);
            let (c2x, c2y) = crate::starknet::dual_settle::point_xy(&ct_j.c2);
            let (tx, ty) = crate::starknet::dual_settle::point_xy(&token_j);
            let (t1x, t1y) = crate::starknet::dual_settle::point_xy(&t1);
            let (t2x, t2y) = crate::starknet::dual_settle::point_xy(&t2);
            let mut n_w = [0u8; 32];
            n_w.copy_from_slice(&{
                use poker_protocol::crypto::curve::CurveScalar as _;
                nonce.as_bytes()
            });
            let mut s_w = [0u8; 32];
            s_w.copy_from_slice(&{
                use poker_protocol::crypto::curve::CurveScalar as _;
                s.as_bytes()
            });
            for w in [pk_x, pk_y, c1x, c1y, c2x, c2y, tx, ty, t1x, t1y, t2x, t2y, n_w, s_w] {
                words.push(w);
            }
            equations.push(HandBatchEquation::Reveal {
                s, pk: pk_j, c1: ct_j.c1, c2: ct_j.c2,
                token: token_j, t1, t2, nonce,
            });
        }

        // ---- leave 条目（仅剥层子集）----
        // 排除槽（自己手牌，in==out）的 DLEq 方程数学上不可满足（a_i 在
        // 挑战前绑定）——防亮牌设计使然。Hand-batch 的 leave 方程集 = 剥层子集
        //（与客户端 execute_with_exclusions 的子集 DLEq 同构）；排除槽的
        // "原样保留"断言由游戏层执行（leave_player_with_proof 强校验）。
        {
            let lsk: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let l_pk: SPT = g_stark * lsk;
            let omega_l: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let cpk: SPT = g_stark * omega_l;
            let nonce_l: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            // 一张剥层卡（确定性密文）
            let mut cards_v: Vec<crate::starknet::dual_settle::LeaveCardPts> = Vec::new();
            for j in 0..1u64 {
                let msg = <StarkCurve as Curve>::hash_to_curve(
                    format!("full-hand-fold/leave-card-{j}").as_bytes(),
                );
                let r: SSC = <SSC as CurveScalar>::random(&mut OsRng);
                let ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
                    &msg, &l_pk, &r,
                );
                // 剥层：out_c2 = in_c2 − sk·c1（d2 = sk·in_c1 非恒等）
                let out_ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve> {
                    c1: ct.c1,
                    c2: ct.c2 - ct.c1 * lsk,
                };
                let d2 = ct.c2 - out_ct.c2;
                let a = ct.c1 * omega_l;
                let _ = d2;
                cards_v.push(crate::starknet::dual_settle::LeaveCardPts {
                    in_c1: ct.c1,
                    in_c2: ct.c2,
                    out_c1: out_ct.c1,
                    out_c2: out_ct.c2,
                    a,
                });
            }
            let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards_v
                .iter()
                .map(|c| poker_protocol_core::stark_curve::HandLeaveCardWords {
                    in_c1: c.in_c1,
                    in_c2: c.in_c2,
                    out_c1: c.out_c1,
                    out_c2: c.out_c2,
                    a: c.a,
                })
                .collect();
            let c = poker_protocol_core::stark_curve::handbatch_leave_challenge(
                &hand_binding, &l_pk, &cpk, &nonce_l, &card_words,
            );
            let s_l = omega_l + c * lsk;
            // 词：[n=1, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]
            words.push(u256_word_pub(1));
            let (x, y) = crate::starknet::dual_settle::point_xy(&l_pk);
            words.push(x); words.push(y);
            let (x, y) = crate::starknet::dual_settle::point_xy(&cpk);
            words.push(x); words.push(y);
            let mut nb = [0u8; 32]; nb.copy_from_slice(&nonce_l.as_bytes()); words.push(nb);
            let mut sb = [0u8; 32]; sb.copy_from_slice(&s_l.as_bytes()); words.push(sb);
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.in_c1); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.in_c2); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.out_c1); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.out_c2); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.a); words.push(x); words.push(y); }
            equations.push(HandBatchEquation::Leave { s: s_l, pk: l_pk, cpk, nonce: nonce_l, cards: cards_v });
        }

        // host parity 自检
        let parsed = parse_batch_terms(&hand_binding, &words).expect("parse full-hand batch");
        assert_eq!(
            parsed.len(),
            (n as usize) + captured + 1,
            "equation count: n_own + n_reveal + 1 leave"
        );
        assert!(host_fold_check(&hand_binding, &parsed), "full-hand batch must fold to identity");

        // 打印 Cairo 向量
        println!("// {label}: captured {} reveals, {} words", captured, words.len());
        println!("// {label}: payload:");
        println!("        array![");
        for w in &words {
            println!("            0x{},", hex::encode(w));
        }
        println!("        ]");
    }

    fn u256_word_pub(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }
}

// ============================================================
// 开局统一基线重建回归（2026-09-03 双真人物化失败修复）：
// start_preflop_shuffle 必须无条件把牌组重建为 (G, m + 当前 agg) 基线、
// 清空 completed、全员 pending —— 已注册玩家的密钥层由 +agg 预置包含，
// 开局洗牌统一纯 shuffle（明文保持、公钥恒 agg，物化闭环）。
// 该语义同时天然清除孤儿密钥层（洗牌期买入者掉线，份额永久缺失）与
// 上一手残留层，无需单独的孤儿检测分支。
// ============================================================
#[cfg(test)]
mod hand_start_baseline_tests {
    use super::*;
    use crate::pokergame::game_state::ShufflePhase;

    fn agg_baseline_deck(table: &Table) -> Vec<ElGamalCiphertext> {
        let agg = table.mental_poker_game.key_manager.get_aggregated_pk();
        table
            .mental_poker_game
            .deck_plaintext
            .iter()
            .map(|p| ElGamalCiphertext { c1: poker_protocol::crypto::base_g(), c2: *p + agg })
            .collect()
    }

    fn deck_is_baseline(table: &Table) -> bool {
        let d = &table.mental_poker_game.deck_encrypted;
        d.len() == table.mental_poker_game.deck_plaintext.len()
            && d.iter().zip(agg_baseline_deck(table).iter()).all(|(a, b)| a == b)
    }

    /// 开局（无论上一手留下什么牌组/洗牌状态）必须重建基线 + 全员 pending。
    #[test]
    fn hand_start_rebuilds_baseline_and_repends_everyone() {
        let mut table = Table::new(9121, "baseline".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, 2);
        // 上一手遗留：牌组带真实洗牌层、completed 非空
        table.start_preflop_shuffle();
        for p in &players {
            table.set_current_shuffler(p.pk_hex.clone());
            submit_real_shuffle(&mut table, p);
        }
        assert!(!deck_is_baseline(&table), "deck must carry contributed layers pre-reset");
        assert_eq!(table.shuffle_state.completed_players.len(), 2);

        table.shuffle_state.phase = ShufflePhase::None; // 模拟上一手结束
        table.start_preflop_shuffle(); // 新一手开局

        assert!(deck_is_baseline(&table), "deck must reset to (G, m+agg)");
        assert!(table.shuffle_state.completed_players.is_empty(),
            "completed layers are void with the deck");
        let mut pending: Vec<String> = table
            .shuffle_state
            .pending_players
            .iter()
            .map(|p| p.0.clone())
            .collect();
        pending.sort();
        let mut expected: Vec<String> = players.iter().map(|p| p.pk_hex.0.clone()).collect();
        expected.sort();
        assert_eq!(pending, expected, "every player re-shuffles");
        assert_eq!(table.shuffle_state.phase, ShufflePhase::BeforePreflop);
    }

    /// 洗牌期买入者掉线（孤儿层）：开局重置后其注册被移除、基线只含剩余
    /// 玩家的 agg —— 孤儿份额问题随基线重建消失。
    #[test]
    fn hand_start_orphan_layer_dissolves_into_baseline() {
        let mut table = Table::new(9122, "orphan".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, 2);
        table.start_preflop_shuffle();
        for p in &players {
            table.set_current_shuffler(p.pk_hex.clone());
            submit_real_shuffle(&mut table, p);
        }
        let orphan = players[0].pk_hex.clone();
        let survivor = players[1].pk_hex.clone();
        table.stand_player_by_pk(&orphan);
        table.shuffle_state.phase = ShufflePhase::None;
        table.start_preflop_shuffle();

        assert!(deck_is_baseline(&table), "baseline rebuilt without the orphan's layer");
        assert_eq!(table.shuffle_state.pending_players, vec![survivor],
            "only the remaining player re-shuffles");
        assert!(!table.mental_poker_game.players.contains_key(orphan.to_string().as_str()));
    }
}

// ============================================================
// snip36 递归证明 e2e：真实一手牌 → 每参与者首条已签名动作 →
// action-sig 批次 → host 直验 + 承诺链对拍 → （ignore）完整出证。
// 证明材料 = 动作签名 v3（endorsement 退役后的唯一参与背书来源）。
// ============================================================
mod recursion_e2e {
    use super::*;
    use crate::pokergame::actions::ActionSig;
    use crate::starknet::recursion_prover;
    use hand_verify_native::recurse::{
        build_action_batch_payload, fold_accumulator, RecurseTask, GENESIS_ACC,
    };
    use hand_verify_native::handbatch::{payload_digest, verify_hand};
    use poker_protocol::z_poker::protocol::sign_game_action;

    /// 带签名的动作：v3 域签名 → 服务端验签（table 口径）→ 动作执行 →
    /// record_action 落签名本体（镜像 game_loop 接受点的完整链路）。
    fn signed_act_and_advance(
        table: &mut Table,
        players: &[Player],
        action_override: Option<&str>,
    ) {
        let turn_seat = table.turn().expect("betting must have a current turn");
        let turn_pk = {
            let seat = table.local_seats.get(&turn_seat).expect("turn seat");
            seat.player.as_ref().expect("seat occupied").pk_hex.clone()
        };
        let player = players.iter().find(|p| p.pk_hex == turn_pk).expect("turn player");

        let others_max_bet = table
            .local_seats
            .values()
            .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
            .map(|s| s.total_bet)
            .max()
            .unwrap_or(0);
        let my_bet = table.local_seats.get(&turn_seat).map(|s| s.total_bet).unwrap_or(0);
        let action = match action_override {
            Some(a) => a.to_string(),
            None => {
                if my_bet < others_max_bet { "call".to_string() } else { "check".to_string() }
            }
        };
        let amount = if action == "call" {
            others_max_bet.saturating_sub(my_bet)
        } else {
            0
        };

        // v3 签名（hand_id 从开局分配值——与真实客户端同源）。
        let hand_id = table
            .hand_proof_log
            .start
            .as_ref()
            .expect("hand started")
            .hand_id;
        let seat = table
            .find_player_by_pk(&player.pk_hex)
            .expect("turn player seated")
            .id;
        let seq = table.accepted_seq_of(seat) + 1;
        let (r_hex, s_hex) = sign_game_action(
            &player.client.sk,
            table.summary.id,
            hand_id,
            seq,
            &action,
            amount,
            &mut OsRng,
        );
        let sig = ActionSig { r_hex: r_hex.clone(), s_hex: s_hex.clone() };

        // 服务端口径验签（table_id/hand_id/seq/action/amount 全进签名域）。
        assert!(
            table.verify_action_sig(&player.pk_hex, seq, &action, amount, &sig),
            "signature must verify against the table domain"
        );

        let result = match action.as_str() {
            "call" => table.handle_call(&player.pk_hex),
            "check" => table.handle_check(&player.pk_hex),
            _ => unreachable!("test only drives check/call"),
        };
        let _ = result;

        // 接受点：seq 单调 + 签名本体落日志（game_loop 镜像）。
        let seq = seq.max(table.accepted_seq_of(seat));
        table.record_action(seat, seq, &action, amount, false, true, Some(sig));

        // turn/phase 推进镜像（对齐生产 handle_turn_advance 的权威模式）：
        // vm_session 存在时 turn 轮转由 VM 视图同步负责（accepted 动作经
        // apply_betting_view、拒绝动作经 sync_rejected_view），此处再手动
        // 轮转会双重推进——拒绝路径上把权威同步的 turn 又盲转过一位，
        // 活锁（2026-09-14 recursion_e2e 复现）。仅本地兜底模式才手动轮转。
        if table.unfolded_players().len() <= 1 {
            table.end_without_showdown();
        } else if table.is_betting_round_complete() {
            table.set_turn(None);
            table.advance_to_next_phase();
        } else if table.vm_session.is_none() {
            let last = table.turn().unwrap_or(1);
            table.set_turn(table.next_unfolded_player(last, 1));
        }
    }

    /// 与 run_full_hand 同骨架，但下注轮全部走带签名动作。
    fn run_signed_full_hand(table_id: u32) -> Table {
        let mut table = Table::new(table_id, "recursion-e2e".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, 2);
        table.mental_poker_game.encrypt_deck();

        table.start_hand();
        let mut shuffled = 0;
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table
                .shuffle_state
                .current_player_pk
                .clone()
                .expect("current shuffler set");
            let player = players
                .iter()
                .find(|p| p.pk_hex == current)
                .expect("current shuffler seated");
            submit_real_shuffle(&mut table, player);
            shuffled += 1;
        }
        assert_eq!(shuffled, 2, "every player shuffles exactly once");
        table.advance_shuffle();
        assert!(table.reveal_token_state.phase == RevealPhase::HandReveal);
        drive_reveal_phase(&mut table, &players);

        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 400, "game did not terminate");
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
                signed_act_and_advance(&mut table, &players, None);
                continue;
            }
            break;
        }
        assert!(
            table.summary.went_to_showdown,
            "check/call line goes to showdown"
        );
        table
    }

    /// 2026-09-07 线上回归：win_hand（派彩）会清零赢家自己的
    /// total_bet，而 take_settle_input 在派彩后执行——不快照则摊牌手的
    /// 结算对账恒为 "vm 累计 vs game 0" 必拒（两手线上复现）。
    /// 派彩前快照（record_final_bets）必须保留终局投入。
    #[test]
    fn showdown_settle_keeps_pre_payout_total_bets() {
        let table = run_signed_full_hand(9131);
        // 摊牌派彩已完成（win_hand 已清零赢家的 seat.total_bet）……
        let any_seat_bet_left = table
            .seats()
            .values()
            .any(|s| s.total_bet > 0 && s.player.is_some());
        // ……但快照必须存在且保留派彩前投入（盲注 50/100 → 每人 ≥50，
        // check/call 线两人相同 = 150）。
        let snap = table
            .hand_proof_log
            .final_total_bets
            .as_ref()
            .expect("final_total_bets snapshot taken before payout");
        assert_eq!(snap.len(), 2, "two participants snapshotted");
        assert!(
            snap.iter().all(|(_, b)| *b >= 50),
            "snapshot keeps pre-payout contributions: {snap:?}"
        );
        // take 必须用快照：即使座位实时值已被派彩清零（至少赢家为 0）。
        let _ = any_seat_bet_left;
        let input = crate::starknet::prove_log::take_settle_input(&table)
            .expect("settle input");
        for (wallet, snap_bet) in snap {
            let taken = input
                .total_bets
                .iter()
                .find(|(w, _)| w == wallet)
                .map(|(_, b)| *b)
                .expect("wallet in taken total_bets");
            assert_eq!(taken, *snap_bet, "take must use pre-payout snapshot");
        }
    }

    /// host 自验（不出证，毫秒级）：一手真实牌的已签名动作 →
    /// action-sig 批次 → host 直验闭合 → 承诺链对拍确定性。
    #[test]
    fn recursion_e2e_signed_hand_host_verify() {
        // table_id 4242：join_buffer 按 (table_id, wallet) 键控——与其他共用
        // table_id=9 + "0xwallet{idx}" 的 full_hand 测试并发跑时会互相覆盖
        // join 证明缓冲，record_hand_start 读到别桌 pk → participants 与
        // 签名 pk 错配（残差不闭合，2026-09-07 e2e 间歇失败根因）。
        let table = run_signed_full_hand(9132);

        // 材料提取：每参与者首条已签名动作 + 座位公钥。
        let start = table.hand_proof_log.start.as_ref().expect("hand started");
        let hand_id = start.hand_id;
        let materials = recursion_prover::action_sig_materials(
            &table.action_log,
            &start.participants,
        );
        assert_eq!(
            materials.len(),
            start.participants.len(),
            "every participant must have a first signed action"
        );

        // 组批（v3 header 6 词 + 每语句 10 词）。
        let hb = starknet_crypto::Felt::from(0xABCDu64);
        let statements: Vec<hand_verify_native::recurse::ActionSigStatement> = materials
            .iter()
            .map(|m| hand_verify_native::recurse::ActionSigStatement {
                pk_x_hex: m.pk_x_hex.clone(),
                pk_y_hex: m.pk_y_hex.clone(),
                r_x_hex: m.r_x_hex.clone(),
                r_y_hex: m.r_y_hex.clone(),
                s_hex: m.s_hex.clone(),
                table_id: table.summary.id,
                hand_id,
                seq: m.seq,
                action: m.action.clone(),
                amount: m.amount,
            })
            .collect();
        let payload =
            build_action_batch_payload(hb, table.summary.id, hand_id, &statements)
                .expect("batch build");

        // host 直验（与 Cairo verify_hand 同构的方程检查）。
        let report = verify_hand(hb, &payload).expect("host verify");
        assert!(report.accepted(), "signed batch must verify host-side");
        assert_eq!(report.n_action, 2, "two action-sig statements");
        assert_eq!(report.n_own, 0, "ownership bucket retired with endorsements");

        // 承诺链对拍：claim 与 acc 与 host 独立重算一致。
        let task = RecurseTask { hand_binding: hb, payload: payload.clone() };
        let claim = task.claim(&report);
        let acc = fold_accumulator(GENESIS_ACC, &[claim]);
        // digest 也应是 payload 的确定性函数（重算一次比对）。
        let claim2 = poseidon_reclaim(hb, &payload, &report);
        assert_eq!(claim, claim2, "claim must be deterministic");
        assert!(acc != starknet_crypto::Felt::ZERO);
    }

    fn poseidon_reclaim(
        hb: starknet_crypto::Felt,
        payload: &[starknet_crypto::Felt],
        report: &hand_verify_native::handbatch::VerifyReport,
    ) -> starknet_crypto::Felt {
        use starknet_crypto::{poseidon_hash_many, Felt};
        let digest = payload_digest(payload);
        poseidon_hash_many(&[
            hb,
            digest,
            Felt::from(report.n_own),
            Felt::from(report.n_reveal),
            Felt::from(report.n_leave),
            Felt::from(report.n_recon),
            Felt::from(report.n_action),
        ])
    }

    /// 完整出证（真实 prove-hand：compile → run → prove → 内置 verify →
    /// parity 门）。需要 proving-tool/target/release/prove-hand。
    #[test]
    #[ignore = "runs prove-hand (~15s); needs proving-tool release binary"]
    fn recursion_e2e_signed_hand_full_prove() {
        let table = run_signed_full_hand(9132);
        let start = table.hand_proof_log.start.as_ref().expect("hand started");
        let hand_id = start.hand_id;
        let materials = recursion_prover::action_sig_materials(
            &table.action_log,
            &start.participants,
        );
        assert_eq!(materials.len(), 2);
        let out_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("output/e2e-signed-hand");
        let out = recursion_prover::prove_batch_blocking(
            table.summary.id,
            hand_id,
            hand_binding_bytes(&table),
            &materials,
            &out_dir,
        )
        .expect("full prove");
        assert_eq!(out.acc.len(), 64, "acc is a 32-byte felt hex");
        assert!(out.ec_ops > 0, "EC residuals proven in trace");
        println!(
            "e2e prove ok: acc={} steps={} ec_ops={} elapsed_ms={}",
            out.acc, out.steps, out.ec_ops, out.elapsed_ms
        );
    }

    fn hand_binding_bytes(table: &Table) -> [u8; 32] {
        let mut hb = [0xABu8; 32];
        hb[0] = 0x03;
        let _ = table;
        hb
    }
}

/// Phase 1 影子证明机集成测试：一手真实加密牌局，reveal 在 WS 同款接受点
/// 补记日志，验证影子 VM 单遍实时 dispatch 与游戏层终局事实零分歧。
mod shadow_e2e {
    use super::*;

    /// seat_players 已统一为有效 felt 钱包（权威模式全量覆盖）。
    fn seat_players_hex_wallets(table: &mut Table, n: u64) -> Vec<Player> {
        seat_players(table, n)
    }

    /// drive_reveal_phase + WS handler 同款 reveal 采集点（socket/mod.rs:861）：
    /// 提交被接受后立即接入实时 VM 镜像接受点（与 WS handler 同位）。
    fn drive_reveal_and_record(table: &mut Table, players: &[Player]) -> RevealPhase {
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
                .expect("pending player must be seated");
            let assign = table
                .reveal_token_state
                .player_assignments
                .get(&pk_hex)
                .cloned()
                .expect("assignment for pending player");
            let cards: Vec<ElGamalCiphertext> = match phase {
                RevealPhase::HandReveal | RevealPhase::RedealReveal | RevealPhase::ShowdownReveal => assign.hand_card,
                RevealPhase::CommunityReveal => assign.community_card,
                RevealPhase::None => unreachable!(),
            };
            let mut tokens = Vec::new();
            for ct in cards {
                let token = ct.gen_reveal_token(&player.client.sk);
                let proof = RevealTokenProof::prove(
                    &player.client.sk,
                    &player.client.pk,
                    &ct,
                    &token,
                    &mut OsRng,
                    &mut PoseidonFeltTranscript::new_domain(poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON),
                );
                tokens.push(poker_protocol::z_poker::protocol::RevealToken {
                    encrypted_card: ct,
                    proof,
                    reveal_token: token,
                    user_public_key: player.client.pk,
                });
            }
            table
                .submit_player_reveal_tokens(&pk_hex, tokens.clone())
                .unwrap_or_else(|e| panic!("{phase:?} token submit failed for {pk_hex}: {e}"));
            table.mark_player_reveal_complete(&pk_hex);
        }
        assert!(
            !table.reveal_token_state.is_active(),
            "reveal phase must complete after all submissions"
        );
        phase
    }

    #[test]
    fn shadow_one_pass_matches_game_layer() {
        let table = drive_showdown_hand(424242);

        let report = crate::starknet::vm_session::take_last_report_for_test(424242)
            .expect("shadow must have finished with the hand");
        assert_eq!(report.hand_id, table.current_hand_id, "shadow hand id");
        assert_eq!(report.metrics.bet_fail, 0, "one-pass bet failures: {report:?}");
        assert!(report.metrics.reveal_ok > 0, "no reveals dispatched: {report:?}");
        assert!(report.metrics.bet_ok > 0, "no bets dispatched: {report:?}");
        assert!(report.issues.is_empty(), "shadow parity issues: {report:?}");
    }

    /// 回归（2026-09-10）：被 VM 拒绝的下注（bet_fail > 0）不再阻断结算——
    /// 结算门只看对账分歧（issues）。恶意玩家单条非法/抢跑下注不能令
    /// 该手不可结算。
    #[test]
    fn rejected_bet_does_not_block_settlement() {
        let table_id = 424244;
        let table = drive_showdown_hand_opt(table_id, true);

        let report = crate::starknet::vm_session::take_last_report_for_test(table_id)
            .expect("shadow must have finished with the hand");
        assert_eq!(report.metrics.bet_fail, 1, "exactly one rejected bet: {report:?}");
        assert!(report.issues.is_empty(), "rejected bet is client noise, not divergence: {report:?}");

        // 结算输入照常产出、快照对账通过（旧门 bet_fail>0 会在此前拒掉这手）。
        let input = crate::starknet::prove_log::take_settle_input(&table)
            .expect("hand must have settle input");
        let mirror = crate::starknet::vm_session::take_last_mirror_for_test(table_id)
            .expect("live hand mirror");
        crate::starknet::hooks::cross_check_snapshot(&mirror, &input)
            .expect("snapshot parity holds despite rejected bet");
    }

    /// 驱动一手完整摊牌（真实加密 + reveal 补记 + 下注），走到
    /// finish_showdown（on_hand_complete 已触发）。供影子对账与生产
    /// 结算对账两个 e2e 复用。
    fn drive_showdown_hand(table_id: u32) -> Table {
        drive_showdown_hand_opt(table_id, false)
    }

    /// `inject_rejected_bet = true`：首次轮到行动者前，让**非行动者**
    /// 抢跑一次 call——VM 必须拒绝（bet_fail +1），且该拒绝不得影响
    /// 后续结算（回归：bet_fail 不再是结算门，2026-09-10）。
    fn drive_showdown_hand_opt(table_id: u32, inject_rejected_bet: bool) -> Table {
        let mut table = Table::new(table_id, "parity-e2e".to_string(), 10000, 9, String::new());
        let players = seat_players_hex_wallets(&mut table, 2);
        table.mental_poker_game.encrypt_deck();

        table.start_hand();
        let mut shuffled = 0;
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table
                .shuffle_state
                .current_player_pk
                .clone()
                .expect("current shuffler set");
            let player = players
                .iter()
                .find(|p| p.pk_hex == current)
                .expect("current shuffler seated");
            submit_real_shuffle(&mut table, player);
            shuffled += 1;
        }
        assert_eq!(shuffled, 2, "every player shuffles exactly once");
        table.advance_shuffle();
        assert!(!table.shuffle_state.is_active());

        let mut steps = 0;
        let mut injected = false;
        loop {
            steps += 1;
            assert!(steps < 400, "game did not terminate");
            if table.reveal_token_state.is_active() {
                let phase_done = drive_reveal_and_record(&mut table, &players);
                if phase_done == RevealPhase::ShowdownReveal {
                    table.finish_showdown();
                    break;
                }
                continue;
            }
            if table.summary.hand_over || table.round_state() == RoundState::Waiting {
                break;
            }
            if table.turn().is_some() {
                if inject_rejected_bet && !injected {
                    injected = true;
                    let turn_pk = {
                        let seat = table.local_seats.get(&table.turn().expect("turn")).expect("turn seat");
                        seat.player.as_ref().expect("seat occupied").pk_hex.clone()
                    };
                    let bystander = players.iter().find(|p| p.pk_hex != turn_pk).expect("bystander");
                    assert!(
                        table.handle_call(&bystander.pk_hex).is_none(),
                        "out-of-turn call must be rejected by VM"
                    );
                }
                act_and_advance(&mut table, &players);
                continue;
            }
            break;
        }
        assert!(table.summary.went_to_showdown, "check/call line goes to showdown");
        table
    }

    /// Phase 0 生产结算路径全量对账 e2e：真实游戏手 → 实时 VM 镜像终局
    /// 比对 → settle_hand（真实 stwo 证明 + calldata 组装）→
    /// cross_check_snapshot + cross_check_deltas 全过——生产 fail-closed
    /// 对账链路的端到端验收（镜像即结算唯一 VM 来源，无第二份重放）。
    #[test]
    fn settlement_build_passes_full_parity_checks() {
        let table_id = 424243;
        let table = drive_showdown_hand(table_id);

        let input = crate::starknet::prove_log::take_settle_input(&table)
            .expect("hand must have settle input");
        // 单一状态表示：结算直接取用实时镜像（无重放构建）。
        // （on_hand_complete 已在 drive 中消费实时镜像并完成终局比对，
        // 测试经 test-only stash 取回镜像与报告。）
        let report = crate::starknet::vm_session::take_last_report_for_test(table_id)
            .expect("live mirror finish report");
        assert!(
            report.issues.is_empty() && report.metrics.bet_fail == 0,
            "live mirror must match game layer: {report:?}"
        );
        let mirror = crate::starknet::vm_session::take_last_mirror_for_test(table_id)
            .expect("live hand mirror");

        // 对账 1（快照）：board / per-wallet total_bet。
        crate::starknet::hooks::cross_check_snapshot(&mirror, &input)
            .expect("snapshot parity");

        // 生产结算构建：分池 + 真实证明 + calldata（含 treasury 台费项）。
        let wallet_map: Vec<(poker_l1::Address, starknet_crypto::Felt)> = input
            .start
            .participants
            .iter()
            .filter_map(|p| {
                let addr = crate::starknet::vm_session::VmTable::addr_from_starknet(&p.wallet)?;
                let felt = crate::starknet::chain::parse_felt(&p.wallet)?;
                Some((addr, felt))
            })
            .collect();
        let treasury: poker_l1::Address = [0x77u8; 20];
        let action_log_digest = starknet_crypto::Felt::from(0xBEEF_u64);
        let settlement = crate::starknet::submit::settle_hand(
            &mirror,
            Some(treasury),
            &wallet_map,
            action_log_digest,
            &[],
        )
        .expect("settlement build (real prove)");

        // 对账 2/3：rake + 逐钱包净输赢。
        assert!(
            !settlement.deltas.is_empty(),
            "settlement must carry player deltas"
        );
        crate::starknet::hooks::cross_check_deltas(
            &settlement.players_remapped,
            &settlement.deltas,
            &input,
        )
        .expect("delta parity through the production settle path");
    }
}

// ============================================================
// 控制轨迹捕获（控制逻辑入 AIR 的原料契约）：VmTable.traces 必须为
// canonical witness 生产者提供完整、链式咬合的 pre/post 链——
// - 跨 dispatch：traces[i].post == traces[i+1].pre；
// - dispatch 内：normalize steps 逐步咬合，末步落在 dispatch 终态；
// - 级联以多个单步呈现（不再折叠成一对 pre/post）。
// ============================================================
mod trace_capture_tests {
    use super::*;
    use poker_l1::contracts::texas_poker::state_machine::NormalizationStep;

    #[test]
    fn dispatch_traces_are_chained_and_complete() {
        let table_id = 424_262u32;
        let mut table = Table::new(table_id, "traces".to_string(), 10000, 9, String::new());
        let players = allin_e2e::seat_players_bankroll(&mut table, 2, 10_000);
        table.mental_poker_game.encrypt_deck();
        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().unwrap();
            let player = players.iter().find(|p| p.pk_hex == current).unwrap();
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();
        allin_e2e::drive_reveal_cascade(&mut table, &players);
        // 一注跟注后终局弃牌：覆盖 betting 命令行 + EndWithoutShowdown 级联。
        let turn_pk = {
            let seat = table.local_seats.get(&table.turn().expect("turn")).unwrap();
            seat.player.as_ref().unwrap().pk_hex.clone()
        };
        assert!(table.handle_call(&turn_pk).is_some());
        let next_pk = {
            let seat = table.local_seats.get(&table.turn().expect("turn")).unwrap();
            seat.player.as_ref().unwrap().pk_hex.clone()
        };
        assert!(table.handle_fold(&next_pk).is_some());
        assert!(table.summary.hand_over, "terminal fold ended the hand");

        let mirror = crate::starknet::vm_session::take_last_mirror_for_test(table_id)
            .expect("live hand mirror");
        let traces = &mirror.traces;
        assert!(
            traces.len() >= 3,
            "reveal submissions + call + fold all recorded: {}",
            traces.len()
        );
        // 跨 dispatch 链式咬合。
        for w in traces.windows(2) {
            assert_eq!(w[0].post, w[1].pre, "dispatch chain broken at {:?}", w[0].selector);
        }
        // dispatch 内部：normalize 步步咬合、末步即终态。
        let mut step_rows = 0usize;
        for t in traces {
            for s in t.normalization.steps.windows(2) {
                assert_eq!(s[0].post, s[1].pre, "step chain broken in {:?}", s[0].step);
            }
            if let Some(last) = t.normalization.steps.last() {
                assert_eq!(
                    last.post, t.post,
                    "last normalize step must land on the dispatch end state"
                );
            }
            step_rows += t.normalization.steps.len();
        }
        assert!(step_rows > 0, "reveal-complete cascades captured: {step_rows}");
        // 终局弃牌的最后一次状态变更 dispatch 含 EndWithoutShowdown 级联。
        let last = traces.last().unwrap();
        assert!(
            last.normalization
                .steps
                .iter()
                .any(|s| matches!(s.step, NormalizationStep::EndWithoutShowdown)),
            "terminal fold dispatch carries the EndWithoutShowdown micro-step: {:?}",
            last.normalization.steps.iter().map(|s| s.step).collect::<Vec<_>>()
        );
    }
}

// ============================================================
// All-in 路径 e2e（Stage 0 基线 + Stage 2 回归锚点）：
// 既有全部满手测试只打 check/call 线——all-in（及盲注即 all-in 的
// runout）是历史零覆盖路径，也正是 PotCollected 单街收注投影分歧
//（reveal dispatch 内多街 normalize 级联）的触发场景。
// ============================================================
mod allin_e2e {
    use super::*;

    /// seat_players 的可调买入版本（1BB 场景需要小买入）。
    pub(super) fn seat_players_bankroll(table: &mut Table, n: u64, bankroll: u64) -> Vec<Player> {
        let mut players = Vec::new();
        for idx in 1..=n {
            let client = ClientPlayer::new();
            let proof = client.generate_pk_proof();
            let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
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
                bankroll: bankroll as i64,
                pk_hex: GamePkHex::new(pk_hex.clone()),
                readable_hands: vec![],
                wallet_address: WalletAddress(format!("0x{:064x}", idx)),
            };
            table.sit_player(player, idx as u32, bankroll, false);
            if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
                seat.folded = false;
            }
            players.push(Player { pk_hex: GamePkHex::new(pk_hex), client });
        }
        players
    }

    /// game_loop::handle_turn_advance 的纯表镜像 + 揭牌仪式守卫
    /// （reveal 激活时不推进——2026-09-07 双推进回归的守卫语义）。
    /// `first = true` 时当前行动者直接 all-in，其后所有人 call。
    pub(crate) fn act_allin_then_call(table: &mut Table, players: &[Player], first: &mut bool) {
        let turn_seat = table.turn().expect("betting must have a current turn");
        let turn_pk = {
            let seat = table.local_seats.get(&turn_seat).expect("turn seat");
            seat.player.as_ref().expect("seat occupied").pk_hex.clone()
        };
        let player = players.iter().find(|p| p.pk_hex == turn_pk).expect("turn player");
        if *first {
            *first = false;
            assert!(
                table.handle_allin(&player.pk_hex).is_some(),
                "all-in raise must be accepted"
            );
        } else {
            assert!(table.handle_call(&player.pk_hex).is_some(), "call must be accepted");
        }
        // 推进守卫：all-in 跟注后 VM 在 dispatch 内收注推进到下一街
        //（apply_betting_view 已触发游戏层仪式）——此处不得二次推进。
        if table.reveal_token_state.is_active() {
            return;
        }
        if table.unfolded_players().len() <= 1 {
            table.end_without_showdown();
        } else if table.is_betting_round_complete() {
            table.set_turn(None);
            table.advance_to_next_phase();
        }
    }

    /// 驱动连续 reveal 窗口（all-in runout 特有：窗口完成后下注轮被跳过、
    /// 下一街窗口立即链式打开）。返回 Some(ShowdownReveal) 表示摊牌窗口
    /// 已消化完毕；None 表示窗口链停在了一个下注轮上。
    pub(super) fn drive_reveal_cascade(table: &mut Table, players: &[Player]) -> Option<RevealPhase> {
        let mut windows = 0;
        while table.reveal_token_state.is_active() {
            windows += 1;
            assert!(windows < 12, "reveal cascade did not terminate");
            let phase = table.reveal_token_state.phase;
            let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
            assert!(!pending.is_empty(), "active window must have pending players");
            for pk_hex in pending {
                let player = players
                    .iter()
                    .find(|p| p.pk_hex == pk_hex)
                    .expect("pending player must be seated");
                let assign = table
                    .reveal_token_state
                    .player_assignments
                    .get(&pk_hex)
                    .cloned()
                    .expect("assignment for pending player");
                let cards: Vec<ElGamalCiphertext> = match phase {
                    RevealPhase::HandReveal | RevealPhase::RedealReveal | RevealPhase::ShowdownReveal => assign.hand_card,
                    RevealPhase::CommunityReveal => assign.community_card,
                    RevealPhase::None => unreachable!(),
                };
                let mut tokens = Vec::new();
                for ct in cards {
                    let token = ct.gen_reveal_token(&player.client.sk);
                    let proof = RevealTokenProof::prove(
                        &player.client.sk,
                        &player.client.pk,
                        &ct,
                        &token,
                        &mut OsRng,
                        &mut PoseidonFeltTranscript::new_domain(poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON),
                    );
                    tokens.push(poker_protocol::z_poker::protocol::RevealToken {
                        encrypted_card: ct,
                        proof,
                        reveal_token: token,
                        user_public_key: player.client.pk,
                    });
                }
                table
                    .submit_player_reveal_tokens(&pk_hex, tokens)
                    .unwrap_or_else(|e| panic!("{phase:?} token submit failed for {pk_hex}: {e}"));
                table.mark_player_reveal_complete(&pk_hex);
            }
            if phase == RevealPhase::ShowdownReveal {
                assert!(!table.reveal_token_state.is_active(), "showdown closes the hand");
                return Some(phase);
            }
            // on_reveal_complete 已触发：runout 链式开下一街窗口，或恢复下注轮。
        }
        None
    }

    /// 驱动一手 all-in runout 到摊牌（真实洗牌/reveal + 实时镜像路径）。
    fn drive_allin_hand(table_id: u32, bankroll: u64) -> Table {
        let mut table = Table::new(table_id, "allin-e2e".to_string(), 10000, 9, String::new());
        let players = seat_players_bankroll(&mut table, 2, bankroll);
        table.mental_poker_game.encrypt_deck();

        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table
                .shuffle_state
                .current_player_pk
                .clone()
                .expect("current shuffler set");
            let player = players
                .iter()
                .find(|p| p.pk_hex == current)
                .expect("current shuffler seated");
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();
        assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
        drive_reveal_cascade(&mut table, &players);

        let mut steps = 0;
        let mut first_action = true;
        loop {
            steps += 1;
            assert!(steps < 400, "game did not terminate");
            if table.reveal_token_state.is_active() {
                if let Some(RevealPhase::ShowdownReveal) = drive_reveal_cascade(&mut table, &players) {
                    table.finish_showdown();
                    break;
                }
                continue;
            }
            if table.summary.hand_over || table.round_state() == RoundState::Waiting {
                break;
            }
            if table.turn().is_some() {
                act_allin_then_call(&mut table, &players, &mut first_action);
                continue;
            }
            break;
        }
        table
    }

    /// 超时 fold 的 VM 权威路径：真实手牌进入下注轮后把计时起点拨回
    /// 超时阈值之前，check_betting_timeout → handle_fold → VM dispatch
    /// 弃牌（本地兜底已删除，此为唯一超时弃牌路径）。终局弃牌必须确定
    /// 性终结手牌（游戏层派奖 + 结算输入）——此前 post-reset 视图令
    /// unfolded≤1 推断永不成立，手牌卡死（2026-09-14 探针实测回归）。
    #[test]
    fn betting_timeout_folds_via_vm() {
        let table_id = 424_254u32;
        let mut table = Table::new(table_id, "timeout-e2e".to_string(), 10000, 9, String::new());
        let players = seat_players_bankroll(&mut table, 2, 10_000);
        table.mental_poker_game.encrypt_deck();

        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().expect("shuffler");
            let player = players.iter().find(|p| p.pk_hex == current).expect("seated");
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();
        assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
        drive_reveal_cascade(&mut table, &players);
        let turn_seat = table.turn().expect("betting started after blinds");
        let turn_pk = {
            let seat = table.local_seats.get(&turn_seat).expect("turn seat");
            seat.player.as_ref().expect("occupied").pk_hex.clone()
        };

        table.set_betting_started_at(now_ms().saturating_sub(60_000));
        let r = table.check_betting_timeout(30).expect("timeout must fold via VM");
        assert_eq!(r.seat_id, turn_seat);
        // 终局弃牌 → 手牌当场终结（fold-win 派奖 + Waiting）。
        assert!(table.summary.hand_over, "terminal fold ends the hand immediately");
        assert_eq!(table.round_state(), RoundState::Waiting);
        assert!(!table.summary.win_messages.is_empty(), "fold-win payout recorded");
        // 终局前账目保留（对账基准）：两人盲注各 ≥ 50。
        let snap = table
            .hand_proof_log
            .final_total_bets
            .as_ref()
            .expect("pre-payout totals snapshotted");
        assert!(snap.iter().all(|(_, b)| *b >= 50), "totals preserved: {snap:?}");
        // 结算输入可产出（游戏层/镜像对账基准完好）。
        assert!(crate::starknet::prove_log::take_settle_input(&table).is_some());
    }

    /// 主动终局弃牌（客户端 FOLD 路径）同样当场终结：fold-win 派奖 +
    /// 影像零分歧 + 生产结算构建通过。
    #[test]
    fn terminal_fold_ends_hand_and_settles() {
        let table_id = 424_261u32;
        let mut table = Table::new(table_id, "foldout".to_string(), 10000, 9, String::new());
        let players = seat_players_bankroll(&mut table, 2, 10_000);
        table.mental_poker_game.encrypt_deck();
        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().unwrap();
            let player = players.iter().find(|p| p.pk_hex == current).unwrap();
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();
        drive_reveal_cascade(&mut table, &players);
        let turn_seat = table.turn().expect("betting started");
        let turn_pk = {
            let seat = table.local_seats.get(&turn_seat).unwrap();
            seat.player.as_ref().unwrap().pk_hex.clone()
        };
        let totals_before: Vec<(u32, u64)> = {
            let mut v: Vec<(u32, u64)> = table.local_seats.values().map(|s| (s.id, s.total_bet)).collect();
            v.sort();
            v
        };

        let r = table.handle_fold(&turn_pk).expect("fold accepted");
        assert_eq!(r.seat_id, turn_seat);
        assert!(table.summary.hand_over, "hand ends on terminal fold");
        assert_eq!(table.round_state(), RoundState::Waiting);
        assert!(!table.summary.win_messages.is_empty());

        let report = crate::starknet::vm_session::take_last_report_for_test(table_id)
            .expect("shadow finished with the hand");
        assert!(report.issues.is_empty(), "fold-out parity: {report:?}");
        let _ = totals_before;

        // 生产结算构建（镜像 pre_settlement 快照 + 证明链）。
        let input = crate::starknet::prove_log::take_settle_input(&table)
            .expect("settle input after fold-win");
        let mirror = crate::starknet::vm_session::take_last_mirror_for_test(table_id)
            .expect("live hand mirror");
        crate::starknet::hooks::cross_check_snapshot(&mirror, &input)
            .expect("fold-out snapshot parity");
        let wallet_map: Vec<(poker_l1::Address, starknet_crypto::Felt)> = input
            .start
            .participants
            .iter()
            .filter_map(|p| {
                let addr = crate::starknet::vm_session::VmTable::addr_from_starknet(&p.wallet)?;
                let felt = crate::starknet::chain::parse_felt(&p.wallet)?;
                Some((addr, felt))
            })
            .collect();
        let settlement = crate::starknet::submit::settle_hand(
            &mirror,
            Some([0x77u8; 20]),
            &wallet_map,
            starknet_crypto::Felt::from(0xBEEF_u64),
            &[],
        )
        .expect("production settlement build accepts the fold-out");
        assert!(!settlement.deltas.is_empty());
    }

    /// 大筹码 all-in（首行动全下 + 对方跟注）→ runout 到摊牌：实时镜像
    /// 与游戏层零分歧（既有满手测试从未覆盖 all-in 行动路径）。
    #[test]
    fn allin_raise_and_call_runs_out_to_showdown() {
        let table_id = 424_252u32;
        let table = drive_allin_hand(table_id, 10_000);

        assert!(table.summary.went_to_showdown, "all-in runout reaches showdown");
        assert_eq!(
            table.mental_poker_game.list_revealed_community_cards().len(),
            5,
            "board completes without betting"
        );
        let report = crate::starknet::vm_session::take_last_report_for_test(table_id)
            .expect("shadow must have finished with the hand");
        assert_eq!(report.metrics.bet_fail, 0, "one-pass bet failures: {report:?}");
        assert!(report.metrics.bet_ok >= 2, "allin + call dispatched: {report:?}");
        assert!(report.issues.is_empty(), "shadow parity on all-in runout: {report:?}");
    }

    /// 1BB 盲注 all-in（双方买入恰为一大盲 → 盲注即全下）的镜像侧验收：
    /// 游戏层/镜像零分歧 + 逐钱包对账。控制逻辑入 AIR 的出证验收由
    /// `starknet::canonical_trace_roundtrip::
    /// blind_allin_control_trace_proves_as_canonical_row_chain` 承担
    /// （封顶盲注 Reveal completion + all-in Call + AdvanceRound 行链
    /// 真实 stwo 出证）；legacy composite 结算路径对该级联仍 fail-closed
    /// （postflop completion 的 AIR 扩写后接线，见 docs/STATUS.md）。
    #[test]
    fn one_bb_blind_allin_hand_mirror_parity() {
        let table_id = 424_253u32;
        let table = drive_allin_hand(table_id, 100);
        assert!(table.summary.went_to_showdown, "blind all-in runs out to showdown");

        let input = crate::starknet::prove_log::take_settle_input(&table)
            .expect("hand must have settle input");
        let report = crate::starknet::vm_session::take_last_report_for_test(table_id)
            .expect("live mirror finish report");
        assert!(report.issues.is_empty(), "game/mirror parity: {report:?}");
        let mirror = crate::starknet::vm_session::take_last_mirror_for_test(table_id)
            .expect("live hand mirror");
        crate::starknet::hooks::cross_check_snapshot(&mirror, &input)
            .expect("blind all-in snapshot parity");
    }
}

// ============================================================
// Stage 2 端到端验收 driver：真实手牌驱动到摊牌窗口打开（不 finish
// ——保留实时 VM 会话的控制轨迹），供 canonical_trace_roundtrip 复用。
// ============================================================
pub(crate) struct RealHandDriver {
    pub(crate) table: Table,
    pub(crate) players: Vec<Player>,
}

impl RealHandDriver {
    /// 建桌 + 入座 + 真实洗牌 + 翻前 HandReveal 完成（盲注已发布）。
    pub(crate) fn new(table_id: u32, bankroll: u64) -> Self {
        let mut table = Table::new(table_id, "canonical-e2e".to_string(), 10000, 9, String::new());
        let players = allin_e2e::seat_players_bankroll(&mut table, 2, bankroll);
        table.mental_poker_game.encrypt_deck();
        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().expect("shuffler");
            let player = players.iter().find(|p| p.pk_hex == current).expect("seated");
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();
        allin_e2e::drive_reveal_cascade(&mut table, &players);
        Self { table, players }
    }

    /// 推进到 ShowdownReveal 窗口打开（all-in 首行动或 check/call 线）。
    /// 不调 finish_showdown——实时 VM 会话与其控制轨迹保留在桌上。
    pub(crate) fn drive_to_showdown_window(mut self) -> Table {
        let mut steps = 0;
        let mut first_action = true;
        loop {
            steps += 1;
            assert!(steps < 400, "game did not terminate");
            if self.table.reveal_token_state.is_active() {
                if self.table.reveal_token_state.phase == RevealPhase::ShowdownReveal {
                    return self.table; // 摊牌窗口打开即停（不 finish）
                }
                allin_e2e::drive_reveal_cascade(&mut self.table, &self.players);
                continue;
            }
            if self.table.summary.hand_over || self.table.round_state() == RoundState::Waiting {
                return self.table;
            }
            if self.table.turn().is_some() {
                let mut first = first_action;
                allin_e2e::act_allin_then_call(&mut self.table, &self.players, &mut first);
                first_action = first;
                continue;
            }
            return self.table;
        }
    }

    /// 推进到摊牌展示期（最后一份摊牌 token 触发的 Showdown 完成已入
    /// 控制轨迹）。不调 end_hand——实时 VM 会话保留（展示期到期前的
    /// 终态）。Game 层的 Showdown 相位在摊牌 reveal 完成时即进入，
    /// 与 VM 的 ShowdownDisplay 同步（单一状态，refresh_from_vm）。
    pub(crate) fn drive_to_showdown_display(mut self) -> Table {
        let mut steps = 0;
        let mut first_action = true;
        loop {
            steps += 1;
            assert!(steps < 400, "game did not terminate");
            if self.table.reveal_token_state.is_active() {
                if self.table.reveal_token_state.phase == RevealPhase::ShowdownReveal {
                    // 完成摊牌窗口（最后一份 token → Showdown 完成级联）。
                    allin_e2e::drive_reveal_cascade(&mut self.table, &self.players);
                    if !self.table.reveal_token_state.is_active() {
                        return self.table;
                    }
                    continue;
                }
                allin_e2e::drive_reveal_cascade(&mut self.table, &self.players);
                continue;
            }
            if self.table.summary.hand_over || self.table.round_state() == RoundState::Waiting {
                return self.table;
            }
            if self.table.turn().is_some() {
                let mut first = first_action;
                allin_e2e::act_allin_then_call(&mut self.table, &self.players, &mut first);
                first_action = first;
                continue;
            }
            if self.table.round_state() == RoundState::Showdown {
                return self.table;
            }
            return self.table;
        }
    }
}

// ===========================================================================
// D1 洗牌证明通道：真实 V2 证明经 submit_verified_shuffle 验证后的留存
//（design/table/data-gaps-onchain.md D1 验收：证明本体 + verified/tx +
// transcript challenge + 方案 b 投影，V1/V2 形状均可序列化下发）。
// ===========================================================================

/// typed Bayer-Groth V2 证明 → 客户端 wire JSON（与真实客户端提交同构）。
pub(crate) fn bg_proof_to_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> crate::pokergame::game_state::ShuffleProofJson {
    use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;
    let poker_protocol::zk_shuffle::versioned::VersionedShuffleProof::BayerGrothV2(bg) = proof
    else {
        panic!("test only builds V2 proofs");
    };
    let _ = VersionedShuffleProof::<poker_protocol::crypto::DefaultCurve>::LegacyV1; // 引用检查
    use poker_protocol::z_poker::convert::{ecpoint_to_hex, scalar_to_hex};
    use crate::pokergame::game_state::{
        BayerGrothShuffleProofEnvelopeJson, BayerGrothShuffleProofJson,
        ElGamalCiphertextJson, MultiExponentiationArgumentJson, ProductArgumentJson,
    };
    let m = &bg.multi_exponentiation;
    let p = &bg.product;
    crate::pokergame::game_state::ShuffleProofJson::BayerGrothV2(BayerGrothShuffleProofEnvelopeJson {
        version: 2,
        proof: BayerGrothShuffleProofJson {
            c_permutation_hex: ecpoint_to_hex(&bg.c_permutation),
            c_permuted_powers_hex: ecpoint_to_hex(&bg.c_permuted_powers),
            multi_exponentiation: MultiExponentiationArgumentJson {
                c_alpha_hex: ecpoint_to_hex(&m.c_alpha),
                c_beta_hex: ecpoint_to_hex(&m.c_beta),
                ciphertext_0: ElGamalCiphertextJson::from_ciphertext(&m.ciphertext_0),
                ciphertext_1: ElGamalCiphertextJson::from_ciphertext(&m.ciphertext_1),
                alpha_response_hex: m.alpha_response.iter().map(scalar_to_hex).collect(),
                commitment_response_hex: scalar_to_hex(&m.commitment_response),
                beta_hex: scalar_to_hex(&m.beta),
                beta_blinding_response_hex: scalar_to_hex(&m.beta_blinding_response),
                rerandomization_response_hex: scalar_to_hex(&m.rerandomization_response),
            },
            product: ProductArgumentJson {
                c_d_hex: ecpoint_to_hex(&p.c_d),
                c_delta_hex: ecpoint_to_hex(&p.c_delta),
                c_capital_delta_hex: ecpoint_to_hex(&p.c_capital_delta),
                a_response_hex: p.a_response.iter().map(scalar_to_hex).collect(),
                b_response_hex: p.b_response.iter().map(scalar_to_hex).collect(),
                r_response_hex: scalar_to_hex(&p.r_response),
                s_response_hex: scalar_to_hex(&p.s_response),
            },
        },
    })
}

/// typed V2 证明 → wire JSON Value（join 轮次构造用）。
fn bg_proof_to_json_value(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> serde_json::Value {
    serde_json::to_value(bg_proof_to_json(proof)).expect("v2 proof serializes")
}

#[test]
fn verified_shuffle_retains_proof_layers() {
    let table_id = 9301u32;
    let mut table = Table::new(table_id, "proof-ledger".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, 3);
    table.mental_poker_game.encrypt_deck();
    table.start_hand();
    assert!(table.shuffle_state.is_active(), "shuffle phase active");
    let hand_id = table.current_hand_id;
    assert!(hand_id > 0, "hand id assigned at hand start");

    let mut rounds = 0;
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("current shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("current shuffler seated");
        // 与真实客户端一致的服务端验证路径（BG V2 Fiat-Shamir 全量验证 +
        // D1 留存），而非测试直连 mental_poker_game.submit_shuffle。
        let deck = table.mental_poker_game.deck_encrypted.clone();
        let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
        let mut transcript = PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
        );
        let round =
            ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
                .expect("random shuffle round");
        let proof_json = bg_proof_to_json(&round.proof);
        let output_json: Vec<ElGamalCiphertextJson> = round
            .output_cards
            .iter()
            .map(ElGamalCiphertextJson::from_ciphertext)
            .collect();
        table
            .submit_verified_shuffle(&player.pk_hex, output_json, proof_json)
            .expect("verified shuffle with retention");
        // socket 层同语义：提交成功后推进轮转指针（否则 current_shuffler
        // 不变，重复提交同一玩家）。
        table.advance_turn_pointer_only();
        rounds += 1;
    }
    assert_eq!(rounds, 3, "every player shuffles once");

    let entry = table.proof_ledger.get(hand_id).expect("hand proof entry");
    assert_eq!(entry.layers.len(), 3);
    assert_eq!(entry.table_id, table_id);
    assert_eq!(entry.deck_size, 52);
    assert!(!entry.aggregate_pk.is_empty());
    for (i, layer) in entry.layers.iter().enumerate() {
        assert!(layer.verified, "layer {} verified", i);
        assert_eq!(layer.proof_version, 2);
        assert_eq!(layer.round as usize, i + 1, "轮次 1 起单调");
        assert!(
            layer.global_challenge.is_some(),
            "V2 层留存 transcript challenge"
        );
        assert!(layer.display.derived, "方案 b 投影标注派生");
        assert!(layer.display.sum_c1_commit.is_some(), "Σc1 派生摘要");
        assert!(layer.display.sum_c2_commit.is_some(), "Σc2 派生摘要");
        assert!(layer.display.nonce.is_none(), "V2 无 nonce 字段");
        assert!((1..=3).contains(&layer.seat), "seat 在座（洗牌顺序非座位序）");
        assert!(!layer.player_name.is_empty());
    }
    // 三层分属三个不同座位（每人恰好洗一次）
    let mut seats: Vec<u32> = entry.layers.iter().map(|l| l.seat).collect();
    seats.sort();
    seats.dedup();
    assert_eq!(seats, vec![1, 2, 3], "三个座位各一层");

    // REST 通道响应形状：serde camelCase 可序列化，证明本体 V2 原样回显。
    let json = serde_json::to_value(entry).expect("entry serializes");
    let layers = json.get("layers").and_then(|v| v.as_array()).expect("layers array");
    assert_eq!(layers.len(), 3);
    assert!(layers[0].get("globalChallenge").is_some());
    assert_eq!(
        layers[0].get("proofVersion").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert!(layers[0].get("proof").unwrap().get("version").is_some());
    assert!(json.get("aggregatePk").is_some());
}

/// join 洗牌层（开局前 Waiting 阶段，真实 join_player_and_shuffle 路径）
/// 进 pending 桶、开局收编进本手。
#[test]
fn join_shuffle_layer_pending_then_adopted() {
    use crate::pokergame::player::Player;
    let table_id = 9302u32;
    let mut table = Table::new(table_id, "join-ledger".to_string(), 10000, 9, String::new());
    seat_players(&mut table, 2);
    table.mental_poker_game.encrypt_deck();
    // Waiting 阶段（未 start_hand）：current_hand_id 仍为 0 → pending 桶。
    assert_eq!(table.current_hand_id, 0);

    // 第三个玩家走真实 join 路径入座（remask + shuffle 两步证明验证）。
    let joiner = ClientPlayer::new_with_wallet_address("0x9302a");
    let deck = table.mental_poker_game.deck_encrypted.clone();
    let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
    let round = joiner
        .join_game_and_shuffle(&deck, &agg_pk, crate::pokergame::random_user_permute())
        .expect("simulated user join shuffle");
    let ms = &round.mask_and_shuffle_round;
    let ec_hex = |p: &poker_protocol::crypto::EcPoint| {
        poker_protocol::z_poker::convert::ecpoint_to_hex(p)
    };
    let sc_hex = |s: &poker_protocol::crypto::Scalar| {
        poker_protocol::z_poker::convert::scalar_to_hex(s)
    };
    let ct_json = |ct: &poker_protocol::crypto::ElGamalCiphertext| {
        serde_json::json!({"c1_hex": ec_hex(&ct.c1), "c2_hex": ec_hex(&ct.c2)})
    };
    let round_json: crate::pokergame::game_state::MaskAndShuffleRoundJson =
        serde_json::from_value(serde_json::json!({
            "mask_cards": ms.mask_cards.iter().map(ct_json).collect::<Vec<_>>(),
            "output_cards": ms.output_cards.iter().map(ct_json).collect::<Vec<_>>(),
            "remask_proof": {
                "per_card_commitments_hex": ms.remask_proof.per_card_commitments.iter().map(ec_hex).collect::<Vec<_>>(),
                "commitment_pk_hex": ec_hex(&ms.remask_proof.commitment_pk),
                "response_hex": sc_hex(&ms.remask_proof.response),
                "nonce_hex": sc_hex(&ms.remask_proof.nonce),
            },
            "shuffle_proof": bg_proof_to_json_value(&ms.proof),
        }))
        .expect("mask and shuffle json");
    let pk_proof_json: crate::pokergame::game_state::PkProofJson =
        serde_json::from_value(serde_json::json!({
            "commitment_hex": ec_hex(&round.pk_ownership_proof.commitment),
            "response_hex": sc_hex(&round.pk_ownership_proof.response),
        }))
        .expect("pk proof json");
    let player = Player {
        socket_id: "test".to_string(),
        id: "joiner".to_string(),
        name: "joiner".to_string(),
        bankroll: 100000,
        wallet_address: WalletAddress("0x9302a".to_string()),
    };
    table
        .join_player_and_shuffle(
            player,
            joiner.pk,
            pk_proof_json,
            Some(round_json),
            3,
            100000,
        )
        .expect("join and shuffle in waiting phase");

    // pending 桶有一条层；开局后第一条 in-hand 层触发收编。
    assert!(
        table.proof_ledger.get(0).is_some_and(|e| e.layers.len() == 1),
        "waiting 层进 pending 桶"
    );

    table.start_hand();
    let hand_id = table.current_hand_id;
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("current shuffler set");
        let deck = table.mental_poker_game.deck_encrypted.clone();
        let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
        let mut transcript = PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
        );
        let round =
            ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
                .expect("random shuffle round");
        let proof_json = bg_proof_to_json(&round.proof);
        let output_json: Vec<ElGamalCiphertextJson> = round
            .output_cards
            .iter()
            .map(ElGamalCiphertextJson::from_ciphertext)
            .collect();
        // 服务端模拟视角：证明构造不依赖洗牌者身份，直接对 current 提交。
        table
            .submit_verified_shuffle(&current, output_json, proof_json)
            .expect("verified shuffle");
        table.advance_turn_pointer_only();
    }
    let entry = table.proof_ledger.get(hand_id).expect("hand entry");
    assert_eq!(
        entry.layers.len(),
        4,
        "pending join 层（收编为首层）+ 开局 3 层（含 joiner 的开局洗牌）= 4"
    );
    assert!(
        table.proof_ledger.get(0).is_none(),
        "pending 桶清空"
    );
    // 收编的首层就是 join 层（座位 3 / joiner）
    assert_eq!(entry.layers[0].seat, 3);
    assert_eq!(entry.layers[0].player_name, "joiner");
}
