//! Starknet 接入端到端测试（cargo test -p texas e2e_starknet）。
//!
//! 全链路结算对拍基线（双状态机历史方案见 docs/archive/MIRROR_UNIFICATION_PLAN.md）：
//! 1. 以**游戏层真实流程**构造牌局——两个客户端用 zgame poker_protocol
//!    （与前端 wasm 同源代码）执行 join_game_and_shuffle，deck 链由客户端洗牌驱动；
//! 2. 游戏层发完底牌后（deck 终局），把 deck **原样注入** mirror VM
//!    （`begin_reveal_hand`），断言 deck 逐字节一致；
//! 3. 客户端对游戏层密文生成的 reveal token（含摊牌阶段对**完整密文**的证明）
//!    必须被 VM 的 reveal 窗口逐个接受（DealHole / Board / ShowdownOwner）；
//! 4. 下注推进到 river（board == 5）→ 结算（derive_settlement_plan）→
//!    证明（Orchestrator + outer aggregate）→ Starknet calldata
//!    （register_aggregate / settle_hand）。
//!
//! 洗牌在 VM 中不再重放（deck 同源注入，#20 Phase 2），因此证明链由
//! reveal-token 任务构成——这正是玩家实际参与的那副牌。

use poker_protocol::crypto::DefaultCurve;
use poker_protocol::crypto::curve::{Curve, CurveScalar};
use rand::rngs::OsRng;

use super::vm_session::VmTable;
use poker_protocol::z_poker::protocol::{ClientPlayer, MentalPokerGame};

type ZgCt = poker_protocol::crypto::ElGamalCiphertext;

/// 模拟游戏层两名客户端 join_game_and_shuffle 入座（服务器验证语义与
/// `Table::join_player_and_shuffle` 一致：proof verify → register → deck := output）。
fn game_layer_join(game: &mut MentalPokerGame, player: &ClientPlayer) {
    let agg_prev = game.key_manager.get_aggregated_pk();
    let round = player
        .join_game_and_shuffle(
            &game.deck_encrypted,
            &agg_prev,
            crate::pokergame::random_user_permute(),
        )
        .expect("simulated user join shuffle");
    let ms = &round.mask_and_shuffle_round;
    // 服务器侧验证（与 join_player_and_shuffle 相同的两步证明校验）
    let mut transcript =
        poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::MASK_SHUFFLE_V2_POSEIDON,
        );
    let input_cards: Vec<ZgCt> = game.deck_encrypted.clone();
    assert!(
        ms.remask_proof
            .verify(&input_cards, &ms.mask_cards, &player.pk, &mut transcript,),
        "remask proof must verify"
    );
    let share_pk = agg_prev + player.pk;
    assert!(
        ms.proof
            .verify(&ms.mask_cards, &ms.output_cards, &share_pk, &mut transcript,)
            .is_ok(),
        "join shuffle proof must verify"
    );
    game.register_player(hex_pk(&player.pk), player.pk, round.pk_ownership_proof);
    game.deck_encrypted = ms.output_cards.clone();
}

/// 完整链路测试：游戏层 join×2 → 发底牌 → deck 注入 mirror →
/// reveal ×(DealHole/Board/Showdown) → 下注 → 结算 → calldata。
/// 牌力完全平分（awards==total_bets）时换随机密钥重打，最多 20 次。
#[test]
#[ignore = "requires live STARKNET_RPC_URL (local devnet); run in the full gate or manually"]
fn e2e_starknet_buyin_play_settle_calldata() {
    // CI 全量门禁带 --include-ignored 也会执行本测试：无 RPC 时早退跳过，
    // 本地起 devnet 并设置 STARKNET_RPC_URL 后才真正运行。
    if std::env::var("STARKNET_RPC_URL").is_err() {
        eprintln!("STARKNET_RPC_URL not set — skipped (no devnet)");
        return;
    }
    for attempt in 0..20 {
        match play_full_hand() {
            Ok(()) => {
                eprintln!("[attempt {attempt}] full hand settled + calldata OK");
                return;
            }
            Err(e) if e.contains("split pot") => {
                eprintln!("[attempt {attempt}] split pot, retrying");
            }
            Err(e) => panic!("hand play failed: {e}"),
        }
    }
    panic!("all 20 attempts produced split pots");
}

fn play_full_hand() -> Result<(), String> {
    let (_mirror, _settlement, _dual) = play_full_hand_artifacts()?;
    Ok(())
}

/// 全链路构建（游戏层真实流程 → 证明 → dapv calldata 对拍），返回中间产物
/// 供链上冒烟（sepolia_settle_smoke）复用。
fn play_full_hand_artifacts() -> Result<
    (
        VmTable,
        super::submit::HandSettlement,
        super::dual_settle::DualSettlement,
    ),
    String,
> {
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];

    // 客户端（真实 scalar 密钥，与 wasm ClientPlayer 同一代码）。
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let client1 = ClientPlayer {
        sk: sk1.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk1,
    };
    let client2 = ClientPlayer {
        sk: sk2.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk2,
    };

    // ---- 游戏层：两名客户端先后 join_game_and_shuffle（deck 由客户端驱动）----
    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });
    game_layer_join(&mut game, &client1);
    game_layer_join(&mut game, &client2);

    // ---- 游戏层发底牌（升序座位 ×2，对齐 deal_preflop 的 VM 规范顺序）----
    let pk_hex1 = hex_pk(&client1.pk);
    let pk_hex2 = hex_pk(&client2.pk);
    for _ in 0..2 {
        game.deal_to_player(&pk_hex1, 1)
            .map_err(|e| format!("deal p1: {e:?}"))?;
        game.deal_to_player(&pk_hex2, 1)
            .map_err(|e| format!("deal p2: {e:?}"))?;
    }
    // 此刻 deck 终局（后续 street 不再改写整副 deck）
    let game_deck: Vec<ZgCt> = game.deck_encrypted.clone();

    // ---- 结算构建（#20 Phase 2 现行架构）：VmTable 是 settle 时
    // 一次性重建器（非常驻 VM/第二本账）——从本手证明日志注入 deck，
    // 产出 ProveTask 链 + pre-payout 快照，供 dapv calldata 对拍 ----
    use poker_l1::contracts::texas_poker::utils::create_pk_ownership_proof;
    let zpk1 =
        super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client1.pk))
            .unwrap();
    let zpk2 =
        super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client2.pk))
            .unwrap();
    let proof1 =
        create_pk_ownership_proof(&sk1, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
            .expect("proof p1");
    let proof2 =
        create_pk_ownership_proof(&sk2, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
            .expect("proof p2");
    let plan = vec![
        (p1, 1000u64, zpk1, None, proof1),
        (p2, 1000u64, zpk2, None, proof2),
    ];
    let mut mirror = VmTable::new(1, creator, 4, 10, 20, creator);
    mirror
        .begin_reveal_hand(
            super::vm_session::conv::ciphertexts(&game_deck).expect("deck bridge"),
            &plan,
            0,
            poker_l1::contracts::texas_poker::types::NO_SEAT,
            7,
        )
        .map_err(|e| format!("begin_reveal_hand: {e}"))?;

    // 对拍断言：重建器 deck 与游戏层 deck 逐字节一致。
    assert_eq!(
        mirror.deck(),
        super::vm_session::conv::ciphertexts(&game_deck).unwrap(),
        "mirror deck must byte-match the game deck after injection"
    );

    // ---- reveal / betting 交替推进到 river ----
    // 客户端语义：每个玩家对"待揭示密文"生成 token = sk·c1 + Schnorr 证明
    // （证明绑定完整密文——包括摊牌阶段，与真实客户端一致）。
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;
    use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript as PfT;

    let clients: [&ClientPlayer; 2] = [&client1, &client2];
    for _step in 0..64 {
        if mirror.table.reveal_token_state().is_some() {
            // pending 座位中编号最小者提交其全部 pending assignments（canonical 顺序）
            let reveal_state = mirror.table.reveal_token_state().unwrap();
            let min_pending_seat = reveal_state
                .assignments
                .iter()
                .filter(|a| !a.is_ready())
                .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
                .min();
            let Some(seat) = min_pending_seat else { break };
            let client = clients[seat as usize];
            // canonical 目标密文（showdown 为 ledger 保存的完整密文）
            let targets = mirror
                .pending_reveal_ciphertexts(seat)
                .map_err(|e| format!("pending targets: {e}"))?;
            let mut tokens = Vec::new();
            let mut proofs = Vec::new();
            for target in &targets {
                let ct = super::vm_session::conv::ciphertexts(std::slice::from_ref(
                    &poker_protocol::crypto::ElGamalCiphertext {
                        c1: target.c1,
                        c2: target.c2,
                    },
                ))
                .expect("ct bridge")
                .remove(0);
                let token = ct.gen_reveal_token(&client.sk);
                let proof = ZgRevealProof::prove(
                    &client.sk,
                    &client.pk,
                    &ct,
                    &token,
                    &mut OsRng,
                    &mut PfT::new_domain(
                        poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                    ),
                );
                tokens.push(
                    super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(
                        token,
                    ))
                    .unwrap(),
                );
                proofs.push(super::vm_session::conv::reveal_token_proof(&proof).unwrap());
            }
            mirror
                .submit_reveal_tokens(seat, tokens, proofs)
                .map_err(|e| format!("seat {seat} reveal submit failed: {e}"))?;
            continue;
        }
        if let Some(actor) = mirror.table.current_turn_option() {
            let other = 1u8 - actor;
            let facing_bet = mirror.table.seats[actor as usize].total_bet()
                < mirror.table.seats[other as usize].total_bet();
            if facing_bet {
                mirror.call(actor).map_err(|e| format!("call: {e}"))?;
            } else {
                mirror.check(actor).map_err(|e| format!("check: {e}"))?;
            }
            continue;
        }
        // 既无 reveal 也无下注轮：若已到河牌则结束
        if mirror.table.community_cards.to_vec().len() == 5 {
            break;
        }
        panic!(
            "stuck: no reveal, no betting turn, board {} cards",
            mirror.table.community_cards.to_vec().len()
        );
    }

    assert_eq!(
        mirror.table.community_cards.to_vec().len(),
        5,
        "board should reach river"
    );
    assert!(
        mirror.has_provable_activity(),
        "reveal tasks must form the provable activity of this hand"
    );

    // 平分检测（须在派奖前：派奖后 board 复位无法 derive）
    let plan_check =
        poker_l1::contracts::texas_poker::settlement::derive_settlement_plan(&mirror.table)
            .map_err(|e| format!("plan: {e}"))?;
    let all_zero_delta = mirror.table.seats.iter().enumerate().all(|(i, s)| {
        plan_check.awards.get(i).copied().unwrap_or(0) as i128 == s.total_bet() as i128
    });
    if all_zero_delta {
        return Err("split pot".into());
    }

    // 派奖前打快照（board/pot/total_bet 完整），供 SettleHandCalldata 使用
    mirror.mark_pre_settlement();

    // showdown 展示期后由 advance_deadline 驱动派奖归一化（对齐 zgame tick）
    std::thread::sleep(std::time::Duration::from_secs(4));
    mirror
        .advance_deadline()
        .map_err(|e| format!("advance: {e}"))?;

    // ---- 结算：分池 + 证明 + calldata ----
    // #18 Phase B：动作日志哈希取一个确定样例（e2e 无 game 层动作日志）。
    let action_log_digest = starknet_crypto::Felt::from(0xA11CE_u64);
    let settlement =
        super::submit::settle_hand(&mirror, Some(creator), &[], action_log_digest, &[])
            .map_err(|e| format!("settlement: {e}"))?;

    assert_eq!(
        settlement.hand_id, 7,
        "hand_id must come from the injected counter"
    );
    assert!(!settlement.register_calldata.is_empty());
    assert!(!settlement.settle_calldata.is_empty());
    assert!(settlement.settle_calldata.len() >= 6);
    assert_ne!(settlement.aggregate_digest, [0u8; 32]);

    // ---- Hand-batch（PokerDualSettlement）：hand_binding + hand-bound 认可批次 ----
    // 认可提交通道已删除：测试在 host 侧生成密钥并铸造（将来 ownership 桶
    // 重接动作签名），直接走构建路径。
    let binding = super::dual_settle::prepare_handbatch_binding(&mirror, &settlement)?;
    let endorsements: Vec<super::dual_settle::Endorsement> = settlement
        .players_remapped
        .iter()
        .map(|_p| {
            let sk = <super::dual_settle::Sc as CurveScalar>::random(&mut rand::rngs::OsRng);
            let pk = <poker_protocol::crypto::curve::StarkCurve as Curve>::base_g() * sk;
            super::dual_settle::mint_endorsement(&sk, &pk, &binding.hand_id_bytes)
        })
        .collect();
    let dual =
        super::dual_settle::build_dual_settlement_with(&mirror, &settlement, &|_hb, _players| {
            Ok(endorsements.clone())
        })
        .map_err(|e| format!("dapv build: {e}"))?;
    assert_ne!(dual.hand_binding, starknet_crypto::Felt::ZERO);
    assert_eq!(
        dual.batch_words.len(),
        5 + 5 * settlement.players_remapped.len()
    );
    // #18 Phase B：register 7 felt（+动作日志承诺）、settle 前缀 +1 标量。
    assert_eq!(dual.register_calldata.len(), 7);
    assert_eq!(
        dual.register_calldata[3], action_log_digest,
        "register pins the action log commitment"
    );
    let expect_len = 1
        + 1
        + 32
        + 1
        + 1
        + 1
        + settlement.players_remapped.len()
        + 1
        + settlement.deltas.len()
        + 1
        + dual.batch_words.len();
    assert_eq!(dual.settle_calldata.len(), expect_len);
    assert_ne!(dual.proved.p_batch_commitment, starknet_crypto::Felt::ZERO);
    assert_eq!(dual.proved.register_calldata.len(), 9);
    // proved settle calldata 由 submit_dual_settlement 在提交期按
    // proved_private 公开段填充（6684d4ef 起），构建期刻意留空。
    assert!(dual.proved.settle_calldata.is_empty());

    // 宿主折叠 parity（链上 fold_and_check 的同构镜像）
    let hb_bytes = dual.hand_binding.to_bytes_be();
    let terms = super::dual_settle::parse_batch_terms(&hb_bytes, &dual.batch_words)
        .expect("parse honest batch");
    assert!(
        super::dual_settle::host_fold_is_identity(&hb_bytes, &terms),
        "honest batch must fold to L == O"
    );
    let mut wrong = hb_bytes;
    wrong[0] ^= 1;
    let wrong_terms = super::dual_settle::parse_batch_terms(&wrong, &dual.batch_words)
        .expect("parse under replayed domain");
    assert!(
        !super::dual_settle::host_fold_is_identity(&wrong, &wrong_terms),
        "cross-hand replay must fold to non-zero L"
    );
    Ok((mirror, settlement, dual))
}

fn hex_pk(pk: &poker_protocol::crypto::EcPoint) -> String {
    poker_protocol::z_poker::convert::ecpoint_to_hex(pk)
}

/// 注入前缀对拍：join×2 → 发底牌 → deck 注入 → 翻牌前 hole reveal 全部通过 →
/// 下注轮开启；全程断言 mirror deck 与游戏层 deck 逐字节一致。
#[test]
fn e2e_starknet_prefix_join_inject_reveal_betting() {
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let client1 = ClientPlayer {
        sk: sk1.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk1,
    };
    let client2 = ClientPlayer {
        sk: sk2.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk2,
    };

    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });
    game_layer_join(&mut game, &client1);
    game_layer_join(&mut game, &client2);
    let pk_hex1 = hex_pk(&client1.pk);
    let pk_hex2 = hex_pk(&client2.pk);
    for _ in 0..2 {
        game.deal_to_player(&pk_hex1, 1).expect("deal p1");
        game.deal_to_player(&pk_hex2, 1).expect("deal p2");
    }
    let game_deck: Vec<ZgCt> = game.deck_encrypted.clone();

    use poker_l1::contracts::texas_poker::utils::create_pk_ownership_proof;
    let zpk1 =
        super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client1.pk))
            .unwrap();
    let zpk2 =
        super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client2.pk))
            .unwrap();
    let proof1 =
        create_pk_ownership_proof(&sk1, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
            .unwrap();
    let proof2 =
        create_pk_ownership_proof(&sk2, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
            .unwrap();
    let plan = vec![
        (p1, 1000u64, zpk1, None, proof1),
        (p2, 1000u64, zpk2, None, proof2),
    ];
    let mut mirror = VmTable::new(1, creator, 4, 10, 20, creator);
    mirror
        .begin_reveal_hand(
            super::vm_session::conv::ciphertexts(&game_deck).unwrap(),
            &plan,
            0,
            poker_l1::contracts::texas_poker::types::NO_SEAT,
            1,
        )
        .expect("inject");

    assert_eq!(
        mirror.deck(),
        super::vm_session::conv::ciphertexts(&game_deck).unwrap(),
        "deck parity after injection"
    );

    // hole reveal ×2（客户端 token 基于游戏层密文生成）
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;
    use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript as PfT;
    let clients: [&ClientPlayer; 2] = [&client1, &client2];
    loop {
        let Some(rs) = mirror.table.reveal_token_state() else {
            break;
        };
        let Some(seat) = rs
            .assignments
            .iter()
            .filter(|a| !a.is_ready())
            .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
            .min()
        else {
            break;
        };
        let client = clients[seat as usize];
        let targets = mirror.pending_reveal_ciphertexts(seat).expect("targets");
        let mut tokens = Vec::new();
        let mut proofs = Vec::new();
        for target in &targets {
            let ct = poker_protocol::crypto::ElGamalCiphertext {
                c1: target.c1,
                c2: target.c2,
            };
            let token = ct.gen_reveal_token(&client.sk);
            tokens.push(
                super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(token))
                    .unwrap(),
            );
            proofs.push(
                super::vm_session::conv::reveal_token_proof(&ZgRevealProof::prove(
                    &client.sk,
                    &client.pk,
                    &ct,
                    &token,
                    &mut OsRng,
                    &mut PfT::new_domain(
                        poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                    ),
                ))
                .unwrap(),
            );
        }
        mirror
            .submit_reveal_tokens(seat, tokens, proofs)
            .expect("hole reveal");
    }
    assert!(
        mirror.table.current_turn_option().is_some(),
        "betting round should start"
    );
}

// ============================================================
// 方案A 实况对拍：走真实 Table 路径（join_player_and_shuffle →
// start_shuffle → mirror_begin_reveal），断言游戏层 reveal
// assignment 密文与 mirror VM pending 目标逐字节一致。
// 复现线上 "reveal set does not cover vm assignments byte-wise"。
// ============================================================
#[tokio::test]
#[ignore = "requires live STARKNET_RPC_URL (local devnet); run in the full gate or manually"]
async fn live_flow_assignments_match_mirror_targets() {
    // CI 全量门禁带 --run-ignored all 也会执行本测试；无 devnet 时早退跳过
    // （本测试曾无守卫地挂在 mirror 对拍 await 上，拖死整个门禁）。
    if std::env::var("STARKNET_RPC_URL").is_err() {
        eprintln!("STARKNET_RPC_URL not set — skipped (no devnet)");
        return;
    }
    use crate::config::Config;
    use crate::models::Database;
    use crate::pokergame::game_state::{
        ElGamalCiphertextJson, MaskAndShuffleRoundJson, PkProofJson, ShuffleProofJson,
    };
    use crate::pokergame::player::{GamePkHex, Player, WalletAddress};
    use crate::pokergame::table::Table;
    use crate::socket::SocketState;

    fn parse_proof_json(v: &serde_json::Value) -> Result<ShuffleProofJson, String> {
        serde_json::from_value(v.clone()).map_err(|e| e.to_string())
    }

    fn ec_hex(p: &poker_protocol::crypto::EcPoint) -> String {
        poker_protocol::z_poker::convert::ecpoint_to_hex(p)
    }
    fn sc_hex(s: &poker_protocol::crypto::Scalar) -> String {
        poker_protocol::z_poker::convert::scalar_to_hex(s)
    }
    fn shuffle_proof_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> serde_json::Value {
        use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;
        match proof {
            VersionedShuffleProof::BayerGrothV2(p) => {
                let m = &p.multi_exponentiation;
                let pr = &p.product;
                serde_json::json!({
                    "version": 2,
                    "proof": {
                        "c_permutation_hex": ec_hex(&p.c_permutation),
                        "c_permuted_powers_hex": ec_hex(&p.c_permuted_powers),
                        "multi_exponentiation": {
                            "c_alpha_hex": ec_hex(&m.c_alpha),
                            "c_beta_hex": ec_hex(&m.c_beta),
                            "ciphertext_0": {"c1_hex": ec_hex(&m.ciphertext_0.c1), "c2_hex": ec_hex(&m.ciphertext_0.c2)},
                            "ciphertext_1": {"c1_hex": ec_hex(&m.ciphertext_1.c1), "c2_hex": ec_hex(&m.ciphertext_1.c2)},
                            "alpha_response_hex": m.alpha_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "commitment_response_hex": sc_hex(&m.commitment_response),
                            "beta_hex": sc_hex(&m.beta),
                            "beta_blinding_response_hex": sc_hex(&m.beta_blinding_response),
                            "rerandomization_response_hex": sc_hex(&m.rerandomization_response),
                        },
                        "product": {
                            "c_d_hex": ec_hex(&pr.c_d),
                            "c_delta_hex": ec_hex(&pr.c_delta),
                            "c_capital_delta_hex": ec_hex(&pr.c_capital_delta),
                            "a_response_hex": pr.a_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "b_response_hex": pr.b_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "r_response_hex": sc_hex(&pr.r_response),
                            "s_response_hex": sc_hex(&pr.s_response),
                        },
                    }
                })
            }
            VersionedShuffleProof::LegacyV1(_) => serde_json::Value::Null,
        }
    }
    fn join_payload(
        player: &ClientPlayer,
        deck: &[poker_protocol::crypto::ElGamalCiphertext],
        agg_pk: &poker_protocol::crypto::EcPoint,
    ) -> (PkProofJson, MaskAndShuffleRoundJson, String) {
        use serde_json::json;
        let round = player
            .join_game_and_shuffle(deck, agg_pk, crate::pokergame::random_user_permute())
            .expect("simulated user join shuffle");
        let ms = &round.mask_and_shuffle_round;
        let ct_json = |ct: &poker_protocol::crypto::ElGamalCiphertext| json!({"c1_hex": ec_hex(&ct.c1), "c2_hex": ec_hex(&ct.c2)});
        let ct_vec_json = |cts: &[poker_protocol::crypto::ElGamalCiphertext]| {
            serde_json::Value::Array(cts.iter().map(ct_json).collect())
        };
        let mask_and_shuffle: MaskAndShuffleRoundJson = serde_json::from_value(json!({
            "mask_cards": ct_vec_json(&ms.mask_cards),
            "output_cards": ct_vec_json(&ms.output_cards),
            "remask_proof": {
                "per_card_commitments_hex": ms.remask_proof.per_card_commitments.iter().map(ec_hex).collect::<Vec<_>>(),
                "commitment_pk_hex": ec_hex(&ms.remask_proof.commitment_pk),
                "response_hex": sc_hex(&ms.remask_proof.response),
                "nonce_hex": sc_hex(&ms.remask_proof.nonce),
            },
            "shuffle_proof": shuffle_proof_json(&ms.proof),
        })).expect("mask and shuffle json");
        let pk_proof: PkProofJson = serde_json::from_value(json!({
            "commitment_hex": ec_hex(&round.pk_ownership_proof.commitment),
            "response_hex": sc_hex(&round.pk_ownership_proof.response),
        }))
        .expect("pk proof json");
        (pk_proof, mask_and_shuffle, ec_hex(&player.pk))
    }

    // Rust 2024 下 set_var 是 unsafe；测试进程独占环境，直接包 unsafe
    unsafe { std::env::set_var("JWT_SECRET", "test-secret") };
    let state = std::sync::Arc::new(SocketState::new(
        Database::new(),
        std::collections::HashMap::new(),
        Config::from_env(),
    ));
    {
        let mut gs = state.state.write().await;
        gs.tables.insert(
            1,
            Table::new(1, "Table 1".to_string(), 10000, 9, String::new()),
        );
    }

    // 与线上一致：bot 先入座 seat 2，浏览器用户后入座 seat 1
    let wallets = [
        "0xba7f00d",
        "0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782",
    ];
    let seat_ids = [2u32, 1u32];
    let mut pks = Vec::new();
    for (i, wallet) in wallets.iter().enumerate() {
        let player = ClientPlayer::new_with_wallet_address(wallet);
        let (pk_proof, round, pk_hex) = {
            let gs = state.state.read().await;
            let table = gs.tables.get(&1).unwrap();
            let deck = table.mental_poker_game.deck_encrypted.clone();
            let agg = poker_protocol::crypto::EcPoint::from(
                table.mental_poker_game.key_manager.get_aggregated_pk(),
            );
            join_payload(&player, &deck, &agg)
        };
        let p = Player {
            socket_id: format!("sock-{i}"),
            id: format!("wallet:{wallet}"),
            name: format!("p{i}"),
            bankroll: 0,
            wallet_address: WalletAddress(wallet.to_string()),
        };
        let res = state
            .join_player_and_shuffle(
                1,
                p,
                player.pk.clone(),
                pk_proof,
                Some(round),
                seat_ids[i],
                1000,
            )
            .await;
        assert!(res.is_ok(), "join {i} failed: {res:?}");
        pks.push((pk_hex, player));
    }

    // 开局（对齐 game_loop：ready 倒计时后 start_shuffle）
    {
        let mut gs = state.state.write().await;
        let table = gs.tables.get_mut(&1).unwrap();
        let _ = table.start_shuffle();
    }

    // 新开局语义（2026-09-03）：start_shuffle 无条件重建 (G, m+agg) 基线、
    // 清空 completed、全员 pending —— 每人再提交一次纯 shuffle（对 agg，
    // 明文保持）后洗牌完成、进入发牌 + HandReveal。
    {
        let mut gs = state.state.write().await;
        let table = gs.tables.get_mut(&1).unwrap();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table
                .shuffle_state
                .current_player_pk
                .clone()
                .expect("current shuffler set");
            let (_pk_hex, player) = pks
                .iter()
                .find(|(pk, _)| *pk == current.0)
                .expect("current shuffler seated");
            let deck = table.mental_poker_game.deck_encrypted.clone();
            let agg = poker_protocol::crypto::EcPoint::from(
                table.mental_poker_game.key_manager.get_aggregated_pk(),
            );
            let round = player
                .shuffle(&deck, &agg, crate::pokergame::random_user_permute())
                .expect("simulated user shuffle");
            let out_json: Vec<ElGamalCiphertextJson> = round
                .output_cards
                .iter()
                .map(ElGamalCiphertextJson::from_ciphertext)
                .collect();
            let proof_json = shuffle_proof_json(&round.proof);
            table
                .submit_verified_shuffle(&current, out_json, parse_proof_json(&proof_json).unwrap())
                .expect("pure shuffle must verify against agg baseline");
        }
        table.advance_shuffle();
    }

    let gs = state.state.read().await;
    let table = gs.tables.get(&1).unwrap();
    assert!(
        table.reveal_token_state.is_active(),
        "preflop reveal must be active"
    );
    let assignments = table.reveal_token_state.player_assignments.clone();
    assert_eq!(assignments.len(), 2, "two players get assignments");

    // #20 Phase 2：无常驻 mirror——从本手日志零命令构建（= DealHole 窗口），
    // 断言注入后 VM 的待揭目标与游戏层 assignment 逐字节同源。
    let start = table
        .hand_proof_log
        .start
        .clone()
        .expect("hand start recorded at advance_shuffle");
    let mirror = super::vm_session::bootstrap_vm_table(1, &start, 1).expect("mirror bootstrap");
    for (pk_hex, _player) in &pks {
        let key = GamePkHex::new(pk_hex.clone());
        let wallet = table.players().get(&key).unwrap().0.clone();
        let addr = VmTable::addr_from_starknet(&wallet).unwrap();
        let assignment = assignments.get(&key).expect("assignment for player");
        let seat = mirror
            .seat_index_of(addr)
            .expect("mirror seat for participant");
        let targets = mirror
            .pending_reveal_ciphertexts(seat)
            .expect("mirror reachable");
        assert_eq!(
            targets.len(),
            assignment.hand_card.len(),
            "target/assignment size mismatch"
        );
        for card in &assignment.hand_card {
            let hit = targets.iter().any(|t| t.c1 == card.c1 && t.c2 == card.c2);
            assert!(hit, "assignment card not byte-matched in mirror targets");
        }
    }
}

/// 踢出后重入对拍：join → 踢出 bot（leave_player）→ bot 重入
/// （join_game_and_shuffle）→ 发牌 → 全员 token → 断言公共牌可物化。
/// 复现"第二手起不显示"（kick+rejoin 后 deck 不变量破坏假设）。
#[test]
fn rejoin_after_kick_materializes() {
    use poker_protocol::z_poker::protocol::MentalPokerGame;

    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let c1 = ClientPlayer {
        sk: sk1.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk1,
    };
    let c2 = ClientPlayer {
        sk: sk2.clone(),
        pk: <DefaultCurve as Curve>::base_g() * &sk2,
    };

    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });
    game_layer_join(&mut game, &c1);
    game_layer_join(&mut game, &c2);

    // ---- 踢出 c2（模拟 reveal 超时 kick → leave_player）----
    let pk2 = hex_pk(&c2.pk);
    game.leave_player(&pk2).expect("leave c2");

    // ---- 模拟服务端 reset_for_next_hand（deck 重建，含 agg 预置层）----
    game.reset();

    // ---- c2 重入（重走 join_game_and_shuffle）----
    game_layer_join(&mut game, &c2);

    // ---- 发牌：底牌 + 公共牌（对齐真实手牌流程）----
    let pk1h = hex_pk(&c1.pk);
    let pk2h = hex_pk(&c2.pk);
    for _ in 0..2 {
        game.deal_to_player(&pk1h, 1).expect("deal p1");
        game.deal_to_player(&pk2h, 1).expect("deal p2");
    }
    game.deal_community_cards_encrypted(3);

    // ---- 全员对公共牌提交 token（两个玩家都交，模拟真实 reveal 完成）----
    let all_cts: Vec<_> = game
        .community_cards_encrypted
        .iter()
        .map(|c| c.encrypted_card.clone())
        .collect();
    for client in [&c1, &c2] {
        for ct in &all_cts {
            game.submit_reveal_token(
                client.generate_reveal_token(ct),
                &(if client.pk == c1.pk {
                    pk1h.clone()
                } else {
                    pk2h.clone()
                }),
            )
            .expect("community token accepted");
        }
    }
    // 物化结果：3 张公共牌必须全部解出
    let revealed = game.list_revealed_community_cards();
    if revealed.len() != 3 {
        // 诊断：残余层 = c2 − Σtokens − m，看它等于谁的公钥
        let card = &game.community_cards_encrypted[0];
        let sum_tok: poker_protocol::crypto::EcPoint = card
            .reveal_state
            .reveal_tokens
            .iter()
            .map(|t| t.reveal_token)
            .sum();
        let leftover = card.encrypted_card.c2 - sum_tok - game.deck_plaintext[4];
        let lo = poker_protocol::z_poker::convert::ecpoint_to_hex(&leftover);
        let p1 = poker_protocol::z_poker::convert::ecpoint_to_hex(&c1.pk);
        let p2 = poker_protocol::z_poker::convert::ecpoint_to_hex(&c2.pk);
        let p1s = poker_protocol::z_poker::convert::ecpoint_to_hex(&(c1.pk + c1.pk));
        let p2s = poker_protocol::z_poker::convert::ecpoint_to_hex(&(c2.pk + c2.pk));
        let agg =
            poker_protocol::z_poker::convert::ecpoint_to_hex(&game.key_manager.get_aggregated_pk());
        panic!(
            "leftover={} || pk1={} pk2={} 2pk1={} 2pk2={} agg={} players={} keyentries={}",
            &lo[..20],
            &p1[..20],
            &p2[..20],
            &p1s[..20],
            &p2s[..20],
            &agg[..20],
            game.players.len(),
            game.key_manager.player_count()
        );
    }
    assert_eq!(
        revealed.len(),
        3,
        "all 3 flop cards must materialize after rejoin"
    );
}

/// 复现 2026-09-01 线上"手牌解密失败"组合：
/// - bot 走 join_and_shuffle（即席层，入座即 remask+shuffle）
/// - 人类走 waiting 入座（仅 register，不洗牌）
/// - 开手时 start_preflop_shuffle 的 pending 只含 waiting 玩家，
///   其用 ClientPlayer::shuffle（全量 agg re_encrypt）补层
/// 断言：发牌后每张牌都能被"其余玩家 token + 本人 token"物化
/// （即客户端 decrypt_readable_card 成功）。若失败，leftover 诊断
/// 会显示残余层等于谁的公钥。
#[test]
fn e2e_mixed_join_paths_materializes() {
    let c1 = ClientPlayer::new_with_wallet_address("0xbot");
    let c2 = ClientPlayer::new_with_wallet_address("0xhuman");
    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });

    // bot 即席 join（与 join_player_and_shuffle 的 shuffle 路径一致）
    game_layer_join(&mut game, &c1);

    // human waiting 入座：仅注册（register_waiting_players 语义）
    let pk1h = hex_pk(&c1.pk);
    let pk2h = hex_pk(&c2.pk);
    game.register_player(pk2h.clone(), c2.pk, c2.generate_pk_proof());

    // 开手洗牌（修复后语义）：pending={human} 且未贡献过层 → 必须走
    // join_game_and_shuffle（remask 自身层 + shuffle），与
    // Table::submit_join_shuffle 的服务器校验完全一致。
    // 对照：用纯 ClientPlayer::shuffle（re_encrypt）会让份额失衡 →
    // 全部卡 materialize 失败（本测试修复前的失败形态）。
    let agg = game.key_manager.get_aggregated_pk();
    let curr_share_pk = agg - c2.pk;
    let join_round = c2
        .join_game_and_shuffle(
            &game.deck_encrypted,
            &curr_share_pk,
            crate::pokergame::random_user_permute(),
        )
        .expect("simulated user join shuffle");
    let ms = &join_round.mask_and_shuffle_round;
    {
        let input_cards: Vec<ZgCt> = game.deck_encrypted.clone();
        // remask + shuffle 共享 transcript（挑战链顺序敏感）
        let mut transcript =
            poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::MASK_SHUFFLE_V2_POSEIDON,
            );
        assert!(
            ms.remask_proof
                .verify(&input_cards, &ms.mask_cards, &c2.pk, &mut transcript),
            "hand-start remask proof must verify"
        );
        assert!(
            ms.proof
                .verify(&ms.mask_cards, &ms.output_cards, &agg, &mut transcript)
                .is_ok(),
            "hand-start shuffle proof must verify"
        );
    }
    game.deck_encrypted = ms.output_cards.clone();

    // 发牌：底牌 2+2 + 公共牌 3（对齐真实手牌）
    for _ in 0..2 {
        game.deal_to_player(&pk1h, 1).expect("deal p1");
        game.deal_to_player(&pk2h, 1).expect("deal p2");
    }
    game.deal_community_cards_encrypted(3);

    // 全员对全部密文提交 token（底牌×2人 + 公共牌×2人）
    let mut all_cts: Vec<ZgCt> = Vec::new();
    for pk in [&pk1h, &pk2h] {
        for card in &game
            .players
            .get(pk.as_str())
            .expect("player")
            .hand_encrypted
        {
            all_cts.push(card.encrypted_card.clone());
        }
    }
    for ct in &game.community_cards_encrypted {
        all_cts.push(ct.encrypted_card.clone());
    }
    for client in [&c1, &c2] {
        let pk = if client.pk == c1.pk { &pk1h } else { &pk2h };
        for ct in &all_cts {
            game.submit_reveal_token(client.generate_reveal_token(ct), pk)
                .expect("reveal token accepted");
        }
    }

    // 物化断言：所有底牌+公共牌必须全部解出
    let mut failed = 0;
    for (pk, _) in game.players.iter() {
        for card in &game.players.get(pk.as_str()).unwrap().hand_encrypted {
            if card.playing_card.is_none() {
                failed += 1;
            }
        }
    }
    for ct in &game.community_cards_encrypted {
        if ct.playing_card.is_none() {
            failed += 1;
        }
    }
    if failed > 0 {
        let card = &game.community_cards_encrypted[0];
        let sum_tok: poker_protocol::crypto::EcPoint = card
            .reveal_state
            .reveal_tokens
            .iter()
            .map(|t| t.reveal_token)
            .sum();
        let leftover = card.encrypted_card.c2 - sum_tok - game.deck_plaintext[4];
        let lo = poker_protocol::z_poker::convert::ecpoint_to_hex(&leftover);
        let p1 = poker_protocol::z_poker::convert::ecpoint_to_hex(&c1.pk);
        let p2 = poker_protocol::z_poker::convert::ecpoint_to_hex(&c2.pk);
        let p1s = poker_protocol::z_poker::convert::ecpoint_to_hex(&(c1.pk + c1.pk));
        let p2s = poker_protocol::z_poker::convert::ecpoint_to_hex(&(c2.pk + c2.pk));
        let agg =
            poker_protocol::z_poker::convert::ecpoint_to_hex(&game.key_manager.get_aggregated_pk());
        panic!(
            "{} cards failed to materialize: leftover={} || pk1={} pk2={} 2pk1={} 2pk2={} agg={} players={} keyentries={}",
            failed,
            &lo[..20],
            &p1[..20],
            &p2[..20],
            &p1s[..20],
            &p2s[..20],
            &agg[..20],
            game.players.len(),
            game.key_manager.player_count()
        );
    }

    // 客户端侧解密断言（decrypt_readable_card 与前端 wasm 同路径）：
    // 真实流程中 HAND_REVEAL_RESULT 携带的 readable card 已被服务端用
    // 其他玩家的 token 剥层，客户端只减自己的 token —— 这里先模拟剥层。
    for client in [&c1, &c2] {
        let pk = if client.pk == c1.pk { &pk1h } else { &pk2h };
        for card in &game.players.get(pk.as_str()).unwrap().hand_encrypted {
            let mut readable = card.encrypted_card.clone();
            for other in [&c1, &c2] {
                if other.pk == client.pk {
                    continue;
                }
                let token = other.generate_reveal_token(&card.encrypted_card);
                readable.c2 = readable.c2 - token.reveal_token;
            }
            assert!(
                client
                    .decrypt_owner_residual_carrier(&readable, game.deck_plaintext.clone())
                    .is_some(),
                "client decrypt_owner_residual_carrier must succeed"
            );
        }
    }
}

/// #22① / #34④：sepolia 真实链上 DAPV settle 冒烟 + gas 实测。
///
/// 默认跳过；`STARKNET_SEPOLIA_SMOKE=1` 时提交**真实交易**。运行前设置：
///   STARKNET_SEPOLIA_SMOKE=1
///   STARKNET_RPC_URL / STARKNET_OPERATOR_ADDRESS / STARKNET_OPERATOR_PRIVATE_KEY
///   STARKNET_DUAL_SETTLEMENT_ADDRESS / STARKNET_VAULT_ADDRESS / STARKNET_STRK_ADDRESS
/// （同 texas/.env 口径；operator 需有少量 STRK 支付 gas + 2 STRK 预充值）
/// 运行：
///   cargo test -p texas --bin texas sepolia_settle_smoke -- --ignored --nocapture
#[tokio::test]
#[ignore = "submits REAL sepolia txs; enable with STARKNET_SEPOLIA_SMOKE=1"]
async fn sepolia_settle_smoke() {
    use starknet::accounts::Account;
    use starknet::core::types::{Call, Felt};
    use starknet::core::utils::starknet_keccak;
    use starknet::providers::Provider;

    if std::env::var("STARKNET_SEPOLIA_SMOKE").as_deref() != Ok("1") {
        eprintln!("STARKNET_SEPOLIA_SMOKE != 1 — skipped (no on-chain txs)");
        return;
    }
    // CI 全量门禁带 --include-ignored 也会执行本测试：无 RPC 时早退跳过。
    if std::env::var("STARKNET_RPC_URL").is_err() {
        eprintln!("STARKNET_RPC_URL not set — skipped (no devnet)");
        return;
    }
    let rpc = std::env::var("STARKNET_RPC_URL").expect("STARKNET_RPC_URL");
    let op_addr = std::env::var("STARKNET_OPERATOR_ADDRESS").expect("STARKNET_OPERATOR_ADDRESS");
    let op_key =
        std::env::var("STARKNET_OPERATOR_PRIVATE_KEY").expect("STARKNET_OPERATOR_PRIVATE_KEY");
    let dual_addr = std::env::var("STARKNET_DUAL_SETTLEMENT_ADDRESS")
        .expect("STARKNET_DUAL_SETTLEMENT_ADDRESS");
    let vault_addr = std::env::var("STARKNET_VAULT_ADDRESS").expect("STARKNET_VAULT_ADDRESS");
    // settlement_enabled() 要求 legacy 字段非空（dapv 模式下不消费，仅门控）。
    let legacy_addr =
        std::env::var("STARKNET_SETTLEMENT_ADDRESS").unwrap_or_else(|_| dual_placeholder());

    // 1. 本地全链路构建（游戏层真实流程 → 证明 → calldata 对拍；split-pot 重试）。
    let (mirror, _s_discard, _d_discard) = {
        let mut got = None;
        for attempt in 0..20 {
            match play_full_hand_artifacts() {
                Ok(arts) => {
                    got = Some(arts);
                    break;
                }
                Err(e) if e.contains("split pot") => {
                    eprintln!("[attempt {attempt}] split pot, retrying");
                }
                Err(e) => panic!("hand play failed: {e}"),
            }
        }
        got.expect("hand artifacts")
    };

    // 2. 全部参与者重映射到 operator：链上筹码净零变动，零余额账户可结算。
    let op_felt = Felt::from_hex(&op_addr).expect("operator felt");
    let op_ff = op_felt;
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];
    let wallet_map = vec![(p1, op_ff), (p2, op_ff), (creator, op_ff)];
    let action_log_digest = starknet_crypto::Felt::from(0xA11C3Du64);
    let settlement =
        super::submit::settle_hand(&mirror, Some(creator), &wallet_map, action_log_digest, &[])
            .expect("settlement rebuild with operator remap");
    assert!(!settlement.players_remapped.is_empty());

    // 3. 初始化全局 chain（与 main.rs 同一入口；dapv/linear 模式）。
    let config = super::config::StarknetConfig {
        rpc_url: rpc.clone(),
        operator_address: op_addr.clone(),
        operator_private_key: op_key.clone(),
        vault_address: vault_addr.clone(),
        settlement_address: legacy_addr,
        dual_settlement_address: dual_addr.clone(),
        settlement_mode: "dapv".into(),
        dapv_settle_entry: "v2".into(),
        combined_program_hash: String::new(),
        combined_native_bin: String::new(),
        settle_mode: super::config::SettleMode::Linear,
        prover_url: None,
        prover_work_dir: "/tmp/zgame-prover".into(),
        snip36_prover_url: None,
        snip36_l2_gas: 0x5f5e100,
        auth_strict: false,
        treasury_address: op_addr.clone(),
        // owner 槽位未配置 = 单账户部署现状（validate 直通）。
        owner_address: String::new(),
        owner_private_key: String::new(),
        table_registry_address: String::new(),
        settlement_exit: "starknet".into(),
        gateway_base_url: String::new(),
    };
    let chain = super::init(config);
    let operator = chain.operator().await.expect("operator account");

    // 4. 预充值 operator 筹码（2 STRK = 2000 chips），规避净负 delta 顺序回退。
    let amount_lo = Felt::from(2_000_000_000_000_000_000u128);
    let amount_hi = Felt::ZERO;
    let vault_felt = Felt::from_hex(&vault_addr).expect("vault felt");
    // vault v3 的 deposit_for 拉取的是 **canonical STRK**（vault.token()）——
    // 授权必须打在规范 STRK 上（STARKNET_STRK_ADDRESS 可能仍指旧 pSTRK）。
    let canonical_strk =
        Felt::from_hex("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")
            .expect("canonical strk felt");
    let prefund = operator
        .execute_v3(vec![
            Call {
                to: canonical_strk,
                selector: starknet_keccak(b"approve"),
                calldata: vec![vault_felt, amount_lo, amount_hi],
            },
            Call {
                to: vault_felt,
                selector: starknet_keccak(b"deposit_for"),
                calldata: vec![op_felt, amount_lo, amount_hi],
            },
        ])
        .send()
        .await
        .expect("vault prefund");
    eprintln!("prefund tx = {:?}", prefund.transaction_hash);

    // 5. dapv 上链：register_hand（含 action_log 承诺）+ verify_and_settle_dapv_stark。
    let binding =
        super::dual_settle::prepare_handbatch_binding(&mirror, &settlement).expect("binding");
    let endorsements: Vec<super::dual_settle::Endorsement> = settlement
        .players_remapped
        .iter()
        .map(|_p| {
            let sk = <super::dual_settle::Sc as CurveScalar>::random(&mut OsRng);
            let pk = <poker_protocol::crypto::curve::StarkCurve as Curve>::base_g() * sk;
            super::dual_settle::mint_endorsement(&sk, &pk, &binding.hand_id_bytes)
        })
        .collect();
    let dual =
        super::dual_settle::build_dual_settlement_with(&mirror, &settlement, &|_hb, _players| {
            Ok(endorsements.clone())
        })
        .expect("dual build");
    let (register_tx, settle_tx) = super::dual_settle::submit_dual_settlement(
        &dual,
        &dual_addr,
        &settlement.players_remapped,
        &settlement.deltas,
        &[],
        // combined 入口未在此测试启用（默认 v2）；P 任务产源见
        // hooks::snip36_settle_flow 的 action_sig_materials 构造。
        &[],
    )
    .await
    .expect("on-chain dapv settle");
    eprintln!("register_tx = {register_tx}\nsettle_tx   = {settle_tx}");

    // 6. settle 回执终态 + gas 实测（#22① 验收数据）。
    use starknet::core::types::ExecutionResult;
    let settle_felt = Felt::from_hex(&settle_tx).expect("settle tx felt");
    let mut gas_line = String::from("gas: unavailable");
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        match provider_of(&rpc).get_transaction_receipt(settle_felt).await {
            Ok(receipt) => {
                let ExecutionResult::Succeeded = receipt.receipt.execution_result() else {
                    panic!(
                        "settle not successful: {:?}",
                        receipt.receipt.execution_result()
                    );
                };
                gas_line = match &receipt.receipt {
                    starknet::core::types::TransactionReceipt::Invoke(r) => {
                        format!("gas: {:?}", r.execution_resources)
                    }
                    other => format!("gas: n/a ({other:?})"),
                };
                break;
            }
            Err(_) => continue, // 尚未入块
        }
    }
    eprintln!(
        "SEPOLIA_SETTLE_SMOKE_OK hand_id={} settle_tx={settle_tx} {gas_line}",
        settlement.hand_id
    );
    assert!(
        gas_line != "gas: unavailable",
        "settle receipt not observed in 120s"
    );
}

/// 冒烟专用的独立 provider（不走全局 chain，避免 init 顺序耦合）。
fn provider_of(
    rpc: &str,
) -> starknet::providers::JsonRpcClient<starknet::providers::jsonrpc::HttpTransport> {
    starknet::providers::JsonRpcClient::new(starknet::providers::jsonrpc::HttpTransport::new(
        url::Url::parse(rpc).expect("rpc url"),
    ))
}

fn dual_placeholder() -> String {
    std::env::var("STARKNET_DUAL_SETTLEMENT_ADDRESS").unwrap_or_default()
}

// =============================================================================
// 链运行时权威 e2e（Phase 2b 目标入口 TableRuntime）
//
// 一手完整牌局**只经过链运行时门面**驱动：create/join（签名认证）→ deck
// 注入 → DealHole/Flop/Turn/River/Showdown reveal（签名提交，含确定性的
// 乱序提前提交——入口队列持有 + 冲刷消化）→ betting（签名提交）→ 派奖。
// 断言：签名防篡改/防重放、乱序命令不丢（fail-closed 收尾）、ProveTask
// 收集、结算计划派生与守恒。
// =============================================================================

mod runtime_authority_e2e {
    use super::*;
    use poker_l1::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
    use poker_l1::contracts::texas_poker::runtime::caller_id;
    use poker_l1::contracts::texas_poker::runtime::dispatch::{
        CreateTableArgs, JoinTableArgs, SeatIndexArgs, SubmitRevealTokensArgs,
    };
    use poker_l1::contracts::texas_poker::runtime::dispatch::{selectors, tx_message_hash};
    use poker_l1::contracts::texas_poker::runtime::table_runtime::{
        CallerIdentity, Submission, TableRuntime,
    };
    use poker_l1::contracts::texas_poker::state_machine::normalize_until_blocked;
    use poker_l1::contracts::texas_poker::types::{CipherDeck, SeatMask, ShuffleState};
    use poker_l1::object_model::ObjectID;
    use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript as RtPfT;

    /// 测试玩家钱包：Starknet felt hex（寻址）+ **随机会话密钥**
    /// （授权锚——P1-2 会话委托：地址派生只用于寻址，交易签名按座位
    /// 登记的会话公钥验证）。会话钥在 join 时随 JoinTableArgs 登记，
    /// 对应生产路径中 vault `set_session_tx_pk[_for]` 核验后的放行。
    struct RtWallet {
        wallet: String,
        address: [u8; 20],
        session_sk: poker_protocol::crypto::types::Scalar,
        session_pk: poker_l1::signature::TaggedPubkey,
    }

    impl RtWallet {
        fn new(seed_byte: u8) -> Self {
            use poker_protocol::crypto::curve::CurvePoint;
            let wallet = format!("0x{:064x}", (seed_byte as u64) * 0x0100_0000_0000_0001);
            let address = caller_id::wallet_to_address(&wallet).expect("test wallet parses");
            // 跨 crate 对拍：poker_l1 权威公式与 texas addr_from_starknet 同源。
            debug_assert_eq!(
                super::super::vm_session::VmTable::addr_from_starknet(&wallet),
                Some(address)
            );
            // 随机会话密钥（与钱包地址零派生关系——授权与寻址分离）。
            let session_sk =
                poker_protocol::crypto::types::hash_to_scalar(&[seed_byte, 0x5E, 0x55, 0x10, 0xCE]);
            let raw = (poker_protocol::crypto::types::base_g() * session_sk)
                .compress()
                .as_ref()
                .to_vec();
            let session_pk = poker_l1::signature::TaggedPubkey::new(
                poker_l1::signature::SignatureScheme::Stark,
                poker_l1::signature::CURRENT_VERSION,
                raw,
            )
            .expect("session pk tagged");
            Self {
                wallet,
                address,
                session_sk,
                session_pk,
            }
        }

        fn identity(&self) -> CallerIdentity {
            CallerIdentity::from_wallet(&self.wallet).expect("test wallet parses")
        }

        fn sign(&self, msg_hash: &[u8; 32]) -> Vec<u8> {
            poker_l1::signature::stark_scheme::sign(&self.session_sk, msg_hash).to_vec()
        }
    }

    fn submission(
        wallet: &RtWallet,
        block_timestamp: u64,
        selector: [u8; 32],
        args: Vec<u8>,
        nonce: u64,
    ) -> Submission {
        Submission {
            wallet: wallet.wallet.clone(),
            block_timestamp,
            selector,
            args,
            signature: vec![],
            nonce,
        }
    }

    /// VM 当前 reveal 窗口中该座位待提交的密文（canonical 顺序）——
    /// 与 VmTable::pending_reveal_ciphertexts 同语义（直接在 VM 表上计算）。
    fn pending_ciphertexts(
        table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
        seat_index: u8,
    ) -> Result<Vec<ZgCt>, String> {
        use poker_l1::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN;
        use poker_l1::contracts::texas_poker::types::RevealTarget;
        let Some(state) = table.reveal_token_state() else {
            return Err("reveal phase is NONE".into());
        };
        let mut out = Vec::new();
        for a in &state.assignments {
            if a.pending_mask & (1u16 << seat_index) != 0 {
                let ct = if table.reveal_phase() == REVEAL_PHASE_SHOWDOWN {
                    let RevealTarget::Hole {
                        seat_index: owner,
                        card_slot,
                    } = a.target
                    else {
                        return Err("showdown assignment must target hole".into());
                    };
                    table
                        .deck_state
                        .owner_readable_hole_cards
                        .get(owner, card_slot)
                        .map(|p| p.full_ciphertext)
                        .ok_or_else(|| "showdown partial ledger missing".to_string())?
                } else {
                    *table
                        .deck_state
                        .encrypted
                        .get(a.encrypted_card_index as usize)
                        .ok_or_else(|| "reveal card index out of range".to_string())?
                };
                out.push(
                    super::super::vm_session::conv::ciphertexts(std::slice::from_ref(
                        &poker_protocol::crypto::ElGamalCiphertext {
                            c1: ct.c1,
                            c2: ct.c2,
                        },
                    ))
                    .expect("ct bridge")
                    .remove(0),
                );
            }
        }
        Ok(out)
    }

    /// 签名一条提交（tx_message_hash 与 runtime 同公式——客户端契约）。
    fn sign_submission(wallet: &RtWallet, table_id: &ObjectID, sub: &Submission) -> Submission {
        let hash = tx_message_hash(
            377,
            table_id,
            &wallet.address,
            &sub.selector,
            &sub.args,
            sub.nonce,
        );
        let mut signed = sub.clone();
        signed.signature = wallet.sign(&hash);
        signed
    }

    #[test]
    fn runtime_full_hand_signed_out_of_order_e2e() {
        let creator = RtWallet::new(200);
        let w1 = RtWallet::new(201);
        let w2 = RtWallet::new(202);

        // ---- 客户端 ceremony：join_game_and_shuffle → 终局 deck ----
        let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
        let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
        let client1 = ClientPlayer {
            sk: sk1.clone(),
            pk: <DefaultCurve as Curve>::base_g() * &sk1,
        };
        let client2 = ClientPlayer {
            sk: sk2.clone(),
            pk: <DefaultCurve as Curve>::base_g() * &sk2,
        };
        let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
            num_players: 2,
            cards_per_player: 2,
            community_cards: 5,
        });
        game_layer_join(&mut game, &client1);
        game_layer_join(&mut game, &client2);
        let pk_hex1 = hex_pk(&client1.pk);
        let pk_hex2 = hex_pk(&client2.pk);
        for _ in 0..2 {
            game.deal_to_player(&pk_hex1, 1).expect("deal p1");
            game.deal_to_player(&pk_hex2, 1).expect("deal p2");
        }
        let game_deck: Vec<ZgCt> = game.deck_encrypted.clone();
        let vm_deck = super::super::vm_session::conv::ciphertexts(&game_deck).expect("deck bridge");

        // ---- 链运行时：开桌 + host 背书入座（P1-2 修复：签名通道不接受
        //     join——未入座无验签锚；join 由服务端完成 vault 登记核验后
        //     经 submit_unsigned 放行，此处直接模拟该路径）----
        let table = poker_l1::contracts::texas_poker::types::TexasPokerTable::new(
            ObjectID::new([0x5A; 20], 77),
            creator.address,
            4,
            10,
            20,
        );
        let mut rt = TableRuntime::new(table, 377);
        let mut now: u64 = 1_778_000_000_000;
        // 按账户 nonce（P1-1）：两家各自从 1 计数——全局命名空间下必碰撞。
        let mut nonces = [1u64, 1u64];
        let table_id = rt.table.id;

        rt.submit_unsigned(
            creator.identity(),
            now,
            &selectors::create_table(),
            &borsh::to_vec(&CreateTableArgs {
                max_players: 4,
                small_blind: 10,
                big_blind: 20,
                rit_mode: poker_l1::contracts::texas_poker::constants::RIT_MODE_DISABLED,
            })
            .expect("args"),
        )
        .expect("create_table");

        // 负路径 1：自洽的签名 join 必须被拒（P1-2 回归）——未入座钱包
        // 没有验签锚，任何持钥者不得为任意钱包构造冒名入座。
        let join1_args = borsh::to_vec(&JoinTableArgs {
            player: w1.address,
            buy_in: 1000,
            pk: super::super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(
                client1.pk,
            ))
            .expect("pk bridge"),
            tx_pk: w1.session_pk.clone(),
            pk_ownership_proof: poker_l1::contracts::texas_poker::utils::create_pk_ownership_proof(
                &sk1,
                &<DefaultCurve as Curve>::Scalar::random(&mut OsRng),
            )
            .expect("ownership proof"),
        })
        .expect("join args");
        let signed_join = sign_submission(
            &w1,
            &table_id,
            &submission(
                &w1,
                now,
                selectors::join_table(),
                join1_args.clone(),
                nonces[0],
            ),
        );
        let join_err = rt
            .submit_signed(signed_join)
            .expect_err("signed join must be rejected — joins are host-endorsed");
        assert!(
            format!("{join_err}").contains("no registered session tx public key"),
            "join rejection reason, got: {join_err}"
        );
        assert!(rt.pending().is_empty(), "auth failure must not enqueue");

        // 正路径：host 背书入座（vault 核验后的放行路径，P1-2(a)）。
        rt.submit_unsigned(w1.identity(), now, &selectors::join_table(), &join1_args)
            .expect("join p1 (host-endorsed after vault verification)");
        let join2_args = borsh::to_vec(&JoinTableArgs {
            player: w2.address,
            buy_in: 1000,
            pk: super::super::vm_session::conv::ec_point(&poker_protocol::crypto::types::ECPoint(
                client2.pk,
            ))
            .expect("pk bridge"),
            tx_pk: w2.session_pk.clone(),
            pk_ownership_proof: poker_l1::contracts::texas_poker::utils::create_pk_ownership_proof(
                &sk2,
                &<DefaultCurve as Curve>::Scalar::random(&mut OsRng),
            )
            .expect("ownership proof"),
        })
        .expect("join args");
        rt.submit_unsigned(w2.identity(), now, &selectors::join_table(), &join2_args)
            .expect("join p2 (host-endorsed)");

        // 负路径 2：签名被篡改必须拒绝（已入座 w1，锚存在，纯粹验签失败）。
        let tamper_msg = tx_message_hash(
            377,
            &table_id,
            &w1.address,
            &[0xAA; 32],
            &[0xBB; 4],
            nonces[0],
        );
        let mut bad = submission(&w1, now, [0xAA; 32], vec![0xBB; 4], nonces[0]);
        bad.signature = vec![0u8; 64];
        bad.signature[63] ^= 0x01;
        let _ = tamper_msg;
        assert!(
            rt.submit_signed(bad).is_err(),
            "tampered signature must be rejected"
        );
        assert!(rt.pending().is_empty(), "auth failure must not enqueue");

        // 负路径 3：跨会话钥顶替——w2 的会话钥签名冒充 w1（锚只认 w1
        // 座位登记的会话钥——身份绑定在座位登记，不在公开派生）。
        let forged_hash = tx_message_hash(
            377,
            &table_id,
            &w1.address,
            &[0xAA; 32],
            &[0xBB; 4],
            nonces[0],
        );
        let forged_sig = w2.sign(&forged_hash);
        let forged = Submission {
            wallet: w1.wallet.clone(),
            block_timestamp: now,
            selector: [0xAA; 32],
            args: vec![0xBB; 4],
            signature: forged_sig,
            nonce: nonces[0],
        };
        assert!(
            rt.submit_signed(forged).is_err(),
            "cross-session substitution must be rejected"
        );
        assert!(rt.pending().is_empty(), "auth failure must not enqueue");

        // ---- deck 注入 bootstrap（方案A：洗牌链在客户端完成）----
        {
            let t = &mut rt.table;
            for seat in t.seats.iter_mut() {
                seat.promote_waiting();
            }
            t.button = 0;
            t.rake_mode = RAKE_MODE_PERCENTAGE;
            t.rake_bps = 500;
            t.rake_cap = 1_000;
            let cards: [poker_protocol::crypto::ElGamalCiphertext; 52] =
                vm_deck.try_into().expect("52 cards");
            t.deck_state.encrypted = CipherDeck::Active(Box::new(cards));
            t.deck_state.cards_dealt = 0;
            t.deck_state.owner_readable_hole_cards.clear();
            let mut contributor_mask: SeatMask = 0;
            for idx in 0..usize::from(t.max_players) {
                if super::super::vm_session::seat_player_addr(&t.seats[idx]).is_some() {
                    contributor_mask |= 1u16 << idx;
                }
            }
            t.deck_state.contributor_mask = contributor_mask;
            t.enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0,
                    completed_mask: 0,
                },
                now,
            )
            .expect("enter shuffling");
            let mut evts = Vec::new();
            normalize_until_blocked(t, now, &mut evts).expect("normalize");
            assert!(
                t.reveal_token_state().is_some(),
                "DealHole window must open"
            );
        }

        // ---- 主循环：reveal（签名）+ betting（签名），turn 揭示**提前乱序提交** ----
        let clients = [&client1, &client2];
        let wallets = [&w1, &w2];
        let mut early_turn_submitted = false;
        // 最近一笔已提交的签名交易（结尾做重放负路径；bet/reveal 两种
        // 都会立即应用或入队——重放检查在 nonce 水位前置，两种都覆盖）。
        let mut last_applied_signed: Option<Submission> = None;
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 200, "runtime hand did not terminate");
            now += 1_000;
            rt.flush_pending();

            // 乱序容忍：flop 已揭示（board 3）、turn 窗口未开——提前提交
            // turn 牌（deck[7]）的 reveal，必须入队等待而非失败。
            if !early_turn_submitted && rt.table.community_cards.to_vec().len() == 3 {
                let turn_ct = *rt
                    .table
                    .deck_state
                    .encrypted
                    .get(7)
                    .expect("turn ciphertext");
                for (seat, client) in clients.iter().enumerate() {
                    let ct = super::super::vm_session::conv::ciphertexts(std::slice::from_ref(
                        &poker_protocol::crypto::ElGamalCiphertext {
                            c1: turn_ct.c1,
                            c2: turn_ct.c2,
                        },
                    ))
                    .expect("ct bridge")
                    .remove(0);
                    let token = ct.gen_reveal_token(&client.sk);
                    let proof =
                        poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof::prove(
                            &client.sk,
                            &client.pk,
                            &ct,
                            &token,
                            &mut OsRng,
                            &mut RtPfT::new_domain(
                                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                            ),
                        );
                    let args = borsh::to_vec(&SubmitRevealTokensArgs {
                        seat_index: seat as u8,
                        reveal_tokens: vec![
                            super::super::vm_session::conv::ec_point(
                                &poker_protocol::crypto::types::ECPoint(token),
                            )
                            .expect("token bridge"),
                        ],
                        proofs: vec![
                            super::super::vm_session::conv::reveal_token_proof(&proof)
                                .expect("proof bridge"),
                        ],
                    })
                    .expect("reveal args");
                    rt.submit_signed(sign_submission(
                        wallets[seat],
                        &table_id,
                        &submission(
                            wallets[seat],
                            now,
                            selectors::submit_player_reveal_tokens(),
                            args,
                            nonces[seat],
                        ),
                    ))
                    .expect("early turn reveal must be held, not rejected");
                    nonces[seat] += 1;
                }
                assert_eq!(
                    rt.pending().len(),
                    2,
                    "early turn reveals must sit in the queue"
                );
                early_turn_submitted = true;
                continue;
            }

            if rt.table.reveal_token_state().is_some() {
                let reveal_state = rt.table.reveal_token_state().unwrap();
                let min_pending_seat = reveal_state
                    .assignments
                    .iter()
                    .filter(|a| !a.is_ready())
                    .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
                    .min();
                let Some(seat) = min_pending_seat else {
                    rt.flush_pending();
                    if rt.table.reveal_token_state().is_none() {
                        continue;
                    }
                    break;
                };
                let client = clients[seat as usize];
                let targets = pending_ciphertexts(&rt.table, seat).expect("pending targets");
                let mut tokens = Vec::new();
                let mut proofs = Vec::new();
                for ct in &targets {
                    let token = ct.gen_reveal_token(&client.sk);
                    let proof =
                        poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof::prove(
                            &client.sk,
                            &client.pk,
                            ct,
                            &token,
                            &mut OsRng,
                            &mut RtPfT::new_domain(
                                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                            ),
                        );
                    tokens.push(
                        super::super::vm_session::conv::ec_point(
                            &poker_protocol::crypto::types::ECPoint(token),
                        )
                        .expect("token bridge"),
                    );
                    proofs.push(
                        super::super::vm_session::conv::reveal_token_proof(&proof)
                            .expect("proof bridge"),
                    );
                }
                let args = borsh::to_vec(&SubmitRevealTokensArgs {
                    seat_index: seat,
                    reveal_tokens: tokens,
                    proofs,
                })
                .expect("reveal args");
                let signed = sign_submission(
                    wallets[seat as usize],
                    &table_id,
                    &submission(
                        wallets[seat as usize],
                        now,
                        selectors::submit_player_reveal_tokens(),
                        args,
                        nonces[seat as usize],
                    ),
                );
                rt.submit_signed(signed.clone()).expect("reveal submit");
                last_applied_signed = Some(signed);
                nonces[seat as usize] += 1;
                continue;
            }
            if let Some(actor) = rt.table.current_turn_option() {
                let other = 1u8 - actor;
                let facing_bet = rt.table.seats[actor as usize].total_bet()
                    < rt.table.seats[other as usize].total_bet();
                let selector = if facing_bet {
                    selectors::call()
                } else {
                    selectors::check()
                };
                let args = borsh::to_vec(&SeatIndexArgs { seat_index: actor }).expect("bet args");
                let signed = sign_submission(
                    wallets[actor as usize],
                    &table_id,
                    &submission(
                        wallets[actor as usize],
                        now,
                        selector,
                        args,
                        nonces[actor as usize],
                    ),
                );
                rt.submit_signed(signed.clone()).expect("bet submit");
                last_applied_signed = Some(signed);
                nonces[actor as usize] += 1;
                continue;
            }
            if rt.table.community_cards.to_vec().len() == 5 {
                break;
            }
            panic!(
                "stuck: no reveal, no betting turn, board {} cards",
                rt.table.community_cards.to_vec().len()
            );
        }

        // ---- 断言：牌面完整、乱序命令全部消化、任务已收集 ----
        assert_eq!(
            rt.table.community_cards.to_vec().len(),
            5,
            "board reaches river"
        );
        assert!(
            early_turn_submitted,
            "out-of-order case must have been exercised"
        );
        rt.finish()
            .expect("pending queue must be fully digested (fail-closed)");

        // 负路径 4：已应用签名交易的重放必须被按账户 nonce 水位拒绝
        //（StaleTxNonce——含 "replay"，队列据此死信不重试）。
        let replay = last_applied_signed.expect("at least one signed submission was made");
        let replay_err = rt
            .submit_signed(replay)
            .expect_err("replay of an applied tx must be rejected");
        assert!(
            format!("{replay_err}").contains("replay"),
            "replay must fail at the per-account nonce guard, got: {replay_err}"
        );

        assert!(
            rt.tasks().len() >= 8,
            "reveal/bet tasks must be collected for the proof layer, got {}",
            rt.tasks().len()
        );

        // ---- 派奖前：结算计划派生 + 守恒 ----
        let plan = poker_l1::contracts::texas_poker::settlement::derive_settlement_plan(&rt.table)
            .expect("settlement plan");
        let gross: u64 = rt.table.seats.iter().map(|s| s.total_bet()).sum();
        let awards: u64 = plan.awards.iter().sum();
        assert_eq!(
            awards + plan.rake,
            gross,
            "awards + rake must conserve the pot"
        );

        // ---- 派奖（服务器驱动 advance_deadline，时钟越过展示期）----
        rt.submit_unsigned(
            creator.identity(),
            now + 10_000,
            &selectors::advance_deadline(),
            &Vec::new(),
        )
        .expect("payout advance");
        assert_eq!(rt.table.pot, 0, "pot must be cleared after payout");
    }
}
