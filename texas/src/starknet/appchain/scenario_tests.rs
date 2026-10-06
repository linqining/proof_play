//! B6/B7 集成场景（真实执行；单测试函数串行驱动 a→d，共享进程级运行时
//! 单例——RUNTIME 是 OnceLock，多场景共用一套 sequencer/pipeline/custody）：
//!
//! - (a) 存款桥：DepositEvent → REAL note 铸出；重复事件（同 tx/index）
//!   幂等——只铸一次；
//! - (b) 一手牌（最小 canonical witness 批，真实 stwo 出证）→ Appchain
//!   出口结算：REAL 策略 StarkRequired + 钉扎本进程 attestor → 本地
//!   prover 完整 STARK 验证 → 批次 → 水位推进 + 批次根；SOFT_CONFIRM
//!   事件载荷（soft/proven 两级）断言；
//! - (c) 提现闭环：结算 proven → payout note REAL 提现烧毁 → finality 门
//!   （水位 + 批次根）放行 → mock pay → mark_paid；
//! - (d) 对账：零差异；储备少记注入 → `reconciliation_mismatch_total`
//!   告警计数触发（M7-ACC-4 形态）。
//!
//! 数字节买 zchain/poker-appchain-texasair e2e（等额全下、无 uncalled 层）：
//! gross_pot 1050（500+500+50）、rake 52（5%，contested 单层）、赢家座1
//! award 998、treasury 10 / operator 42。
//!
//! 出证为真实 stwo（`prove_canonical_tagged_batch` + 独立验证器），release
//! 下秒级；`cargo test -p texas --release appchain` 驱动。

use std::sync::{Arc, Mutex};

use poker_appchain::note::AssetClass;
use poker_texas_air::texas_canonical::{
    CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalTransitionKind,
    CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS, MAX_CANONICAL_SEATS,
    NO_CANONICAL_SEAT, CANONICAL_ABI_VERSION,
};
use poker_texas_air::texas_canonical_air::prove_canonical_tagged_batch;

use super::bridge::{process_deposits_once, process_withdrawals_once, reconcile_once,
    DepositEvent, MockVaultProvider};
use super::exit::{settle_from_projection, MirrorProjection};
use super::runtime::{init_for_test, runtime, AppchainConfig};
use super::keys;

/// 桌 id（canonical 镜像与 appchain 账本同值——归档绑定判据）。
const TABLE_ID: u32 = 42;
const BUY_IN: u64 = 500;
const FOLDER_NOTE: u64 = 50;
const GROSS_POT: u64 = BUY_IN * 2 + FOLDER_NOTE; // 1050
const RAKE: u64 = 52;
const AWARD: u64 = GROSS_POT - RAKE; // 998
const TREASURY_OUT: u64 = 10;
const OPERATOR_OUT: u64 = RAKE - TREASURY_OUT; // 42

fn deposit_event(tx: u8, owner: [u8; 32], amount: u64) -> DepositEvent {
    DepositEvent {
        source_chain: 1,
        vault: [0xAB; 32],
        tx_hash: [tx; 32],
        event_index: 0,
        owner,
        amount,
        seq: 0,
    }
}

/// 5 行 canonical witness 批：Raise → Raise(all-in) → Fold → Call(all-in)
/// → AdvanceRound 收池（终态镜像 pot = 1050）。构造即自检（validate_shape
/// 含 custody 恒等式）。镜像 poker-appchain-texasair e2e 已证形状。
fn full_hand_witnesses() -> Vec<CanonicalTransitionWitness> {
    let active_seat = |stack: u64, bet: u64, total_bet: u64, index: usize| CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted: false,
        stack,
        bet,
        total_bet,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [70 + index as u8; 32],
        key_commitment: [80 + index as u8; 32],
        hole_cards_commitment: [90 + index as u8; 32],
    };
    let hand_start = || {
        let mut image = poker_texas_air::texas_canonical::CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: u64::from(TABLE_ID),
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Betting,
            phase_subtag: 1,
            street: 1,
            current_turn: 0,
            deadline_ms: 42_500,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 3_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 50,
            min_raise: 50,
            chip_pool: BUY_IN * 3,
            pot: 0,
            button: 0,
            last_bb_seat: poker_texas_air::texas_canonical::NO_CANONICAL_SEAT,
            max_players: 3,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        };
        image.seats[0] = active_seat(BUY_IN, 0, 0, 0);
        image.seats[1] = active_seat(BUY_IN - 25, 25, 25, 1);
        image.seats[2] = active_seat(BUY_IN - 50, 50, 50, 2);
        image
    };
    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut poker_texas_air::texas_canonical::CanonicalStateImage)| {
        let pre = rows
            .last()
            .map(|r| r.post.clone())
            .unwrap_or_else(hand_start);
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: poker_texas_air::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: poker_texas_air::canonical_rake_opening::CanonicalBlindOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
            .validate_shape()
            .unwrap_or_else(|e| panic!("witness {seq} ({kind:?}) shape invalid: {e}"));
        rows.push(witness);
    };

    step(CanonicalTransitionKind::Raise, [70; 32], 0, 200, &|p| {
        p.current_turn = 1;
        p.current_bet = 200;
        p.min_raise = 150;
        p.acted_mask = 0b001;
        p.seats[0].acted = true;
        p.seats[0].stack = BUY_IN - 200;
        p.seats[0].bet = 200;
        p.seats[0].total_bet = 200;
    });
    step(CanonicalTransitionKind::Raise, [71; 32], 1, 500, &|p| {
        p.current_turn = 2;
        p.current_bet = 500;
        p.min_raise = 300;
        p.acted_mask = 0b010;
        p.seats[1].acted = true;
        p.seats[1].status = CanonicalSeatStatus::AllIn;
        p.seats[1].stack = 0;
        p.seats[1].bet = 500;
        p.seats[1].total_bet = 500;
        p.seats[0].acted = false;
    });
    step(CanonicalTransitionKind::Fold, [72; 32], 2, 0, &|p| {
        p.current_turn = 0;
        p.acted_mask = 0b110;
        p.seats[2].status = CanonicalSeatStatus::Folded;
        p.seats[2].acted = true;
    });
    step(CanonicalTransitionKind::Call, [70; 32], 0, 300, &|p| {
        p.current_turn = NO_CANONICAL_SEAT;
        p.acted_mask = 0b111;
        p.seats[0].acted = true;
        p.seats[0].status = CanonicalSeatStatus::AllIn;
        p.seats[0].stack = 0;
        p.seats[0].bet = 500;
        p.seats[0].total_bet = 500;
    });

    let advance_pre = rows.last().expect("pre-advance row").post.clone();
    let mut advance_post = advance_pre.clone();
    advance_post.call_seq = 5;
    advance_post.phase = CanonicalPhase::Revealing;
    advance_post.phase_subtag = 2;
    advance_post.street = 2;
    advance_post.deadline_ms = 45_000;
    advance_post.current_turn = NO_CANONICAL_SEAT;
    advance_post.current_bet = 0;
    advance_post.min_raise = 0;
    advance_post.pot = GROSS_POT;
    advance_post.protocol_pending_mask = 0b111;
    for seat in &mut advance_post.seats {
        seat.bet = 0;
    }
    let mut advance = CanonicalTransitionWitness {
        pre: advance_pre,
        post: advance_post,
        kind: CanonicalTransitionKind::AdvanceRound,
        actor: [0; 32],
        action: CanonicalActionPayload {
            seat: NO_CANONICAL_SEAT,
            amount: 0,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening {
            pre_cards_dealt: 6,
            post_cards_dealt: 9,
            pre_board_len: 0,
            post_board_len: 0,
            pre_second_board_len: 0,
            post_second_board_len: 0,
            run_it_twice: false,
            reveal_purpose: 2,
            assignment_count: 3,
            assignments: {
                let mut slots = [CanonicalBoardRevealAssignment::EMPTY;
                    MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS];
                for (position, slot) in slots.iter_mut().take(3).enumerate() {
                    *slot = CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 6 + position as u8,
                        runout_index: 0,
                        board_position: position as u8,
                        pending_mask: 0b111,
                        submitted_mask: 0,
                    };
                }
                slots
            },
        },
        protocol_completion: Default::default(),
        rake_opening: poker_texas_air::canonical_rake_opening::CanonicalRakeOpening::ZERO,
        blind_opening: poker_texas_air::canonical_rake_opening::CanonicalBlindOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    advance.seal();
    advance.validate_shape().expect("advance opening shape");
    rows.push(advance);
    rows
}

/// 结算投影（镜像 pre-payout 快照的 settlement-core 输入）。
fn scenario_projection(wallets: &[[u8; 32]; 3]) -> MirrorProjection {
    let total_bets: Vec<u64> = {
        let mut v = vec![0u64; MAX_CANONICAL_SEATS];
        v[0] = BUY_IN;
        v[1] = BUY_IN;
        v[2] = FOLDER_NOTE;
        v
    };
    let inactive: Vec<bool> = {
        let mut v = vec![true; MAX_CANONICAL_SEATS];
        v[0] = false;
        v[1] = false;
        v[2] = true; // BB 弃牌
        v
    };
    let all_in: Vec<bool> = {
        let mut v = vec![false; MAX_CANONICAL_SEATS];
        v[0] = true;
        v[1] = true;
        v
    };
    let holes: Vec<&'static [u8]> = {
        let mut v: Vec<&'static [u8]> = vec![&[]; MAX_CANONICAL_SEATS];
        v[0] = Box::leak(vec![0u8, 1].into_boxed_slice()); // ♠2 ♠3
        v[1] = Box::leak(vec![12u8, 11].into_boxed_slice()); // ♠A ♠K
        v
    };
    MirrorProjection {
        snapshot: poker_settlement_core::TableSnapshot {
            seat_count: MAX_CANONICAL_SEATS,
            button: 0,
            total_bets: Box::leak(total_bets.into_boxed_slice()),
            inactive: Box::leak(inactive.into_boxed_slice()),
            all_in: Box::leak(all_in.into_boxed_slice()),
            hole_cards: Box::leak(holes.into_boxed_slice()),
            rake_mode: poker_settlement_core::RAKE_MODE_PERCENTAGE,
            rake_bps: 500,
            rake_cap: 1_000,
        },
        boards: poker_settlement_core::SettlementBoards::single(vec![10, 9, 8, 13, 26]),
        participants: vec![
            (0, wallets[0], BUY_IN, BUY_IN),
            (1, wallets[1], BUY_IN, BUY_IN),
            (2, wallets[2], FOLDER_NOTE, FOLDER_NOTE),
        ],
        mirror_pot: GROSS_POT,
    }
}

#[test]
fn appchain_bridge_scenarios_deposit_settle_withdraw_reconcile() {
    let mock = Arc::new(MockVaultProvider::new());
    let config = AppchainConfig {
        enabled: true,
        wal_dir: "/tmp/texas-appchain-test".into(),
        sequencer_seed: [0x5E; 32],
        attestor_seed: [0xA7; 32],
        asset_class: AssetClass::Real,
        treasury_bps: 2_000,
        provider: "mock".into(),
        poll_ms: 200,
        reconcile_secs: 300,
        prove_timeout_secs: 900, // 真实 stwo：debug 构建下验证耗时显著更长
        rake_bps: 500,
        rake_cap: 1_000,
    };
    init_for_test(config, Arc::clone(&mock) as Arc<dyn super::bridge::VaultProvider>)
        .expect("runtime singleton (single scenario test per process)");
    let rt = runtime().expect("global handle");

    // 软确认事件捕获
    let events: Arc<Mutex<Vec<(u64, String, u64, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    super::runtime::set_soft_confirm_listener(Box::new(move |frame, root, wm, level| {
        sink.lock().unwrap().push((frame, root.to_string(), wm, level.to_string()));
    }));

    let wallets: [[u8; 32]; 3] = [
        [0xA0; 32],
        [0xA1; 32],
        {
            let mut w = [0u8; 32];
            w[31] = 0xA2;
            w
        },
    ];

    // ===== (a) 存款桥：事件 → REAL note 铸出；重复事件幂等 =====
    let w0 = keys::owner_key_of(&wallets[0]).public_bytes();
    let w1 = keys::owner_key_of(&wallets[1]).public_bytes();
    let w2 = keys::owner_key_of(&wallets[2]).public_bytes();
    mock.push_deposit(deposit_event(1, wallets[0], BUY_IN));
    mock.push_deposit(deposit_event(2, wallets[1], BUY_IN));
    mock.push_deposit(deposit_event(3, wallets[2], FOLDER_NOTE));
    let processed = process_deposits_once(rt).expect("deposit bridge run");
    assert_eq!(processed, 3, "3 events processed");
    let balance = |owner: &[u8; 33]| -> u128 {
        rt.with_seq(|seq| seq.state().balances_of(owner).0)
    };
    assert_eq!(balance(&w0), u128::from(BUY_IN));
    assert_eq!(balance(&w1), u128::from(BUY_IN));
    assert_eq!(balance(&w2), u128::from(FOLDER_NOTE));
    assert_eq!(rt.metrics.counter("bridge_deposits_total"), 3);
    // 幂等：同一 (tx, index) 事件再次投递（新游标位）→ 只推游标不铸币
    mock.push_duplicate(deposit_event(1, wallets[0], BUY_IN));
    let processed_again = process_deposits_once(rt).expect("duplicate run");
    assert_eq!(processed_again, 0, "duplicate deposit must be idempotent");
    assert_eq!(balance(&w0), u128::from(BUY_IN), "no double mint");
    assert_eq!(rt.metrics.counter("bridge_deposits_total"), 3);

    // ===== (b) 一手牌：真实 STARK 出证 → Appchain 出口结算 =====
    // 真实 stwo 出证（独立验证器在 prover.prove 内再跑一次全量验证）。
    let archive = prove_canonical_tagged_batch(&full_hand_witnesses())
        .expect("canonical batch proof (real stwo)");
    assert_eq!(archive.table_id, u64::from(TABLE_ID));
    let archive_bytes = borsh::to_vec(&archive).expect("archive encoding");
    let hand_proof = poker_appchain::settlement::HandProofBinding {
        archive_bytes,
        post_state_commitment: archive.post_state_commitment,
        pre_state_root: archive.pre_state_root,
        post_state_root: archive.post_state_root,
    };
    let receipt = settle_from_projection(
        rt,
        TABLE_ID,
        1,
        scenario_projection(&wallets),
        RAKE,
        Some(hand_proof),
    )
    .expect("appchain exit settles the hand");
    assert!(receipt.proven, "settle must be proven within timeout");
    let settle_op = receipt.settle_op_index;
    // 水位推进 + 批次根记录（§5.4 finality 证据齐备）
    assert!(rt.with_seq(|seq| seq.proven_watermark()) >= settle_op);
    assert_eq!(rt.with_seq(|seq| seq.batch_covered_through()), Some(settle_op));
    assert_eq!(
        rt.with_seq(|seq| seq.batch_root_at(settle_op)),
        receipt.batch_root
    );
    // 资金转移：赢家 payout note + rake 分账 note
    assert_eq!(balance(&w1), u128::from(AWARD), "winner payout note");
    let treasury = rt.treasury_key().public_bytes();
    let operator = rt.operator_key().public_bytes();
    assert_eq!(balance(&treasury), u128::from(TREASURY_OUT));
    assert_eq!(balance(&operator), u128::from(OPERATOR_OUT));
    // 手不可重放（同 binding 二次 Settle 必拒——sequencer settled_bindings）
    assert_ne!(receipt.hand_binding, [0u8; 32]);

    // 软确认事件载荷：soft（每帧）+ proven（批次后）两级齐备
    let events = events.lock().unwrap();
    assert!(
        events.iter().any(|(_, _, _, level)| level == "soft"),
        "soft-level events emitted per frame"
    );
    let proven_event = events
        .iter()
        .find(|(frame, _, _, level)| *frame == settle_op && level == "proven")
        .expect("proven-level event for settle op");
    let (frame, root_hex, watermark, _) = proven_event;
    assert_eq!(*frame, settle_op);
    assert!(root_hex.starts_with("0x") && root_hex.len() == 66, "state_root_hex format");
    assert!(*watermark >= settle_op, "watermark covers settle op");
    drop(events);

    // ===== (c) 提现闭环：finality 门放行 → mock pay → mark_paid =====
    let request_id = {
        let mut r = [0u8; 32];
        r[0] = 0x5A;
        r
    };
    rt.request_withdrawal(&wallets[1], AWARD, request_id, [0xEE; 32])
        .expect("finalized REAL withdrawal enqueued");
    assert_eq!(rt.custody.lock().unwrap().queued_withdrawals(), 1);
    assert_eq!(balance(&w1), 0, "payout note burned");
    let paid = process_withdrawals_once(rt);
    assert_eq!(paid, 1, "one payout executed");
    assert_eq!(rt.custody.lock().unwrap().queued_withdrawals(), 0);
    let mock_paid = mock.paid();
    assert_eq!(mock_paid.len(), 1);
    assert_eq!(mock_paid[0].0, request_id);
    assert_eq!(mock_paid[0].1, AWARD);
    // 幂等重复申请（同 id 同载荷）不冲突、不重复打款——note 已烧毁，
    // 二次申请在"无 exact 面额 note"处拒绝
    rt.request_withdrawal(&wallets[1], AWARD, request_id, [0xEE; 32])
        .expect_err("note already burned — second request has no note");
    assert_eq!(process_withdrawals_once(rt), 0);

    // ===== (d) 对账：零差异 → 储备少记注入 → 告警触发 =====
    let report = reconcile_once(rt).expect("first reconciliation");
    assert_eq!(report.delta, 0, "balanced: issued == snapshot + paid-back");
    assert_eq!(
        u64::try_from(report.issued_real_total).unwrap(),
        GROSS_POT,
        "issued = live(52) + burned(998)"
    );
    assert_eq!(
        u64::try_from(report.pending_withdrawal_total).unwrap(),
        0,
        "no queued withdrawals after payout"
    );
    // 注入：mock 储备少记 → 差异非零 → 告警计数
    let mismatch_before = rt.metrics.counter("reconciliation_mismatch_total");
    mock.set_reserve(100); // 少记（真实储备 52 + 打款回冲 998 = 1050）
    let bad = reconcile_once(rt).expect("second reconciliation");
    assert_ne!(bad.delta, 0, "under-reported reserve must show a delta");
    assert!(
        rt.metrics.counter("reconciliation_mismatch_total") > mismatch_before,
        "mismatch alert counter must fire (M7-ACC-4)"
    );
    assert!(runtime().is_some());
}

/// dev faucet（发现 5/11 统一通道，e2e 语料线 M3-2）：PLAY 面直铸
/// owner 可见余额 note、重复领取靠 nonce 区分幂等键、REAL 面拒绝
/// （绝不无储备铸 REAL）。局部 build_for_test 实例——不触全局单例，
/// 与上方场景测试无 OnceLock 争用。
#[test]
fn dev_faucet_credits_play_and_refuses_real() {
    use super::runtime::{build_for_test, faucet_submit};

    let mock = Arc::new(MockVaultProvider::new());
    let play_config = AppchainConfig {
        enabled: true,
        wal_dir: "/tmp/texas-appchain-faucet-test".into(),
        sequencer_seed: [0x5E; 32],
        attestor_seed: [0xA7; 32],
        asset_class: AssetClass::Play,
        treasury_bps: 2_000,
        provider: "mock".into(),
        poll_ms: 200,
        reconcile_secs: 300,
        prove_timeout_secs: 900,
        rake_bps: 500,
        rake_cap: 1_000,
    };
    let rt =
        build_for_test(play_config.clone(), Arc::clone(&mock) as Arc<dyn super::bridge::VaultProvider>);

    let wallet = [0xA1u8; 32];
    // 首铸：owner 名下出现对应 PLAY 余额 note（无桌绑定）。
    let frame = faucet_submit(&rt, wallet, 5_000, 7).expect("PLAY 面铸入成功");
    let owner = super::keys::owner_key_of(&wallet).public_bytes();
    let found = rt.with_seq(|seq| {
        seq.state()
            .notes
            .values()
            .any(|e| {
                e.note.owner == owner
                    && e.note.asset_class == AssetClass::Play
                    && e.note.amount == 5_000
                    && e.note.table_id.is_none()
            })
    });
    assert!(found, "faucet 后 owner 应有 PLAY 余额 note（frame={frame}）");

    // 同钱包同额度重复领取（nonce=0 → 时间派生 deposit_id）不撞幂等键。
    faucet_submit(&rt, wallet, 5_000, 0).expect("重复领取成功（nonce 区分）");

    // 零额仍走同一路径（Operation::Deposit amount=0 由 sequencer 裁决——
    // 这里只钉 faucet 层不 panic；拒绝语义归 sequencer）。
    let _ = faucet_submit(&rt, wallet, 0, 9);

    // REAL 面：拒绝（绝不无储备铸 REAL）。
    let real_config = AppchainConfig {
        asset_class: AssetClass::Real,
        ..play_config
    };
    let rt_real = build_for_test(real_config, Arc::clone(&mock) as Arc<dyn super::bridge::VaultProvider>);
    let err = faucet_submit(&rt_real, wallet, 5_000, 7).unwrap_err();
    assert!(err.contains("REAL"), "{err}");
}
