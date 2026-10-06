//! batch-poster 驱动契约集成测试（mock ProofSource + mock StarknetSend，
//! 不真出证不真上链）。

use std::sync::Arc;
use std::time::Duration;

use batch_poster::config::{CadenceConfig, FoldConfig, PosterConfig};
use batch_poster::proof::MockProofSource;
use batch_poster::{DrivePhase, PosterDriver};
use settle_queue::task::{
    FoldStatement, LegCalldata, SettleKey, SettlePayload, SettleRoute, SettleTask,
};
use settle_queue::wal::QueueWal;
use starknet_txmgr::mock::{MockSend, MockSendScript, ReceiptKind};
use starknet_txmgr::{TxManagerConfig, VisiblePolicy};
use starknet_types_core::felt::Felt;

fn tmproot(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("batch-poster-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn leg(selector: u64, word: u64) -> LegCalldata {
    LegCalldata {
        selector: format!("{selector:#x}"),
        calldata: vec![format!("{word:#x}")],
    }
}

fn legacy_payload() -> SettlePayload {
    SettlePayload {
        register: leg(0x1111, 1),
        settle: leg(0x2222, 2),
        fold_statement: None,
    }
}

fn dual_payload(statement: Option<FoldStatement>) -> SettlePayload {
    SettlePayload {
        register: leg(0x3333, 3),
        settle: leg(0x4444, 4),
        fold_statement: statement,
    }
}

fn fold_statement(i: u64) -> FoldStatement {
    FoldStatement {
        program_hash: "0x1".into(),
        hand_binding: format!("{:#x}", 0x1000 + i),
        fact: format!("{:#x}", 0x2000 + i),
    }
}

fn base_config(root: &std::path::Path) -> PosterConfig {
    PosterConfig {
        queue_wal: root.join("queue.jsonl"),
        sidecar_dir: root.join("sidecar"),
        monad_spool_dir: root.join("spool"),
        operator_account: Felt::from(0x77u64),
        legacy_settlement: Felt::from(0xaaa1u64),
        dual_settlement: Felt::from(0xbbb2u64),
        cadence: CadenceConfig {
            max_batch_hands: 8,
            max_wait_secs: 300,
            min_batch_hands: 1,
        },
        fold: FoldConfig {
            enabled: false,
            ..FoldConfig::default()
        },
        dual_max_attempts: 2,
        legacy_max_attempts: 2,
        poll_interval: Duration::from_millis(1),
        txmgr: TxManagerConfig {
            receipt_polls: 2,
            receipt_poll_interval: Duration::from_millis(1),
            max_attempts_per_tx: 1, // 腿级有界重试纪律归 poster（每 tick 一发）
            ..TxManagerConfig::default()
        },
        visible: VisiblePolicy {
            polls: 2,
            interval: Duration::from_millis(1),
        },
        balance: batch_poster::config::BalanceRollupConfig::default(),
        privacy: Some(privacy_profile::resolve(None, None, None, None).unwrap()),
        privacy_error: None,
    }
}

fn driver<S: starknet_txmgr::StarknetSend, P: batch_poster::proof::ProofSource>(
    cfg: PosterConfig,
    send: Arc<S>,
    proofs: Arc<P>,
) -> PosterDriver<S, P> {
    PosterDriver::new(cfg, send, proofs).unwrap()
}

/// Legacy 两笔驱动契约：register → settlement_digest view 可见 → settle；
/// 回执 sidecar 落两笔交易；poster-state 在途清空。
#[tokio::test]
async fn legacy_two_tx_drive_contract() {
    let root = tmproot("legacy");
    let cfg = base_config(&root);
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    let key = SettleKey::new(1, 100);
    wal.enqueue(SettleTask::legacy(key, legacy_payload(), 0))
        .unwrap();

    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 10,
        broadcast_results: vec![Ok(()), Ok(())],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![Ok(vec![Felt::from(1u64)])],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg.clone(), send.clone(), proofs);

    // tick 1：拾取 + register 广播（RegisterSent）。
    let r = d.tick_at(1).await.unwrap();
    assert_eq!(r.picked, 1);
    assert_eq!(r.tasks_driven, 1, "register 广播是一步");
    // tick 2：可见性断言（settlement_digest view 非零）。
    d.tick_at(2).await.unwrap();
    assert_eq!(send.view_calls(), 1, "Legacy 等 settlement_digest 可见");
    // tick 3：settle 广播 + 回执。
    let r = d.tick_at(3).await.unwrap();
    assert_eq!(r.receipts_written, 1);

    // 两笔顺序：register selector 先于 settle selector。
    let intents = send.intents();
    assert_eq!(intents.len(), 2, "两笔交易非单笔直发");
    assert_eq!(intents[0].calls[0].selector, Felt::from(0x1111u64));
    assert_eq!(intents[1].calls[0].selector, Felt::from(0x2222u64));
    assert!(intents[0].nonce < intents[1].nonce, "nonce 保序");

    // 回执 sidecar：两笔交易哈希。
    let receipt = d
        .sidecar()
        .read_receipt(&key)
        .unwrap()
        .expect("receipt written");
    assert_eq!(receipt.route, SettleRoute::Legacy);
    assert_eq!(receipt.txs.len(), 2);
    assert!(
        d.sidecar()
            .read_state()
            .unwrap()
            .unwrap()
            .in_flight
            .is_empty()
    );
    std::fs::remove_dir_all(&root).ok();
}

/// Dual 双笔驱动 + 降级驱动契约：dual 腿重试耗尽 → 投递期死信（poster 写
/// dead/）→ texas 降级（WAL Downgraded）→ poster 清死信、按 legacy 保底
/// payload 重投至回执。
#[tokio::test]
async fn dual_two_tx_dead_letter_then_downgrade_requeue() {
    let root = tmproot("dual-downgrade");
    let cfg = base_config(&root);
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    let key = SettleKey::new(2, 200);
    wal.enqueue(SettleTask::dual(
        key,
        "v2".into(),
        dual_payload(None),
        Some(legacy_payload()), // legacy 保底（降级重投用）
        0,
    ))
    .unwrap();

    // 广播脚本：dual register ok；dual settle 失败 ×2（耗尽）；
    // 降级后 legacy register ok、legacy settle ok。
    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![
            Ok(()),                             // dual register
            Err("insufficient balance".into()), // dual settle #1
            Err("insufficient balance".into()), // dual settle #2 → 死信
            Ok(()),                             // legacy register
            Ok(()),                             // legacy settle
        ],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)], // dual register 回执
            vec![],
            vec![],
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![Ok(vec![Felt::from(1u64)])],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg.clone(), send.clone(), proofs);

    // tick 1：dual register。tick 2：dual 直通可见相位。tick 3-4：settle 失败
    // ×2 → 投递期死信（route_at_death = Dual）。
    d.tick_at(1).await.unwrap();
    d.tick_at(2).await.unwrap();
    d.tick_at(3).await.unwrap();
    d.tick_at(4).await.unwrap();
    let dead = d.sidecar().read_dead(&key).unwrap().expect("投递期死信");
    assert_eq!(
        dead.route_at_death,
        SettleRoute::Dual,
        "Dual 死信 = 降级候选"
    );
    assert_eq!(dead.attempts, 2);

    // texas 读死信 → 写 WAL 降级事件（测试扮演 texas）。
    wal.downgrade(key).unwrap();

    // tick 5：观察降级 → 清死信 → 按 legacy 保底重投 register。
    let r = d.tick_at(5).await.unwrap();
    assert_eq!(r.downgrades_applied, 1);
    assert!(d.sidecar().read_dead(&key).unwrap().is_none(), "死信已清");
    // legacy register 的 selector 来自保底 payload（0x1111）。
    let intents = send.intents();
    assert_eq!(
        intents.last().unwrap().calls[0].selector,
        Felt::from(0x1111u64),
        "降级后改投 legacy register"
    );

    // tick 6：legacy 可见性。tick 7：legacy settle + 回执。
    d.tick_at(6).await.unwrap();
    let r = d.tick_at(7).await.unwrap();
    assert_eq!(r.receipts_written, 1);
    let receipt = d.sidecar().read_receipt(&key).unwrap().unwrap();
    assert_eq!(receipt.route, SettleRoute::Legacy, "回执记录降级后路由");
    std::fs::remove_dir_all(&root).ok();
}

/// 降级 fail-closed：无 legacy 保底 payload 的降级 = 投递期死信（终态），
/// 绝不拿 dual calldata 冒充 legacy。
#[tokio::test]
async fn downgrade_without_fallback_dead_letters() {
    let root = tmproot("downgrade-nofallback");
    let cfg = base_config(&root);
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    let key = SettleKey::new(3, 300);
    wal.enqueue(SettleTask::dual(
        key,
        "v2".into(),
        dual_payload(None),
        None,
        0,
    ))
    .unwrap();
    wal.downgrade(key).unwrap(); // 直接降级（无保底）。

    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![Ok(())],
        receipts_by_broadcast: vec![vec![Some(ReceiptKind::Succeeded)]],
        view_results: vec![],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg, send, proofs);
    d.tick_at(1).await.unwrap(); // 拾取 + dual register + 观察降级事件
    let dead = d
        .sidecar()
        .read_dead(&key)
        .unwrap()
        .expect("无保底降级 = 死信");
    assert_eq!(
        dead.route_at_death,
        SettleRoute::Legacy,
        "终态死信（不再降级）"
    );
    std::fs::remove_dir_all(&root).ok();
}

/// fold 批级键域 + 崩溃恢复：批键 = keccak_root（同语句集同键）、批回执
/// 回填批记录并逐 member 写回执、Monad 信封落盘；崩溃（drop）后恢复不
/// 重复出证（MockProofSource 计数 = 1）。
#[tokio::test]
async fn fold_batch_key_domain_and_crash_recovery() {
    let root = tmproot("fold");
    let mut cfg = base_config(&root);
    cfg.fold.enabled = true;
    // M2 硬门槛：fold 开 ⇒ rollup 开（余额树随批推进 + 批完成快照根）。
    cfg.balance.enabled = true;
    cfg.balance.state_path = root.join("balance-state.json");
    cfg.balance.checkpoint_path = root.join("balance-checkpoints.jsonl");
    cfg.balance.ledger_state_path = root.join("ledger-state.json");
    // 测试增量以「账本单位」直书（100 非生产 wei 量级）→ divisor=1。
    cfg.balance.ledger_unit_divisor = 1;
    {
        let mut seeder = balance_rollup::BalanceRollup::open(
            &cfg.balance.state_path,
            &cfg.balance.checkpoint_path,
            balance_rollup::LeafFormat::Plain,
        )
        .unwrap();
        seeder
            .seed_balances(&[(Felt::from(0xbbb2u64), 100)], 0)
            .unwrap();
        // 账本镜像同种子（funder 代充的账本面等价物；divisor=1 与 cfg 一致）。
        let mut ledger = balance_rollup::ledger::LedgerMirror::open(
            &cfg.balance.ledger_state_path,
            cfg.balance.ledger_unit_divisor,
        )
        .unwrap();
        let felt32 = Felt::from(0xbbb2u64).to_bytes_be();
        // 账本键 = 钱包 felt 低 20 字节地址（wallet_felt_to_address 同式）。
        let addr = balance_rollup::ledger::wallet_felt_to_address(&felt32);
        ledger.seed(&[(addr, 100)], 0).unwrap();
    }
    cfg.cadence.max_wait_secs = 60; // 时间窗内攒批
    cfg.cadence.max_batch_hands = 2; // 2 手即满（K=2 为 2 的幂）
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    let k1 = SettleKey::new(4, 400);
    let k2 = SettleKey::new(5, 500);
    // 余额增量语料（escape 地基）：输家先有种子面之外的净额约定——测试
    // 里赢家 +N / 输家 -N 双方都直接携带（rollup 侧只验零和与下穿）。
    let balance = |win: i128| settle_queue::task::BalanceEntry {
        players: vec!["0xaaa1".into(), "0xbbb2".into()],
        deltas_wei: vec![win, -win],
    };
    wal.enqueue(
        SettleTask::dual(
            k1,
            "snip36".into(),
            dual_payload(Some(fold_statement(1))),
            Some(legacy_payload()),
            0,
        )
        .with_balance_entry(balance(100)),
    )
    .unwrap();
    wal.enqueue(
        SettleTask::dual(
            k2,
            "snip36".into(),
            dual_payload(Some(fold_statement(2))),
            Some(legacy_payload()),
            0,
        )
        .with_balance_entry(balance(-100)),
    )
    .unwrap();

    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![Ok(()), Ok(()), Ok(())],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg.clone(), send.clone(), proofs.clone());

    // tick 1：拾取 2 手 + 攒满 K=2 成批（出证在下一 tick 的批推进步）。
    let r = d.tick_at(1).await.unwrap();
    assert_eq!(r.picked, 2);
    assert_eq!(r.batches_formed, 1, "K=2 攒满即成批");
    assert_eq!(proofs.call_count(), 0, "成批与出证分步（一步一 tick）");
    // tick 2：出证 → Submitting；批键 = keccak_root。
    d.tick_at(2).await.unwrap();
    assert_eq!(proofs.call_count(), 1, "出证一次");
    let batches = d.sidecar().list_batches().unwrap();
    assert_eq!(batches.len(), 1);
    let expected_key =
        batch_poster::batch::compute_batch_key(&[fold_statement(1), fold_statement(2)]).unwrap();
    assert_eq!(
        batches[0].batch_key,
        format!("0x{}", hex::encode(expected_key)),
        "批键 = keccak_root（zchain 幂等键/Monad 信封主键）"
    );
    assert_eq!(batches[0].members, vec![k1, k2], "members 引用单手键");

    // Monad 信封 + DA L1 statements 伴随工件落盘（spool，键 = keccak_root）。
    let spooled = std::fs::read_dir(&cfg.monad_spool_dir).unwrap().count();
    assert_eq!(spooled, 2, "信封 + statements 伴随工件");
    let statements_path = cfg.monad_spool_dir.join(format!(
        "{}.statements.json",
        batches[0].batch_key.trim_start_matches("0x")
    ));
    let statements: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&statements_path).unwrap()).unwrap();
    assert_eq!(
        statements["keccak_root"], batches[0].batch_key,
        "DA L1 锚 = 批键（fact preimage 离线可复核）"
    );
    assert_eq!(
        statements["statements"].as_array().map(Vec::len),
        Some(2),
        "K=2 语句全量公开"
    );

    // 崩溃：drop 驱动器（批已 Forming→Submitting，出证产物在内存丢失）。
    drop(d);

    // 恢复：新驱动器（同 sidecar/WAL）——批记录续投、出证不重复超限。
    let send2 = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![Ok(()), Ok(()), Ok(())],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![],
    }));
    let proofs2 = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d2 = driver(cfg.clone(), send2, proofs2.clone());
    // 恢复语义：Submitting 但出证产物（内存态）丢失 → 回 Forming 重出证
    //（批键幂等保证不重复上链），再逐 member fold 入口提交。
    d2.recover().unwrap();
    d2.tick_at(3).await.unwrap(); // Submitting(产物缺失) → 回 Forming
    assert_eq!(proofs2.call_count(), 0);
    d2.tick_at(4).await.unwrap(); // Forming 重出证 → Submitting
    assert_eq!(proofs2.call_count(), 1, "恢复后重出证恰好一次（批键幂等）");
    let r = d2.tick_at(5).await.unwrap(); // member 1 fold settle
    assert_eq!(r.receipts_written, 1);
    let r = d2.tick_at(6).await.unwrap(); // member 2 fold settle + 批回执
    assert_eq!(r.receipts_written, 1);
    assert_eq!(r.batches_receipted, 1, "批回执回填批记录");

    // 逐 member 回执（批键随行）；批记录 Receipted。
    let rec1 = d2.sidecar().read_receipt(&k1).unwrap().unwrap();
    let rec2 = d2.sidecar().read_receipt(&k2).unwrap().unwrap();
    assert_eq!(
        rec1.batch_key.as_deref(),
        Some(batches[0].batch_key.as_str())
    );
    assert_eq!(
        rec2.batch_key.as_deref(),
        Some(batches[0].batch_key.as_str())
    );
    let sealed = d2
        .sidecar()
        .read_batch(&batches[0].batch_key)
        .unwrap()
        .unwrap();
    assert_eq!(sealed.state, settle_queue::sidecar::BatchState::Receipted);
    // M2：批完成时余额树根随批登记（批记录 + spool 伴随工件）。
    assert!(
        sealed.balance_root.is_some(),
        "批记录必须携带 balance_root（escape 地基随批）"
    );
    let companion = root
        .join("spool")
        .join(format!(
            "{}.balance.json",
            sealed.batch_key.trim_start_matches("0x")
        ));
    assert!(companion.exists(), "余额根伴随工件随批落盘: {}", companion.display());
    // 账本面增量根工件（escape-ledger）：叶集 = 换手后非零余额方。
    let ledger_path = root.join("spool").join(format!(
        "{}.ledger-root.json",
        sealed.batch_key.trim_start_matches("0x")
    ));
    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert_eq!(ledger["spec_version"], 1);
    assert_eq!(ledger["ledger_index"], 1);
    assert_eq!(ledger["leaf_count"], 1, "换手后仅 bbb2 余 100（种子面）");
    assert!(ledger["hash_spec"]
        .as_str()
        .unwrap()
        .contains("zchain.vault.balance_root.v1"));
    std::fs::remove_dir_all(&root).ok();
}

/// drain 逃生口：置位后不拾取新任务，在途清空后 idle。
#[tokio::test]
async fn drain_stops_picking() {
    let root = tmproot("drain");
    let cfg = base_config(&root);
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    wal.enqueue(SettleTask::legacy(
        SettleKey::new(6, 600),
        legacy_payload(),
        0,
    ))
    .unwrap();
    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![Ok(()), Ok(())],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![Ok(vec![Felt::from(1u64)])],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg, send, proofs);
    d.drain();
    let r = d.tick_at(1).await.unwrap();
    assert_eq!(r.picked, 0, "drain 期不拾取（tick 前置位）");
    assert!(d.draining());
    assert!(d.status().draining);
    std::fs::remove_dir_all(&root).ok();
}

/// 相位语义冒烟：RegisterSent/RegisterVisible 由 poster-state 快照携带
/// （settle-queue SubmitPhase 映射）。
#[tokio::test]
async fn phases_persisted_in_poster_state() {
    let root = tmproot("phases");
    let cfg = base_config(&root);
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    let key = SettleKey::new(7, 700);
    wal.enqueue(SettleTask::legacy(key, legacy_payload(), 0))
        .unwrap();
    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![Ok(()), Ok(())],
        receipts_by_broadcast: vec![
            vec![Some(ReceiptKind::Succeeded)],
            vec![Some(ReceiptKind::Succeeded)],
        ],
        view_results: vec![Ok(vec![Felt::from(1u64)])],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg, send, proofs);
    d.tick_at(1).await.unwrap();
    let st = d.sidecar().read_state().unwrap().unwrap();
    assert_eq!(st.in_flight.len(), 1);
    assert_eq!(
        st.in_flight[0].phase,
        Some(settle_queue::state::SubmitPhase::RegisterSent),
        "Picked 相在 None、广播后 RegisterSent"
    );
    let _ = DrivePhase::Picked; // 相位词汇可达性（poster 驱动视图）。
    std::fs::remove_dir_all(&root).ok();
}

/// oldest_batch_age_secs 语义回归：两个在途批（created_at 不同）时，
/// 年龄必须基于**最早**创建的批（created_at 取 min）——修复前 `.max()`
/// 给出的是最年轻批的年龄（监控语义相反）。
#[tokio::test]
async fn oldest_batch_age_is_the_oldest_open_batch() {
    let root = tmproot("oldest-age");
    let mut cfg = base_config(&root);
    cfg.fold.enabled = true;
    // M2 硬门槛：fold 开 ⇒ rollup 开（余额树随批推进 + 批完成快照根）。
    cfg.balance.enabled = true;
    cfg.balance.state_path = root.join("balance-state.json");
    cfg.balance.checkpoint_path = root.join("balance-checkpoints.jsonl");
    cfg.cadence.max_batch_hands = 2; // 4 手 → 两个批（每批 2 手）
    let mut wal = QueueWal::open(&cfg.queue_wal).unwrap();
    for i in 1..=4u32 {
        wal.enqueue(SettleTask::dual(
            SettleKey::new(8, i),
            "snip36".into(),
            dual_payload(Some(fold_statement(u64::from(i)))),
            Some(legacy_payload()),
            0,
        ))
        .unwrap();
    }
    let send = Arc::new(MockSend::new(MockSendScript {
        chain_nonce: 0,
        broadcast_results: vec![],
        receipts_by_broadcast: vec![],
        view_results: vec![],
    }));
    let proofs = Arc::new(MockProofSource::new(&cfg.fold.expected_program_hash));
    let mut d = driver(cfg, send, proofs);
    d.tick_at(1).await.unwrap(); // 批 1 成型（created_at = 1）
    d.tick_at(1000).await.unwrap(); // 批 1 出证（Submitting，在途）+ 批 2 成型（created_at = 1000）
    let st = d.status();
    assert_eq!(st.pending_batches, 2, "两个批都在途");
    let now_sys = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let oldest = st.oldest_batch_age_secs.expect("有在途批");
    // 年龄基于最早批（created_at=1）：≥ now-1，且严格大于最年轻批的年龄
    //（now-1000）——修复前 .max() 恰好给出后者。
    assert!(
        oldest > now_sys.saturating_sub(1000),
        "oldest={oldest} 应基于最早创建的批（修复前 .max() 会返回最年轻批年龄 ≈ {}）",
        now_sys.saturating_sub(1000)
    );
    assert!(oldest >= now_sys.saturating_sub(1));
    std::fs::remove_dir_all(&root).ok();
}
