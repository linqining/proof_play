//! 单写者协议集成测试：texas 独写 queue WAL、poster 独写 sidecar，
//! 双文件互不交叉；DeadLetter 双源归属；降级迁移的跨文件协作。

use settle_queue::sidecar::{DeadRecord, PosterSidecar};
use settle_queue::task::{SettleKey, SettlePayload, SettleRoute, SettleTask};
use settle_queue::wal::{self, QueueState, QueueWal, WalEvent};

fn dual_task(table: u32, hand: u32) -> SettleTask {
    SettleTask::dual(
        SettleKey::new(table, hand),
        "v2".into(),
        SettlePayload {
            register: settle_queue::task::LegCalldata {
                selector: "0x11".into(),
                calldata: vec!["0x1".into()],
            },
            settle: settle_queue::task::LegCalldata {
                selector: "0x22".into(),
                calldata: vec!["0x2".into()],
            },
            fold_statement: None,
        },
        None,
        0,
    )
}

fn tmproot(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("settle-queue-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// 双文件单写者：WAL 目录只出现 queue.jsonl（texas 写面），sidecar 目录
/// 只出现 poster 自有文件（poster 写面）——两个写者的落盘文件集不相交。
#[test]
fn writers_own_disjoint_file_sets() {
    let root = tmproot("disjoint");
    let wal_path = root.join("texas").join("queue.jsonl");
    let sidecar_dir = root.join("poster");

    // texas 面：只有 queue.jsonl。
    let mut wal = QueueWal::open(&wal_path).unwrap();
    wal.enqueue(dual_task(1, 1)).unwrap();
    let texas_files: Vec<String> = walk(&root.join("texas"));
    assert_eq!(texas_files, vec!["queue.jsonl".to_string()]);

    // poster 面：state/receipts/dead/batches，没有 WAL。
    let sc = PosterSidecar::open(&sidecar_dir).unwrap();
    sc.write_state(&settle_queue::PosterStateFile {
        version: 1,
        cursor: 1,
        in_flight: vec![],
        draining: false,
        updated_at: 1,
    })
    .unwrap();
    let poster_files = walk(&sidecar_dir);
    for f in &poster_files {
        assert!(
            f.starts_with("receipts/")
                || f.starts_with("dead/")
                || f.starts_with("batches/")
                || f == "poster-state.json",
            "poster 写面越界：{f}"
        );
    }
    std::fs::remove_dir_all(&root).ok();
}

fn walk(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        if e.path().is_dir() {
            for sub in walk(&e.path()) {
                out.push(format!("{}/", e.file_name().to_string_lossy()) + &sub);
            }
        } else {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    out
}

/// 跨文件协作全链：入队 → poster 扫描 → 投递期死信（poster 写 dead/）→
/// texas 回读降级（写 WAL）→ poster 扫描看到 Downgraded、清死信重投。
#[test]
fn dual_leg_dead_letter_then_downgrade_requeue() {
    let root = tmproot("downgrade-loop");
    let wal_path = root.join("queue.jsonl");
    let sidecar_dir = root.join("sidecar");

    // texas：入队 Dual 条目。
    let mut wal = QueueWal::open(&wal_path).unwrap();
    let key = SettleKey::new(3, 9);
    wal.enqueue(dual_task(3, 9)).unwrap();

    // poster：游标扫描看到条目。
    let sc = PosterSidecar::open(&sidecar_dir).unwrap();
    let (events, cursor) = wal::scan_from(&wal_path, 0).unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0].1, WalEvent::Enqueued { .. }));
    assert_eq!(cursor, 1);

    // poster：dual 腿重试耗尽 → 投递期死信写 dead/（poster 独占）。
    sc.write_dead(&DeadRecord {
        key,
        route_at_death: SettleRoute::Dual,
        reason: "verify_and_settle_dapv leg exhausted".into(),
        attempts: 8,
        at: 100,
    })
    .unwrap();

    // texas：扫描 sidecar 死信 → Dual 死信是降级候选 → 写 WAL 降级事件。
    let dead = sc.list_dead().unwrap();
    assert_eq!(dead.len(), 1);
    assert!(dead[0].downgrade_candidate());
    wal.downgrade(key).unwrap();

    // poster：下轮扫描看到 Downgraded；对账后清死信、按 Legacy 重投。
    let (events2, _) = wal::scan_from(&wal_path, cursor).unwrap();
    assert!(matches!(events2[0].1, WalEvent::Downgraded { .. }));
    let state: QueueState = wal::replay(&wal_path).unwrap();
    let rec = state.record(&key).unwrap();
    assert_eq!(rec.task.route, SettleRoute::Legacy, "WAL 侧路由已降级");
    assert!(rec.downgraded);
    sc.clear_dead(&key).unwrap();
    assert!(sc.list_dead().unwrap().is_empty());
    std::fs::remove_dir_all(&root).ok();
}
