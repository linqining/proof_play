//! da-backup CLI——DA L0 快照备份的部署入口。
//!
//! ```text
//! da-backup run    --config <manifest.json>              # 单次快照（cron/timer 形态）
//! da-backup watch  --config <manifest.json> [--interval 300]  # 常驻循环（第二块盘推式）
//! da-backup verify <snapshot_dir>                        # 独立复核（快照完整性）
//! da-backup restore <snapshot_dir> --into <dir>          # 恢复演练（打印 RTO）
//! ```
//!
//! manifest 形态（JSON）：
//! `{"dest_dir":"...","retention":7,"sources":[{"name":"queue","path":"..."},…]}`
//! 缺省覆盖面与部署位见 docs/BATCH_POSTER_OPS.md DA 节。

use std::path::PathBuf;
use std::time::Duration;

use da_backup::{BackupConfig, BackupError};

fn usage() -> ! {
    eprintln!(
        "用法: da-backup <run|watch|verify|restore> …\n\
         \x20 run    --config <manifest.json>                     单次快照\n\
         \x20 watch  --config <manifest.json> [--interval <secs>] 常驻循环（缺省 300s）\n\
         \x20 verify <snapshot_dir>                               复核快照\n\
         \x20 restore <snapshot_dir> --into <dir>                 恢复演练（打印 RTO）"
    );
    std::process::exit(2);
}

fn arg_of(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run_watch(cfg: BackupConfig, interval: Duration) -> Result<(), BackupError> {
    eprintln!(
        "[da-backup] watch 启动（interval={:?}，dest={}）",
        interval,
        cfg.dest_dir.display()
    );
    loop {
        match da_backup::run_once(&cfg, now_secs()) {
            Ok(r) => eprintln!(
                "[da-backup] 快照完成 {}（{} 文件 / {} bytes）",
                r.snapshot_dir.display(),
                r.manifest.files.len(),
                r.manifest.total_bytes
            ),
            Err(e) => eprintln!("[da-backup] 快照失败: {e}"),
        }
        std::thread::sleep(interval);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or_else(|| usage());
    match mode {
        "run" => {
            let Some(config_path) = arg_of(&args, "--config") else { usage() };
            let cfg = BackupConfig::from_path(&config_path)
                .unwrap_or_else(|e| die(&format!("manifest 装载失败: {e}")));
            let report =
                da_backup::run_once(&cfg, now_secs()).unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "{}",
                serde_json::to_string_pretty(&report.manifest).unwrap_or_default()
            );
            eprintln!("[da-backup] 快照: {}", report.snapshot_dir.display());
        }
        "watch" => {
            let Some(config_path) = arg_of(&args, "--config") else { usage() };
            let cfg = BackupConfig::from_path(&config_path)
                .unwrap_or_else(|e| die(&format!("manifest 装载失败: {e}")));
            let interval = arg_of(&args, "--interval")
                .and_then(|s| s.parse().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(300));
            if let Err(e) = run_watch(cfg, interval) {
                die(&e.to_string());
            }
        }
        "verify" => {
            let Some(snap) = args.get(2) else { usage() };
            let manifest =
                da_backup::verify(snap).unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "[da-backup] 快照完整（{} 文件 / {} bytes / at={}）",
                manifest.files.len(),
                manifest.total_bytes,
                manifest.at
            );
        }
        "restore" => {
            let Some(snap) = args.get(2) else { usage() };
            let Some(into) = arg_of(&args, "--into") else { usage() };
            let rr = da_backup::restore(snap, PathBuf::from(&into))
                .unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "[da-backup] 恢复完成：{} 文件 / {} bytes / RTO={}ms → {}",
                rr.files,
                rr.bytes,
                rr.elapsed_ms,
                rr.into_dir.display()
            );
        }
        _ => usage(),
    }
}

fn die(msg: &str) -> ! {
    eprintln!("[da-backup] {msg}");
    std::process::exit(1);
}
