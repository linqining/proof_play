//! da-backup——DA L0：WAL/收据/队列 WAL 异地快照备份（M2 硬门槛，
//! 排期 §2.2）。
//!
//! 面向**第二块盘 / 对象存储挂载点**的推式快照：`run_once` 把配置的
//! 数据面（queue WAL、poster sidecar、appchain WAL 目录、spool 工件等）
//! 整体拷入 `dest/snap-<at>-<pid>/`，逐文件 SHA-256 写 `MANIFEST.json`，
//! 按 retention 轮换旧快照；`verify` 独立复核快照完整性；`restore`
//! 恢复到目标目录并输出耗时（恢复演练 RTO 实测口径——押后项「DA L0
//! 恢复演练 RTO>24h / 月成本超预算」以此为测量面）。
//!
//! ## 一致性边界（诚实声明）
//!
//! 快照是**崩溃一致性近似**：拷贝期间源文件可能仍在追加（JSONL/WAL
//! 尾部可能撕裂）。恢复的安全性由各消费方的重放容忍兜底——settle-queue
//! WAL 重放自带撕裂尾行修复；sequencer WAL 同为帧日志。verify 只对
//! **快照内部**做逐字节复核（拷贝完成后哈希，不受后续追加影响）。
//!
//! ## 覆盖面
//!
//! prove_log 为进程内存态（单一状态架构，无落盘文件）——不在备份面；
//! 实际落盘物以部署 manifest 为准（queue WAL / sidecar / appchain WAL
//! / spool），缺省清单见 docs/BATCH_POSTER_OPS.md DA 节。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// 单个备份源（文件或目录，递归）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSource {
    /// 逻辑名（快照内子目录名；稳定——恢复时按名回放）。
    pub name: String,
    pub path: PathBuf,
}

/// 备份配置（JSON 载体；部署单元 env 文件旁一份 manifest）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupConfig {
    /// 快照目的地（第二块盘挂载点 / 对象存储挂载）。
    pub dest_dir: PathBuf,
    /// 保留快照数（超出删最旧；0 = 不轮换）。
    pub retention: usize,
    pub sources: Vec<BackupSource>,
}

impl BackupConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, BackupError> {
        let raw = std::fs::read_to_string(path)?;
        serde_json::from_str(&raw).map_err(BackupError::Json)
    }

    pub fn to_json(&self) -> Result<String, BackupError> {
        serde_json::to_string_pretty(self).map_err(BackupError::Json)
    }
}

/// 快照内单文件记录（校验面）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupFile {
    /// 源逻辑名。
    pub source: String,
    /// 快照内相对路径（`<name>/<rel>`，目录分隔符 `/`）。
    pub rel: String,
    /// SHA-256（hex 64）。
    pub sha256: String,
    pub bytes: u64,
}

/// 快照清单（`MANIFEST.json`，原子写）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// 快照时刻（unix 秒，调用方注入——测试确定性）。
    pub at: u64,
    pub files: Vec<BackupFile>,
    pub total_bytes: u64,
    /// 生成器标识（bin 版本随行，跨版本排查用）。
    pub generator: String,
}

/// 一次快照的报告。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub snapshot_dir: PathBuf,
    pub manifest: BackupManifest,
}

/// 恢复演练报告（RTO 实测口径）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreReport {
    pub files: usize,
    pub bytes: u64,
    /// 恢复耗时（毫秒；调用方计时注入的起止差）。
    pub elapsed_ms: u128,
    pub into_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("快照缺失清单：{0}")]
    NoManifest(PathBuf),
    #[error("校验失败：{0}（快照损坏/被改——restore 拒绝）")]
    Tampered(String),
    #[error("配置非法：{0}")]
    Config(String),
}

/// 生成器标识（bin/库同源）。
pub const GENERATOR: &str = concat!("da-backup ", env!("CARGO_PKG_VERSION"));

/// 执行一次快照（同步阻塞拷贝——数据面量级 MB/GB 级，调用方放定时器
/// 或 watch 循环）。
pub fn run_once(cfg: &BackupConfig, at: u64) -> Result<BackupReport, BackupError> {
    if cfg.sources.is_empty() {
        return Err(BackupError::Config("sources 为空——无可备份面".into()));
    }
    if cfg.dest_dir.as_os_str().is_empty() {
        return Err(BackupError::Config("dest_dir 未配置".into()));
    }
    // 快照目录：零填充时间戳 + pid（同秒多实例不撞；字典序 = 时间序）。
    let snap = cfg
        .dest_dir
        .join(format!("snap-{:020}-{}", at, std::process::id()));
    std::fs::create_dir_all(&snap)?;
    let mut files: Vec<BackupFile> = Vec::new();
    for src in &cfg.sources {
        if src.name.contains('/') || src.name.contains("..") {
            return Err(BackupError::Config(format!(
                "source name {} 非法（不得含路径分隔符/..）",
                src.name
            )));
        }
        if !src.path.exists() {
            // 缺席源跳过并继续（dev 面可能未开 appchain；prod manifest
            // 由部署方把关——缺文件本身在 verify/restore 面即不可见）。
            continue;
        }
        if src.path.is_file() {
            let rel = format!("{}/{}", src.name, file_name(&src.path));
            let dst = snap.join(&rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let bytes = copy_file(&src.path, &dst)?;
            let digest = sha256_file(&dst)?;
            files.push(BackupFile {
                source: src.name.clone(),
                rel,
                sha256: digest,
                bytes,
            });
        } else {
            copy_dir(src, &snap, &mut files)?;
        }
    }
    let total_bytes = files.iter().map(|f| f.bytes).sum();
    let manifest = BackupManifest {
        at,
        files,
        total_bytes,
        generator: GENERATOR.into(),
    };
    atomic_write_json(&snap.join("MANIFEST.json"), &manifest)?;
    rotate(&cfg.dest_dir, cfg.retention)?;
    Ok(BackupReport {
        snapshot_dir: snap,
        manifest,
    })
}

/// 复核快照（MANIFEST 逐文件重哈希；任何缺失/改写 fail-closed）。
pub fn verify(snap_dir: impl AsRef<Path>) -> Result<BackupManifest, BackupError> {
    let snap = snap_dir.as_ref();
    let manifest_path = snap.join("MANIFEST.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|_| BackupError::NoManifest(snap.to_path_buf()))?;
    let manifest: BackupManifest = serde_json::from_str(&raw)?;
    for f in &manifest.files {
        let p = snap.join(&f.rel);
        let actual = sha256_file(&p).map_err(|_| {
            BackupError::Tampered(format!("{} 缺失或不可读", f.rel))
        })?;
        if actual != f.sha256 {
            return Err(BackupError::Tampered(format!(
                "{} 哈希不符（manifest {} ≠ 实际 {actual}）",
                f.rel, f.sha256
            )));
        }
        let size = std::fs::metadata(&p)?.len();
        if size != f.bytes {
            return Err(BackupError::Tampered(format!(
                "{} 尺寸不符（manifest {} ≠ 实际 {size}）",
                f.rel, f.bytes
            )));
        }
    }
    Ok(manifest)
}

/// 恢复演练：快照 → 目标目录（`<into>/<source>/<rel-tail>`，与源布局
/// 对齐），恢复后先 verify 再计 RTO。
pub fn restore(
    snap_dir: impl AsRef<Path>,
    into_dir: impl AsRef<Path>,
) -> Result<RestoreReport, BackupError> {
    let started = std::time::Instant::now();
    let manifest = verify(&snap_dir)?;
    let into = into_dir.as_ref();
    std::fs::create_dir_all(into)?;
    for f in &manifest.files {
        let src = snap_dir.as_ref().join(&f.rel);
        // rel 首段 = source 逻辑名，回放保持 `<into>/<name>/<rel 剩余>`。
        let rel_tail = f
            .rel
            .split_once('/')
            .map(|(_, tail)| tail)
            .unwrap_or(&f.rel);
        let dst = into.join(&f.source).join(rel_tail);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&src, &dst)?;
    }
    Ok(RestoreReport {
        files: manifest.files.len(),
        bytes: manifest.total_bytes,
        elapsed_ms: started.elapsed().as_millis(),
        into_dir: into.to_path_buf(),
    })
}

/// 轮换：按目录名（零填充时间戳）升序保留最新 `keep` 个 snap-*。
pub fn rotate(dest_dir: impl AsRef<Path>, keep: usize) -> Result<Vec<PathBuf>, BackupError> {
    let mut snaps: Vec<PathBuf> = std::fs::read_dir(dest_dir.as_ref())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("snap-"))
        })
        .collect();
    snaps.sort();
    if keep == 0 || snaps.len() <= keep {
        return Ok(Vec::new());
    }
    let doomed = snaps.len() - keep;
    let removed = snaps[..doomed].to_vec();
    for p in &removed {
        std::fs::remove_dir_all(p)?;
    }
    Ok(removed)
}

// ---------- 内部 ----------

fn copy_dir(
    src: &BackupSource,
    snap: &Path,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    // 相对路径集合（BTreeMap 保序稳定——manifest 可重现）。
    let mut rels: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();
    walk(&src.path, &src.path, &mut rels)?;
    for (abs, rel) in rels {
        let rel_str = format!("{}/{}", src.name, rel.to_string_lossy().replace('\\', "/"));
        let dst = snap.join(&rel_str);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = copy_file(&abs, &dst)?;
        files.push(BackupFile {
            source: src.name.clone(),
            rel: rel_str,
            sha256: sha256_file(&dst)?,
            bytes,
        });
    }
    Ok(())
}

fn walk(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<(), BackupError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            walk(root, &p, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| BackupError::Config(format!("walk 前缀剥离: {e}")))?
                .to_path_buf();
            out.insert(p, rel);
        }
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<u64, BackupError> {
    std::fs::copy(from, to).map_err(BackupError::from)
}

fn sha256_file(path: &Path) -> Result<String, BackupError> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), BackupError> {
    let body = serde_json::to_vec_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json: {e}")))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("da-backup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cfg_for(data: &Path, dest: &Path, retention: usize) -> BackupConfig {
        BackupConfig {
            dest_dir: dest.to_path_buf(),
            retention,
            sources: vec![
                BackupSource {
                    name: "queue".into(),
                    path: data.join("queue.jsonl"),
                },
                BackupSource {
                    name: "appchain".into(),
                    path: data.join("appchain"),
                },
            ],
        }
    }

    fn seed(data: &Path) {
        std::fs::create_dir_all(data.join("appchain/nested")).unwrap();
        std::fs::write(data.join("queue.jsonl"), b"{\"seq\":1}\n{\"seq\":2}\n").unwrap();
        std::fs::write(data.join("appchain/sequencer.wal"), b"frame-0\nframe-1\n").unwrap();
        std::fs::write(
            data.join("appchain/nested/seed.hex"),
            b"0123456789abcdef",
        )
        .unwrap();
    }

    /// 快照：文件 + 目录递归入 manifest、哈希可复核、verify 通过。
    #[test]
    fn snapshot_manifest_and_verify() {
        let dir = tmp("snap");
        let (data, dest) = (dir.join("data"), dir.join("dest"));
        seed(&data);
        let cfg = cfg_for(&data, &dest, 3);
        let report = run_once(&cfg, 1_000).unwrap();
        assert_eq!(report.manifest.files.len(), 3, "1 文件 + 2 目录文件");
        assert_eq!(report.manifest.total_bytes, 20 + 16 + 16);
        // 独立复核通过。
        let back = verify(&report.snapshot_dir).unwrap();
        assert_eq!(back, report.manifest);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 篡改检测：改一个字节 verify 即 fail-closed。
    #[test]
    fn tamper_detected() {
        let dir = tmp("tamper");
        let (data, dest) = (dir.join("data"), dir.join("dest"));
        seed(&data);
        let cfg = cfg_for(&data, &dest, 3);
        let report = run_once(&cfg, 1_000).unwrap();
        let target = report.snapshot_dir.join("queue/queue.jsonl");
        std::fs::write(&target, b"tampered").unwrap();
        let err = verify(&report.snapshot_dir).unwrap_err();
        assert!(matches!(err, BackupError::Tampered(_)), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 轮换：retention 之外的最旧快照被删（零填充名 = 时间序）。
    #[test]
    fn rotation_keeps_newest() {
        let dir = tmp("rotate");
        let (data, dest) = (dir.join("data"), dir.join("dest"));
        seed(&data);
        let cfg = cfg_for(&data, &dest, 2);
        run_once(&cfg, 1_000).unwrap();
        run_once(&cfg, 2_000).unwrap();
        run_once(&cfg, 3_000).unwrap();
        let snaps: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        assert_eq!(snaps.len(), 2, "retention=2");
        assert!(snaps.iter().any(|n| n.contains("00000000000000003000")));
        assert!(!snaps.iter().any(|n| n.contains("00000000000000001000")));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 恢复演练：恢复树与源逐字节一致（布局按 source 名回放）+ RTO 报告。
    #[test]
    fn restore_replays_layout() {
        let dir = tmp("restore");
        let (data, dest) = (dir.join("data"), dir.join("dest"));
        seed(&data);
        let cfg = cfg_for(&data, &dest, 3);
        let report = run_once(&cfg, 1_000).unwrap();
        let into = dir.join("restored");
        let rr = restore(&report.snapshot_dir, &into).unwrap();
        assert_eq!(rr.files, 3);
        assert_eq!(std::fs::read(into.join("queue/queue.jsonl")).unwrap(), b"{\"seq\":1}\n{\"seq\":2}\n");
        assert_eq!(
            std::fs::read(into.join("appchain/nested/seed.hex")).unwrap(),
            b"0123456789abcdef"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 空源 / 非法名 fail-closed；缺席源跳过（dev 面 appchain 未开）。
    #[test]
    fn config_and_missing_source_edges() {
        let dir = tmp("edges");
        let (data, dest) = (dir.join("data"), dir.join("dest"));
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("queue.jsonl"), b"x").unwrap();
        let mut cfg = cfg_for(&data, &dest, 3);
        cfg.sources.clear();
        assert!(matches!(
            run_once(&cfg, 1).unwrap_err(),
            BackupError::Config(_)
        ));
        cfg.sources = vec![BackupSource {
            name: "appchain".into(),
            path: data.join("appchain"),
        }];
        let report = run_once(&cfg, 1).unwrap();
        assert!(report.manifest.files.is_empty(), "缺席源跳过不报错");
        cfg.sources = vec![BackupSource {
            name: "bad/name".into(),
            path: data.join("queue.jsonl"),
        }];
        assert!(matches!(
            run_once(&cfg, 2).unwrap_err(),
            BackupError::Config(_)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
