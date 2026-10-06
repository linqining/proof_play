//! 架构守卫：纯核心状态机（`core/`）的纯度与边界强制（分层架构 L2）。
//!
//! 目标拓扑（2026-09-09 划界）：
//!
//! ```text
//! 游戏运行时(texas) → 链运行时(runtime/) → 纯核心状态机(core/)
//! ```
//!
//! 本测试扫描 `src/contracts/texas_poker/core/` 全部源码，强制三条规则：
//!
//! 1. **纯度**：核心不含时钟（`std::time`/`SystemTime`/`Instant`）、IO
//!    （`std::fs`/`std::net`/`std::io`）、异步运行时（`tokio`）；随机数只
//!    允许出现在缩进的 `#[cfg(test)]` 模块内（顶层 `use rand` 拒绝）。
//! 2. **依赖方向**：核心不得引用 runtime 模块（`dispatch`/`prove_task`/
//!    `state_codec`）——依赖恒为 runtime → core。
//! 3. **清单一致**：`core/mod.rs` 的 `pub mod` 声明与目录文件一一对应，
//!    防止绕过清单私加文件。
//!
//! 注释行（`//`/`//!`）跳过；违例直接 panic 并给出文件：行号。

use std::path::{Path, PathBuf};

const CORE_DIR: &str = "src/contracts/texas_poker/core";

/// 全文禁止的子串（核心必须零出现——含测试代码，测试也不该碰时钟/IO）。
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "std::time",
    "SystemTime",
    "Instant::",
    "std::fs",
    "std::net",
    "std::io",
    "tokio::",
];

/// 仅在顶层（未缩进的 `use rand ...`）禁止：测试模块内缩进使用放行。
const FORBIDDEN_TOPLEVEL_USES: &[&str] = &["use rand"];

/// 核心引用 runtime 模块的模式（依赖方向违例）。
const FORBIDDEN_RUNTIME_REFS: &[&str] = &[
    "super::dispatch",
    "super::prove_task",
    "super::state_codec",
    "super::runtime",
    "texas_poker::dispatch",
    "texas_poker::prove_task",
    "texas_poker::state_codec",
    "texas_poker::runtime",
];

fn core_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CORE_DIR)
}

fn core_files() -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(core_dir())
        .expect("core/ directory exists")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "core/ directory must contain sources");
    files
}

fn is_comment_line(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
}

#[test]
fn core_is_pure_no_clock_io_async() {
    for file in core_files() {
        let content = std::fs::read_to_string(&file).expect("read core source");
        for (idx, line) in content.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            for pat in FORBIDDEN_SUBSTRINGS {
                assert!(
                    !line.contains(pat),
                    "core purity violation at {}:{}: contains `{pat}` — 时钟/IO/异步只允许 runtime 层\n  line: {line}",
                    file.display(),
                    idx + 1,
                );
            }
            let trimmed = line.trim_start();
            for pat in FORBIDDEN_TOPLEVEL_USES {
                if trimmed.starts_with(pat) && !line.starts_with(char::is_whitespace) {
                    panic!(
                        "core purity violation at {}:{}: 顶层 `{pat}` — 随机数只允许在 #[cfg(test)] 模块内（缩进）使用\n  line: {line}",
                        file.display(),
                        idx + 1,
                    );
                }
            }
        }
    }
}

#[test]
fn core_never_references_runtime_modules() {
    for file in core_files() {
        let content = std::fs::read_to_string(&file).expect("read core source");
        for (idx, line) in content.lines().enumerate() {
            if is_comment_line(line) {
                continue;
            }
            for pat in FORBIDDEN_RUNTIME_REFS {
                assert!(
                    !line.contains(pat),
                    "dependency-direction violation at {}:{}: core 引用了 runtime 模块 `{pat}` — 依赖必须恒为 runtime → core\n  line: {line}",
                    file.display(),
                    idx + 1,
                );
            }
        }
    }
}

#[test]
fn core_mod_rs_manifest_matches_directory() {
    let mod_rs = std::fs::read_to_string(core_dir().join("mod.rs")).expect("core/mod.rs exists");
    let declared: Vec<String> = mod_rs
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            t.strip_prefix("pub mod ")
                .map(|rest| rest.trim_end_matches(';').trim().to_string())
        })
        .collect();

    let on_disk: Vec<String> = core_files()
        .iter()
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().to_string()))
        .filter(|name| name != "mod")
        .collect();

    for name in &on_disk {
        assert!(
            declared.contains(name),
            "core/{name}.rs 存在但未在 core/mod.rs 声明 `pub mod {name};` — 私加文件必须登记"
        );
    }
    for name in &declared {
        assert!(
            on_disk.contains(name),
            "core/mod.rs 声明了 `pub mod {name};` 但文件不存在"
        );
    }
}
