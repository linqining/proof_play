//! 内存纪律：每步峰值锚点（实测引注）+ fail-closed 步骤闸门。
//!
//! # 锚点（全部为 ask 材料/工程报告的实测数字，出处逐条标注；未测项如实标 None）
//!
//! | 步骤 | 峰值 | 来源 |
//! |---|---|---|
//! | 叶电路证明（padding qm31_ops 2^23） | 19.4 GB（20,819,279,872 B） | leaf-prover 独立进程 /usr/bin/time -l 实测（架构 §内存上界表） |
//! | 折叠（两两折叠/根折叠同形状） | 7.4 GB（7,909,834,752 B） | test_fold_two_leaves /usr/bin/time -l 实测（架构 §2 本轮亲跑） |
//! | 叶+折叠同进程 | 21.9 GB（21,931,687,936 B） | 4-leaf golden e2e 实测 → **叶/折叠必须分进程**（本 crate 的 [`crate::backend::CliBackend`] 每步一个子进程即执行面） |
//! | 批 Cairo 证明 K=1（canonical_small 钉扎参数） | 1.87 GiB（2,011,987,968 B）/ 1.94 GiB | prove-hand /usr/bin/time -l 实测（2026-09-29，本机 36GB） |
//! | 批 Cairo 证明 K=64（canonical_small 钉扎参数） | **3.69 GiB（3,959,144,448 B）** | 同上；555,223 steps / prove 4.5s —— L1 腿 E2E 实测，低于 6G 硬约束 |
//! | 批 Cairo 证明 K=1（canonical 预处理迹，**弃用对照**） | 9.55-12.9 GiB | 同程序同日实测——canonical 预处理迹 543,100,528 cells 是内存大头，**canonical_small 钉扎（10,161,776 cells）是 ≤6G 的成立前提** |
//! | 根证明产物 | 1.5 MB（377K felts，与 N 无关） | 4-leaf e2e proof_size_estimate=377,264 实测 |
//! | 终证腿（scarb 2.18 run 的 prove） | 未测 | 依赖 scarb 2.18（本机 2.11.4 解析不了 stwo_cairo_verifier workspace）——部署前 E2E 测 |
//! | Groth16 终证包裹（本 crate 电路） | 未单测峰值；约束 < 单手 4.58M（同量级） | 单手 4.58M 在 36GB 机稳定、K=4=18.3M 稳定、K=8=36.7M SIGKILL（report §4/§5）→ 本电路峰值低于 K=4 批量 |
//!
//! # 服务器上界（硬约束）
//!
//! stark：7.3 GB RAM / 4 核 → **叶证明腿（19.4 GB）不可在 stark 裸跑**；
//! 折叠腿 7.4 GB 贴近上界（需 cgroup 放行 + 无并发）。[`check_step`] 按此
//! fail-closed：配额不足直接拒绝，不靠 OOM 杀进程兜底。

use anyhow::{anyhow, Result};

/// 叶证明腿峰值（leaf-prover 实测 20,819,279,872 B）。
pub const LEAF_PROVE_PEAK_BYTES: u64 = 20_819_279_872;
/// 折叠腿峰值（test_fold_two_leaves 实测 7,909,834,752 B）。
pub const FOLD_PEAK_BYTES: u64 = 7_909_834_752;
/// 叶+折叠同进程峰值（4-leaf e2e 实测 21,931,687,936 B）——同进程形态被此数否决。
pub const LEAF_FOLD_SAME_PROCESS_PEAK_BYTES: u64 = 21_931_687_936;
/// L1 批证明腿（canonical_small 钉扎参数）K=64 实测峰值（/usr/bin/time -l，
/// 2026-09-29）。K=1 同参数实测 2,011,987,968 B；canonical 参数对照实测
/// 9.55-12.9 GB（弃用）。全部 <6G 硬约束。
pub const CAIRO_PROVE_K64_MEASURED_BYTES: u64 = 3_959_144_448;
/// stark 服务器物理内存（实测 7459 MB，架构 §2 亲跑 ssh 只读）。
pub const STARK_RAM_BYTES: u64 = 7_459 * 1024 * 1024;

/// 聚合链的步骤。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// 批 Cairo 证明（prove-hand --params registry）。
    CairoProve,
    /// 叶电路证明（leaf-prover）。
    LeafProve,
    /// 折叠树（stwo_run_and_prove_recursive_tree，含根折叠）。
    Fold,
    /// 终证腿（scarb 2.18 execute/prove，峰值未测）。
    FinalProof,
    /// Groth16 终证包裹（本 crate 电路，<4.58M 约束）。
    RootWrap,
}

impl Step {
    /// 已实测的峰值锚点；None = 未测（闸门只告警不拒绝，见 [`check_step`]）。
    #[must_use]
    pub fn measured_peak_bytes(self) -> Option<u64> {
        match self {
            Step::CairoProve => Some(CAIRO_PROVE_K64_MEASURED_BYTES), // K=64 实测（K≤64 批的保守上界）
            Step::LeafProve => Some(LEAF_PROVE_PEAK_BYTES),
            Step::Fold => Some(FOLD_PEAK_BYTES),
            Step::FinalProof => None, // 未测（scarb 2.18 腿）
            Step::RootWrap => None,   // <4.58M 约束同量级；未单测峰值
        }
    }

    /// 该步骤是否必须独占进程（叶+折叠同进程实测 21.9GB 被否决）。
    #[must_use]
    pub fn requires_own_process(self) -> bool {
        matches!(self, Step::CairoProve | Step::LeafProve | Step::Fold | Step::FinalProof)
    }
}

/// 步骤闸门：实测锚点 > 配额 → 拒绝（fail-closed）；未测锚点 → 放行但提示
/// （不伪造安全声明）。
///
/// # Errors
/// [`Step::LeafProve`] / [`Step::Fold`] 在配额低于实测峰值时。
pub fn check_step(step: Step, available_bytes: u64) -> Result<()> {
    match step.measured_peak_bytes() {
        Some(peak) if peak > available_bytes => Err(anyhow!(
            "step {step:?} needs measured peak {peak} bytes > available {available_bytes} bytes（fail-closed；另起更大内存机器或加 swap 前不得开跑）"
        )),
        Some(_peak) => Ok(()),
        None => Ok(()), // 未测步骤：不拒绝也不担保（注释见模块表）
    }
}

/// stark 服务器上能否跑该步骤（7.3 GB 口径）。
#[must_use]
pub fn fits_stark(step: Step) -> bool {
    check_step(step, STARK_RAM_BYTES).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 实测锚点引注的数值不变（防手滑改错实测数）。
    #[test]
    fn anchors_match_measured_values() {
        assert_eq!(LEAF_PROVE_PEAK_BYTES, 20_819_279_872, "leaf-prover /usr/bin/time 实测");
        assert_eq!(FOLD_PEAK_BYTES, 7_909_834_752, "test_fold_two_leaves 实测");
        assert_eq!(LEAF_FOLD_SAME_PROCESS_PEAK_BYTES, 21_931_687_936, "4-leaf e2e 实测");
        // 叶腿在 stark（7.3G）不可跑；折叠腿 7.37GB 同样越过 7459MB 物理线 ——
        // 如实结论：stark 裸跑两腿都过不了闸门，需 swap/cgroup 放行或更大内存机器
        assert!(!fits_stark(Step::LeafProve), "叶腿 19.4GB 不得在 stark 裸跑");
        assert!(
            !fits_stark(Step::Fold),
            "折叠腿实测 7.37GB > stark 7459MB（7.23GiB）物理线 —— 闸门拒绝是预期，扩配额前不得开跑"
        );
        assert!(fits_stark(Step::Fold) == check_step(Step::Fold, STARK_RAM_BYTES).is_ok());
        // L1 批证明腿（canonical_small 钉扎）：K=64 实测 3.69GiB —— stark 可跑、6G 内
        assert_eq!(CAIRO_PROVE_K64_MEASURED_BYTES, 3_959_144_448, "K=64 实测锚点不变");
        assert!(fits_stark(Step::CairoProve), "L1 批腿 K=64 实测 3.69GiB < stark 7.3G（canonical_small 前提）");
        assert!(check_step(Step::CairoProve, 3 * 1024 * 1024 * 1024).is_err(), "<K=64 实测峰值的配额必须拒绝");
    }

    /// 闸门 fail-closed：配额不足拒绝、充裕放行、未测步骤放行（不担保）。
    #[test]
    fn check_step_gate() {
        assert!(check_step(Step::LeafProve, 24 * 1024 * 1024 * 1024).is_ok());
        assert!(check_step(Step::LeafProve, 8 * 1024 * 1024 * 1024).is_err());
        assert!(check_step(Step::Fold, 8 * 1024 * 1024 * 1024).is_ok());
        assert!(check_step(Step::Fold, 4 * 1024 * 1024 * 1024).is_err());
        // 未测步骤：放行（注释口径），不 panic；已测步骤 0 配额拒绝
        assert!(check_step(Step::CairoProve, 0).is_err(), "已测步骤 0 配额 fail-closed");
        assert!(check_step(Step::FinalProof, 0).is_ok());
        assert!(check_step(Step::RootWrap, 0).is_ok());
    }
}
