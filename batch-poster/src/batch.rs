//! 攒批策略与批键派生。
//!
//! ## K 政策（对齐 stark-recursion，全路径消歧 texas/src/starknet/chain.rs）
//!
//! - 上限 64：`stark_recursion::chain::MAX_HANDS_PER_LEAF`
//!   （stark-recursion/src/chain.rs:63）；
//! - 条数 2 的幂：`check_hand_count` 校验（stark-recursion/src/chain.rs:165-175，
//!   keccak 根折叠与 SettleBatch 同约束）；
//! - FoldBatchPlan（stark-recursion/src/chain.rs:388）是批语句面的权威
//!   形态；本模块只做尺寸政策与批键派生，语句面构造归 ProofSource。
//!
//! ## 批键（批级键域，键域闭合）
//!
//! `batch_key = keccak_root`：对 K 条 FoldStatement 按
//! `groth16_wrap::batch::keccak_batch_root` 派生（与 zchain 侧
//! SettleBatch.sol 逐式一致，stark-recursion/src/bin/batch_inputs.rs:11 注
//! 释钉板）——同时是 zchain 侧幂等键与 MonadProofEnvelope 主键；
//! `members` 引用单手键 `(table_id, hand_id)`（单手键只做队列去重）。

use settle_queue::task::FoldStatement;

/// 政策上限（`stark_recursion::chain::MAX_HANDS_PER_LEAF`）。
pub const MAX_BATCH_HANDS: usize = stark_recursion::chain::MAX_HANDS_PER_LEAF;

/// K 政策校验（1..=64 且 2 的幂——chain.rs:165-175 check_hand_count 镜像）。
pub fn check_batch_size(k: usize) -> Result<(), String> {
    if k == 0 {
        return Err("batch must contain at least one hand".into());
    }
    if k > MAX_BATCH_HANDS {
        return Err(format!(
            "batch has {k} hands > MAX_HANDS_PER_LEAF={MAX_BATCH_HANDS}"
        ));
    }
    if !k.is_power_of_two() {
        return Err(format!(
            "batch hand count must be a power of two, got {k}（SettleBatch keccak 根折叠同约束）"
        ));
    }
    Ok(())
}

/// 计划批尺寸：≤ min(count, k_max) 的最大 2 的幂（count=0 → 0）。
pub fn plan_batch_size(count: usize, k_max: usize) -> usize {
    if count == 0 || k_max == 0 {
        return 0;
    }
    let capped = count.min(k_max).min(MAX_BATCH_HANDS);
    // 最大 2 的幂 ≤ capped（capped ≤ 64，无溢出之虞）。
    (capped + 1).next_power_of_two() >> 1
}

/// cadence 判定：攒满 K 立即发；或最老候选等待超过时间窗（op-batcher
/// max-channel-duration 语义）按计划尺寸（≥min）发。
pub fn should_publish(
    count: usize,
    oldest_age_secs: u64,
    cfg: &crate::config::CadenceConfig,
) -> bool {
    if count < cfg.min_batch_hands {
        return false;
    }
    if count >= cfg.max_batch_hands {
        return true; // 攒满 K。
    }
    // 时间窗到期：计划尺寸（最大 2 的幂 ≤ count）仍须 ≥ 触发下限。
    oldest_age_secs >= cfg.max_wait_secs
        && plan_batch_size(count, cfg.max_batch_hands) >= cfg.min_batch_hands
}

use settle_queue::task::SettleKey;

/// fold 批输入（ProofSource 的语句面输入；statements 与 members 一一对应）。
pub struct FoldBatchInput {
    pub members: Vec<SettleKey>,
    pub statements: Vec<FoldStatement>,
    /// 累加链接入（批 n-1 的 fact；首批 0x0 = genesis）。
    pub acc_prev: String,
}

/// 批键派生：keccak_root（同公式 keccak_batch_root；输入须已过
/// [`check_batch_size`]——本函数再次 fail-closed 校验）。
pub fn compute_batch_key(statements: &[FoldStatement]) -> Result<[u8; 32], String> {
    check_batch_size(statements.len())?;
    let stmts: Vec<groth16_wrap::batch::BatchStatement> = statements
        .iter()
        .map(|s| {
            let program_hash = felt_from_hex(&s.program_hash)?;
            let hand_binding = felt_from_hex(&s.hand_binding)?;
            let fact = felt_from_hex(&s.fact)?;
            Ok(groth16_wrap::batch::BatchStatement {
                program_hash,
                hand_binding,
                fact,
            })
        })
        .collect::<Result<_, String>>()?;
    groth16_wrap::batch::keccak_batch_root(&stmts).map_err(|e| e.to_string())
}

/// hex felt → Felt252（groth16-wrap felt_from_hex 包装）。
fn felt_from_hex(s: &str) -> Result<groth16_wrap::Felt252, String> {
    groth16_wrap::felt::felt_from_hex(s).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K 政策：1..=64 且 2 的幂（chain.rs:165-175 镜像）。
    #[test]
    fn batch_size_policy() {
        for ok in [1, 2, 4, 8, 16, 32, 64] {
            assert!(check_batch_size(ok).is_ok(), "k={ok} 应合法");
        }
        for bad in [0, 3, 5, 6, 7, 12, 65, 100, 128] {
            assert!(check_batch_size(bad).is_err(), "k={bad} 应拒绝");
        }
    }

    /// 计划批尺寸：≤ min(count, K) 的最大 2 的幂。
    #[test]
    fn planned_size_is_largest_power_of_two() {
        assert_eq!(plan_batch_size(0, 64), 0);
        assert_eq!(plan_batch_size(1, 64), 1);
        assert_eq!(plan_batch_size(3, 64), 2, "3 手 → 批 2，剩 1 留待下批");
        assert_eq!(plan_batch_size(6, 8), 4);
        assert_eq!(plan_batch_size(6, 4), 4);
        assert_eq!(plan_batch_size(100, 64), 64);
    }

    /// cadence：攒满即发；时间窗到期按计划尺寸发；不足下限不发。
    #[test]
    fn cadence_fires_on_size_or_window() {
        let cfg = crate::config::CadenceConfig {
            max_batch_hands: 8,
            max_wait_secs: 300,
            min_batch_hands: 1,
        };
        // 8 手攒满 K → 发。
        assert!(should_publish(8, 0, &cfg));
        // 4 手（2 的幂但未满 K）窗未到 → 不发（中间尺寸不触发，保攒批）。
        assert!(!should_publish(4, 100, &cfg));
        // 6 手未满、窗未到 → 不发。
        assert!(!should_publish(6, 299, &cfg));
        // 窗到期（planned=4 ≥ min）→ 发。
        assert!(should_publish(6, 300, &cfg));
        // 单手 + 窗到期 → 发（min=1）。
        assert!(should_publish(1, 301, &cfg));
        // min=2 时单手不发。
        let cfg2 = crate::config::CadenceConfig {
            min_batch_hands: 2,
            ..cfg.clone()
        };
        assert!(!should_publish(1, 9999, &cfg2));
    }

    /// 批键派生：同语句集同键（幂等）；条数非 2 的幂 fail-closed。
    #[test]
    fn batch_key_derivation() {
        let stmt = |i: u64| FoldStatement {
            program_hash: format!("0x{i}"),
            hand_binding: format!("0x{:x}", 0x100 + i),
            fact: format!("0x{:x}", 0x200 + i),
        };
        let two = [stmt(1), stmt(2)];
        let k1 = compute_batch_key(&two).unwrap();
        let k2 = compute_batch_key(&two).unwrap();
        assert_eq!(k1, k2, "同语句集同批键（批幂等）");
        let three = [stmt(1), stmt(2), stmt(3)];
        assert!(compute_batch_key(&three).is_err(), "非 2 的幂 fail-closed");
        // 换一条语句 → 键变。
        let other = [stmt(1), stmt(9)];
        assert_ne!(k1, compute_batch_key(&other).unwrap());
    }
}
