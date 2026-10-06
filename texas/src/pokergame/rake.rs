//! 链下抽水（rake）——与链上结算口径逐字对齐：
//! - 公式：`rake = min(pot * rake_bps / 10_000, rake_cap)`（poker_l1 `settle.rs::compute_rake`）
//! - 摊牌（contested）底池才抽；fold-win（uncontested）不抽
//!   （`state_machine.rs::end_without_showdown`、`SettlementPlan::validate`）
//! - 边池分层：仅争夺层（eligible ≥ 2）按比例分摊，余数按层序补齐
//!   （`settlement.rs::allocate_rake`）
//!
//! 参数来源与链上相同的环境变量：`STARKNET_RAKE_BPS` / `STARKNET_RAKE_CAP`，
//! 缺省用 poker_l1 常量，保证链下显示与链上到账一致（唯一解析点——
//! 链下显示、VM 镜像、链上 calldata 全部读这里，防止第二份配置漂移）。

use std::sync::OnceLock;

use poker_l1::contracts::texas_poker::constants::{DEFAULT_RAKE_BPS, DEFAULT_RAKE_CAP};

/// 抽水参数（进程级，从环境变量读一次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RakeParams {
    /// 台费比例（basis points，500 = 5%）。
    pub rake_bps: u16,
    /// 单手牌台费封顶金额。
    pub rake_cap: u64,
}

static RAKE_PARAMS: OnceLock<RakeParams> = OnceLock::new();

/// 进程级抽水参数。首次调用时读环境变量并缓存。
pub fn rake_params() -> &'static RakeParams {
    RAKE_PARAMS.get_or_init(|| RakeParams {
        rake_bps: std::env::var("STARKNET_RAKE_BPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RAKE_BPS),
        rake_cap: std::env::var("STARKNET_RAKE_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RAKE_CAP),
    })
}

/// 计算本手总台费（不修改状态）。u128 中间量避免 `pot * bps` 溢出。
pub fn compute_rake(pot: u64, params: &RakeParams) -> u64 {
    if pot == 0 {
        return 0;
    }
    let by_rate = (u128::from(pot) * u128::from(params.rake_bps) / 10_000) as u64;
    by_rate.min(params.rake_cap).min(pot)
}

/// 把总台费分摊到底池层（镜像链上 `allocate_rake`）。
///
/// `layers` 为 `(层金额, 争夺人数)`，顺序与链上一致：主池在前、边池按层级在后。
/// 仅争夺层（人数 ≥ 2）按 `层金额 / gross_pot` 比例承担；uncontested 层为 0；
/// 整除余数按层序补到争夺层（不超过该层剩余金额）。
///
/// 返回与 `layers` 等长的分摊列表，总和 ≤ `total_rake`
/// （正常对局必有争夺层，余数必然放得下；防御性 saturating，不再panic）。
pub fn allocate_rake(layers: &[(u64, usize)], total_rake: u64, gross_pot: u64) -> Vec<u64> {
    if total_rake == 0 || layers.is_empty() || gross_pot == 0 {
        return vec![0; layers.len()];
    }
    let mut allocations = vec![0u64; layers.len()];
    let mut allocated: u64 = 0;
    for (i, &(amount, eligible)) in layers.iter().enumerate() {
        if eligible >= 2 {
            let share =
                (u128::from(amount) * u128::from(total_rake) / u128::from(gross_pot)) as u64;
            allocations[i] = share;
            allocated = allocated.saturating_add(share);
        }
    }
    let mut remainder = total_rake.saturating_sub(allocated);
    for (i, &(amount, eligible)) in layers.iter().enumerate() {
        if remainder == 0 {
            break;
        }
        if eligible < 2 {
            continue;
        }
        let available = amount.saturating_sub(allocations[i]);
        let take = remainder.min(available);
        allocations[i] += take;
        remainder -= take;
    }
    allocations
}

/// fold-win 抽水（"no flop, no drop" 行业惯例）：
/// - 翻前结束（`flop_seen == false`，board 不足 3 张）：不抽；
/// - 翻后结束：对「被争夺过的钱」抽——底池扣除未跟注返还。未跟注返还 =
///   唯一最高下注（fold-win 下必属赢家，其余人皆弃牌）超出次高下注的部分。
///
/// 与链上 `derive_fold_win_plan` 用同一公式（`poker_l1/settlement.rs`），
/// 前端筹码 / 牌史 / 链上 delta 三本账一致。
///
/// `bets` 为各座位 total_bet（含赢家），`winner_idx` 为赢家在 `bets` 中的下标。
pub fn fold_win_rake(pot: u64, bets: &[u64], winner_idx: usize, flop_seen: bool) -> u64 {
    if !flop_seen || pot == 0 || bets.is_empty() || winner_idx >= bets.len() {
        return 0;
    }
    let second_max = bets
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != winner_idx)
        .map(|(_, b)| *b)
        .max()
        .unwrap_or(0);
    let uncalled = bets[winner_idx].saturating_sub(second_max);
    let contested = pot.saturating_sub(uncalled);
    compute_rake(contested, rake_params())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(bps: u16, cap: u64) -> RakeParams {
        RakeParams { rake_bps: bps, rake_cap: cap }
    }

    #[test]
    fn compute_rake_matches_chain_formula() {
        // 与 poker_l1 settle.rs 测试同参对齐
        assert_eq!(compute_rake(1000, &params(500, 1000)), 50);
        assert_eq!(compute_rake(1000, &params(500, 30)), 30);
        assert_eq!(compute_rake(0, &params(500, 1000)), 0);
        assert_eq!(compute_rake(1000, &params(0, 1000)), 0);
        assert_eq!(compute_rake(100, &params(1000, 10_000)), 10);
    }

    #[test]
    fn allocate_single_contested_layer() {
        // 无边池：整笔 rake 全落在主池
        let allocs = allocate_rake(&[(1000, 2)], 50, 1000);
        assert_eq!(allocs, vec![50]);
    }

    #[test]
    fn allocate_skips_uncontested_layers() {
        // 主池(3人争夺) + 边池(1人独占)：边池不承担
        let allocs = allocate_rake(&[(600, 3), (400, 1)], 50, 1000);
        assert_eq!(allocs, vec![50, 0]);
    }

    #[test]
    fn allocate_pro_rata_with_remainder() {
        // 1000 总池，rake 50：主池 600 → 30，边池 400 → 20，无余数
        let allocs = allocate_rake(&[(600, 2), (400, 2)], 50, 1000);
        assert_eq!(allocs, vec![30, 20]);
        // 700/300，rake 51：333…→ 35 与 15（整除向下），余数 1 补到首个争夺层
        let allocs = allocate_rake(&[(700, 2), (300, 2)], 51, 1000);
        assert_eq!(allocs[0] + allocs[1], 51);
        assert_eq!(allocs, vec![36, 15]);
    }

    #[test]
    fn allocate_zero_rake() {
        assert_eq!(allocate_rake(&[(1000, 2)], 0, 1000), vec![0]);
    }

    /// 2026-09-04 审核发现：台费基数 = 争夺层总额（链上 contested_gross），
    /// 未跟注返还层不参与。1000 池 = 主池 600 争夺 + 400 未跟注返还：
    /// 链上抽 600×5% = 30（非 50），且全落主池。
    #[test]
    fn rake_base_excludes_uncontested_layer() {
        let layers = [(600u64, 2usize), (400, 1)];
        let contested_gross = layers.iter()
            .filter(|(_, e)| *e >= 2)
            .map(|(a, _)| a)
            .sum::<u64>();
        assert_eq!(contested_gross, 600);
        let rake = compute_rake(contested_gross, &params(500, 1000));
        assert_eq!(rake, 30);
        assert_eq!(allocate_rake(&layers, rake, contested_gross), vec![30, 0]);
    }

    // ---- fold-win 抽水（"no flop, no drop"）----

    /// 翻前结束（盲注偷池等）：无论底池多大都不抽。
    #[test]
    fn fold_win_preflop_never_raked() {
        // SB 10 + BB 20，BB 弃牌给 SB 的加注：翻前，不抽。
        assert_eq!(fold_win_rake(30, &[30, 20], 0, false), 0);
        // 大底池翻前同样不抽。
        assert_eq!(fold_win_rake(900, &[700, 200], 0, false), 0);
    }

    /// 翻后 fold-win：未跟注返还部分不抽。
    /// A 下注 300，B 跟到 100 后在翻牌弃牌：底池 400，未跟注 200，
    /// 争夺部分 200 → 抽 5% = 10。
    #[test]
    fn fold_win_postflop_excludes_uncalled() {
        assert_eq!(fold_win_rake(400, &[300, 100], 0, true), 10);
    }

    /// 翻后 fold-win：等额互跟（无未跟注返还）全额抽。
    #[test]
    fn fold_win_postflop_equal_bets_full_base() {
        assert_eq!(fold_win_rake(400, &[200, 200], 0, true), 20);
    }

    /// 三人局：次高下注取所有非赢家中的最大值（不是次大排序值的第二位）。
    /// bets [500(winner), 300, 100]：未跟注 = 500-300 = 200，争夺 = 700 → 35。
    #[test]
    fn fold_win_second_max_over_all_others() {
        assert_eq!(fold_win_rake(900, &[500, 300, 100], 0, true), 35);
    }

    /// 单一贡献者（其余全弃未投入）：争夺部分 0，不抽。
    #[test]
    fn fold_win_single_contributor_zero() {
        assert_eq!(fold_win_rake(500, &[500, 0, 0], 0, true), 0);
    }

    /// 上限封顶：200 底池全争夺，5% = 10 超 cap(此处用大额验证 min 路径）。
    #[test]
    fn fold_win_respects_cap() {
        // 2,000,000 全争夺，5% = 100,000 > cap 1000 → 1000。
        assert_eq!(fold_win_rake(2_000_000, &[1_000_000, 1_000_000], 0, true), 1000);
    }

    /// 零底池 / 越界下标防御：0。
    #[test]
    fn fold_win_zero_pot_and_bounds() {
        assert_eq!(fold_win_rake(0, &[0, 0], 0, true), 0);
        assert_eq!(fold_win_rake(100, &[100], 5, true), 0);
    }
}
