//! Texas Poker 边池分层算法。
//!
//! 逐层切片 all-in 玩家的 bet 水位，构造多个 [`SidePot`]。
//!
//! # AIR/Trace 友好设计（原"电路友好"，SNARK → Stwo 迁移后重述）
//!
//! - `eligible_seats` 用 `u16` 位掩码（MAX_PLAYERS=9，9 bit 足够），第 j 位为 1
//!   表示 seat j eligible。定长、无动态分配、无 panic 路径；9-bit mask 可由
//!   canonical AIR 的逐位分解/one-hot 选择子直接承载。
//! - `SidePotResult.pots` 为**固定 9 槽数组 + 有效层数 `pot_count`**（含主池
//!   作为 `pots[0]`），`pots[pot_count..]` 是 canonical 空槽
//!   `SidePot::new(0, 0)`——输出定宽，可直接排 AIR 列（参照 `texas_canonical`
//!   的 `MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS` 模式）。
//! - **无排序**：all-in 水位经 O(n²) 两两比较求秩（同额按座位号破平，秩
//!   单射），按秩落入固定槽位——槽序即升序，无需排序网络/lookup。切片
//!   循环定界 9 次迭代，每步只有 min/max/减法与逐座位 eligible 谓词。
//! - 无单层溢出保护（`sum_bets` 已做全局上界校验，单层 pot 必然 <= total）。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::constants::{MAX_PLAYERS, MAX_TOTAL_BET};

/// 固定 pot 层槽位数（= 座位数上限：互异 all-in 水位数 ≤ all-in 座位数 ≤ 9，
/// 最外层超额与最后一层水位重合时金额为 0 不成层，故层数上限即 9）。
pub const MAX_SIDE_POTS: usize = MAX_PLAYERS as usize;

// ========== 位掩码辅助 ==========

/// 构造 eligible 位掩码：第 j 位置 1。
const fn seat_bit(j: u8) -> u16 {
    1u16 << j
}

/// 位掩码工具：测试第 j 位是否置 1。
#[must_use]
pub const fn is_eligible(mask: u16, seat: u8) -> bool {
    (mask & seat_bit(seat)) != 0
}

// ========== 数据结构 ==========

/// 单层 pot（主池或边池）。
///
/// `eligible_seats` 为 `u16` 位掩码：第 j 位为 1 表示 seat j 有资格争夺该层。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SidePot {
    /// 该层 pot 总金额。
    pub amount: u64,
    /// 有资格争夺该层 pot 的座位位掩码（bit j = 1 → seat j eligible）。
    pub eligible_seats: u16,
}

impl SidePot {
    /// 构造新 SidePot。
    #[must_use]
    pub const fn new(amount: u64, eligible_seats: u16) -> Self {
        Self {
            amount,
            eligible_seats,
        }
    }

    /// 判断指定座位是否 eligible。
    #[must_use]
    pub const fn is_eligible(&self, seat: u8) -> bool {
        is_eligible(self.eligible_seats, seat)
    }
}

/// 边池计算错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SidePotError {
    /// 总下注超过 MAX_TOTAL_BET（溢出保护）。
    #[error("total bets exceed MAX_TOTAL_BET, possible overflow")]
    BetOverflow,
    /// bets/folded/all_in 三个向量长度不一致。
    #[error("bets/folded/all_in vectors must have same length")]
    LengthMismatch,
}

/// 边池计算结果。
///
/// `pots` 为固定 [`MAX_SIDE_POTS`] 槽数组，`pots[0..pot_count]` 按水位升序
/// 携带活跃层（主池恒为 `pots[0]`，即使无人 all-in 也至少一层），
/// `pots[pot_count..]` 为 canonical 空槽 `SidePot::new(0, 0)`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidePotResult {
    /// 所有 pot 层槽位（含主池 pots[0]；空槽全零）。
    pub pots: [SidePot; MAX_SIDE_POTS],
    /// 活跃层数（≥ 1）。
    pub pot_count: u8,
}

impl SidePotResult {
    /// 活跃层切片（`pots[0..pot_count]`）。
    #[must_use]
    pub fn active(&self) -> &[SidePot] {
        &self.pots[..usize::from(self.pot_count)]
    }

    /// 返回所有 pot 层的总额（空槽金额为 0，不影响求和）。
    #[must_use]
    pub fn total(&self) -> u64 {
        self.pots.iter().map(|p| p.amount).sum()
    }
}

// ========== 核心算法 ==========

/// 计算边池分层。
///
/// # 参数
/// - `bets`：每个座位的总下注
/// - `folded`：每个座位是否已 fold
/// - `all_in`：每个座位是否 all-in
///
/// # 算法（定宽、无排序、无 panic 路径）
/// 1. 计算总下注 `total_pot`（含上界校验）。
/// 2. 对每个 all-in 座位（bet > 0），用 O(n²) 两两比较求秩：秩 = 严格小于
///    它的水位数 + 同额时座位号更小的数量（单射）；按秩写入固定 9 槽
///    `levels`——槽序即水位升序，替代 `sort`（AIR 中排序需要排序网络/
///    lookup，秩求和只是线性累加 + 有界比较）。
/// 3. 逐槽切片 `amount_j = Σ_i max(0, min(bet_i, level_j) − level_{j−1})`，
///    eligible 逐座位谓词化（未 fold 且 bet 越过本层下界）；同额水位经
///    `level <= prev_level` 自然去重。
/// 4. 最外层（超出最大 all-in 的部分）单独一层，金额为 0 时不成层。
/// 5. **落槽前合并**：eligible 为空的层不单独成层，金额直接并入上一层
///    （固定数组下直接索引 `pots[count−1]`，无 `expect` panic 路径）。
///
/// # Errors
/// - `SidePotError::LengthMismatch`：三个向量长度不一致或超过 MAX_PLAYERS
/// - `SidePotError::BetOverflow`：总下注超过 MAX_TOTAL_BET
pub fn calculate_side_pots(
    bets: &[u64],
    folded: &[bool],
    all_in: &[bool],
) -> Result<SidePotResult, SidePotError> {
    let n = bets.len();
    if folded.len() != n || all_in.len() != n {
        return Err(SidePotError::LengthMismatch);
    }
    // 运行时座位数不应超过 MAX_PLAYERS（位掩码/固定槽容量）。
    if n > MAX_SIDE_POTS {
        return Err(SidePotError::LengthMismatch);
    }

    let total_pot = sum_bets(bets)?;

    // all-in 水位按秩落入固定槽位（槽序即升序；空槽为 0，而真实水位 > 0）。
    let mut levels = [0u64; MAX_SIDE_POTS];
    for (j, &bet) in bets.iter().enumerate() {
        if !all_in[j] || bet == 0 {
            continue;
        }
        let mut rank = 0usize;
        for (k, &other) in bets.iter().enumerate() {
            if k == j || !all_in[k] || other == 0 {
                continue;
            }
            if other < bet || (other == bet && k < j) {
                rank += 1;
            }
        }
        levels[rank] = bet;
    }

    let mut pots = [SidePot::new(0, 0); MAX_SIDE_POTS];
    let mut pot_count: usize = 0;
    let mut prev_level: u64 = 0;

    // 逐槽切片（含最外层：levels 末尾之后的超额部分由最后一步兜底）。
    for &level in &levels {
        if level == 0 || level <= prev_level {
            continue;
        }
        let (amount, eligible) = slice_layer(bets, folded, prev_level, level, n);
        record_layer(&mut pots, &mut pot_count, amount, eligible);
        prev_level = level;
    }

    // 最外层：超出最大 all-in 水位的贡献。
    if prev_level < total_pot {
        let (amount, eligible) = slice_layer(bets, folded, prev_level, u64::MAX, n);
        record_layer(&mut pots, &mut pot_count, amount, eligible);
    }

    // 若所有层 eligible 都为空（全员 fold 的极端情况），仍保留一个 pot 持有总额。
    if pot_count == 0 {
        pots[0] = SidePot::new(total_pot, 0);
        pot_count = 1;
    }

    Ok(SidePotResult {
        pots,
        pot_count: pot_count as u8,
    })
}

/// 切片单层：计算 [prev_level, level) 区间内各座位的贡献总额与 eligible 位掩码。
///
/// `level = u64::MAX` 表示最外层（取全部超额部分）。
fn slice_layer(bets: &[u64], folded: &[bool], prev_level: u64, level: u64, n: usize) -> (u64, u16) {
    let mut amount: u64 = 0;
    let mut eligible: u16 = 0;
    for j in 0..n {
        let bet = bets[j];
        if bet > prev_level {
            // contribution = min(bet, level) - prev_level（bet > prev_level 保证不下溢）
            let cap = if bet < level { bet } else { level };
            amount += cap - prev_level;
            if !folded[j] {
                eligible |= seat_bit(j as u8);
            }
        }
    }
    (amount, eligible)
}

/// 落槽前判断：金额为 0 不成层；eligible 为空且已有层时金额并入上一层
/// （M-A3 简化，直接索引，无 panic 路径）。
///
/// 层数上界论证：互异 all-in 水位 ≤ all-in 座位数 ≤ [`MAX_SIDE_POTS`]；
/// 最外层只在 `prev_level < total_pot` 时尝试，若此前已落 `MAX_SIDE_POTS`
/// 层则所有座位均已 all-in 且 prev_level = 最大 bet，外层切片金额恒 0，
/// 不会第 10 次落槽。故 `pot_count` 恒 ≤ [`MAX_SIDE_POTS`]。
fn record_layer(pots: &mut [SidePot; MAX_SIDE_POTS], pot_count: &mut usize, amount: u64, eligible: u16) {
    if amount == 0 {
        return;
    }
    if eligible == 0 && *pot_count > 0 {
        // 所有贡献者都 fold：金额并入最后一层。
        pots[*pot_count - 1].amount += amount;
    } else {
        pots[*pot_count] = SidePot::new(amount, eligible);
        *pot_count += 1;
    }
}

/// 计算总下注（含上界校验）。
fn sum_bets(bets: &[u64]) -> Result<u64, SidePotError> {
    let mut total: u64 = 0;
    for &bet in bets {
        total = total.checked_add(bet).ok_or(SidePotError::BetOverflow)?;
        if total > MAX_TOTAL_BET {
            return Err(SidePotError::BetOverflow);
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eligible_vec(mask: u16) -> Vec<u8> {
        (0..16).filter(|&j| is_eligible(mask, j)).collect()
    }

    /// 断言定宽 canonical：活跃层数一致，空槽全零，活跃层金额非零。
    fn assert_canonical(result: &SidePotResult) {
        assert!(usize::from(result.pot_count) >= 1);
        assert!(usize::from(result.pot_count) <= MAX_SIDE_POTS);
        for pot in result.active() {
            // 唯一例外：全零下注的退化单层（total==0，与旧算法行为一致）。
            assert!(
                pot.amount > 0 || result.total() == 0,
                "active layer carries zero amount"
            );
        }
        for pot in &result.pots[usize::from(result.pot_count)..] {
            assert_eq!(pot.amount, 0, "inactive slot carries non-zero amount");
            assert_eq!(pot.eligible_seats, 0, "inactive slot carries eligibility");
        }
    }

    /// 参照实现：旧"收集 → 排序 → 去重切片"算法（迁移前语义基准）。
    fn reference_side_pots(bets: &[u64], folded: &[bool], all_in: &[bool]) -> SidePotResult {
        let n = bets.len();
        let total_pot = bets.iter().sum::<u64>();
        let mut levels: Vec<u64> = (0..n)
            .filter(|&j| all_in[j] && bets[j] > 0)
            .map(|j| bets[j])
            .collect();
        levels.sort_unstable();

        let mut pots: Vec<SidePot> = Vec::new();
        let mut prev_level: u64 = 0;
        // 与旧 push_or_merge 逐字等价（含 amount==0 提前返回、prev_level 无条件更新）。
        let mut push_or_merge = |pots: &mut Vec<SidePot>, amount: u64, eligible: u16| {
            if amount == 0 {
                return;
            }
            if eligible == 0 && !pots.is_empty() {
                pots.last_mut().expect("non-empty").amount += amount;
            } else {
                pots.push(SidePot::new(amount, eligible));
            }
        };
        for &level in &levels {
            if level <= prev_level {
                continue;
            }
            let (amount, eligible) = slice_layer(bets, folded, prev_level, level, n);
            push_or_merge(&mut pots, amount, eligible);
            prev_level = level;
        }
        if prev_level < total_pot {
            let (amount, eligible) = slice_layer(bets, folded, prev_level, u64::MAX, n);
            push_or_merge(&mut pots, amount, eligible);
        }
        if pots.is_empty() {
            pots.push(SidePot::new(total_pot, 0));
        }
        let mut fixed = [SidePot::new(0, 0); MAX_SIDE_POTS];
        fixed[..pots.len()].copy_from_slice(&pots);
        SidePotResult {
            pots: fixed,
            pot_count: pots.len() as u8,
        }
    }

    /// 确定性伪随机差分：新秩放置实现与旧排序基准逐字节等价。
    #[test]
    fn matches_reference_sort_implementation() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let n = 2 + (next() as usize) % (MAX_SIDE_POTS - 1);
            let bets: Vec<u64> = (0..n).map(|_| next() % 30).collect();
            let folded: Vec<bool> = (0..n).map(|_| next() % 2 == 0).collect();
            let all_in: Vec<bool> = (0..n).map(|_| next() % 3 == 0).collect();
            let got = calculate_side_pots(&bets, &folded, &all_in).expect("layers");
            let want = reference_side_pots(&bets, &folded, &all_in);
            assert_eq!(got, want, "divergence at bets={bets:?} folded={folded:?} all_in={all_in:?}");
            assert_canonical(&got);
        }
    }

    /// all-in 水位在座位序上降序（旧算法的排序关键场景）语义不变。
    #[test]
    fn descending_seat_order_all_in_levels() {
        // s0 all-in 100、s1 all-in 50、s2 call 100：水位排序后 [50, 100]，
        // 层 1 = 150（eligible 0,1,2），层 2 = 100（s0 与 s2 超出 50 的部分）。
        let bets = vec![100, 50, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).expect("layers");
        assert_eq!(usize::from(result.pot_count), 2);
        assert_eq!(result.pots[0].amount, 150);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1, 2]);
        assert_eq!(result.pots[1].amount, 100);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![0, 2]);
        assert_canonical(&result);
    }

    #[test]
    fn test_no_all_in_single_pot() {
        let bets = vec![100, 100];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 1);
        assert_eq!(result.pots[0].amount, 200);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1]);
        assert_eq!(result.total(), 200);
        assert_canonical(&result);
    }

    #[test]
    fn test_single_all_in_two_pots() {
        // P0 all-in 50，P1 call 100 → pots[0] 100（eligible [0,1]），pots[1] 50（eligible [1]）
        let bets = vec![50, 100];
        let folded = vec![false, false];
        let all_in = vec![true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 2);
        assert_eq!(result.pots[0].amount, 100);
        assert_eq!(result.pots[1].amount, 50);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![1]);
        assert_eq!(result.total(), 150);
        assert_canonical(&result);
    }

    #[test]
    fn test_three_players_two_all_in_levels() {
        let bets = vec![50, 100, 100];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 2);
        assert_eq!(result.pots[0].amount, 150);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1, 2]);
        assert_eq!(result.pots[1].amount, 100);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![1, 2]);
        assert_eq!(result.total(), 250);
        assert_canonical(&result);
    }

    #[test]
    fn test_folded_player_contributes_but_ineligible() {
        // P0 fold 已下注 30，P1 all-in 100，P2 call 100
        let bets = vec![30, 100, 100];
        let folded = vec![true, false, false];
        let all_in = vec![false, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 1);
        assert_eq!(result.pots[0].amount, 230);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![1, 2]);
        assert_eq!(result.total(), 230);
        assert_canonical(&result);
    }

    #[test]
    fn test_empty_eligible_merge() {
        // 所有超额贡献者都 fold：P0 all-in 50（未 fold），P1/P2 fold 已下注 200
        // level=50: pot 150，eligible [0]
        // outer: P1+P2 各贡献 150 = 300，eligible [] → 合并到 pots[0] → 450
        let bets = vec![50, 200, 200];
        let folded = vec![false, true, true];
        let all_in = vec![true, false, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 1);
        assert_eq!(result.pots[0].amount, 450);
        assert_eq!(result.total(), 450);
        assert_canonical(&result);
    }

    #[test]
    fn test_all_in_bets_same_level() {
        // 两玩家 all-in 相同金额 → 同一 level（秩相邻，level<=prev_level 跳过重复）
        let bets = vec![100, 100, 200];
        let folded = vec![false, false, false];
        let all_in = vec![true, true, false];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), 2);
        assert_eq!(result.pots[0].amount, 300);
        assert_eq!(eligible_vec(result.pots[0].eligible_seats), vec![0, 1, 2]);
        assert_eq!(result.pots[1].amount, 100);
        assert_eq!(eligible_vec(result.pots[1].eligible_seats), vec![2]);
        assert_canonical(&result);
    }

    #[test]
    fn test_nine_seat_full_width() {
        // 9 座互异 all-in 水位：恰好铺满 9 个固定槽位（最外层金额为 0 不成层）。
        let bets: Vec<u64> = (1..=9).map(|i| 10 * i).rev().collect();
        let folded = vec![false; 9];
        let all_in = vec![true; 9];
        let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
        assert_eq!(usize::from(result.pot_count), MAX_SIDE_POTS);
        assert_eq!(result.total(), 450);
        assert_canonical(&result);
    }

    #[test]
    fn test_length_mismatch_rejected() {
        let bets = vec![100, 100];
        let folded = vec![false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in),
            Err(SidePotError::LengthMismatch)
        );
    }

    #[test]
    fn test_too_many_seats_rejected() {
        let bets = vec![1u64; MAX_SIDE_POTS + 1];
        let folded = vec![false; MAX_SIDE_POTS + 1];
        let all_in = vec![false; MAX_SIDE_POTS + 1];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in),
            Err(SidePotError::LengthMismatch)
        );
    }

    #[test]
    fn test_bet_overflow_detected() {
        let bets = vec![MAX_TOTAL_BET, 1];
        let folded = vec![false, false];
        let all_in = vec![false, false];
        assert_eq!(
            calculate_side_pots(&bets, &folded, &all_in),
            Err(SidePotError::BetOverflow)
        );
    }

    #[test]
    fn test_side_pot_borsh_roundtrip() {
        let pot = SidePot::new(150, seat_bit(0) | seat_bit(2) | seat_bit(3));
        let bytes = borsh::to_vec(&pot).unwrap();
        let recovered: SidePot = borsh::from_slice(&bytes).unwrap();
        assert_eq!(pot, recovered);
    }

    #[test]
    fn test_seat_bit_and_is_eligible() {
        assert!(is_eligible(seat_bit(0), 0));
        assert!(is_eligible(seat_bit(5), 5));
        assert!(!is_eligible(seat_bit(0), 1));
        assert!(!is_eligible(0, 0)); // 空掩码无人 eligible
    }
}
