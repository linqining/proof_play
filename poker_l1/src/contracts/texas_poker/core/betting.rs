//! Texas Poker 下注轮状态与规则。
//!
//! # AIR/Trace 友好设计（原"电路友好"，SNARK → Stwo 迁移后重述）
//!
//! 成本模型已从"R1CS 约束数"变为"trace 列宽 × 行数"，以下设计在两个模型
//! 下均成立，理由标注了 AIR 侧依据：
//!
//! - `BettingRound` 仅保留两个状态字段：`current_bet`（当前轮最高下注）与
//!   `min_raise`（最小加注增量）。删除了 `actions_taken`/`last_raiser_seat`/
//!   `big_blind` 等死字段（生产代码从未读取）。AIR 下每个固定宽度状态字段
//!   都要逐行打开并计入 Poseidon state-root
//!   （`state_root::poseidon_betting_round`），死字段是每行都付费的列，
//!   故删字段在 Stwo 下收益反而更大。
//! - 下注轮完成判定由 state_machine 的 `acted_this_round` + `bet == current_bet`
//!   完成，BettingRound 只负责金额校验。AIR 侧由 `AdvanceRound` 选择子的
//!   "全部剩余 Active 座位已 acted 且 bet == current_bet" 关系一一对应。
//! - 金额校验全部 total（`saturating_sub`/`Result`，无 panic 路径）：trace
//!   生成是宿主原生执行，panic 即 prover 崩溃；显式 Result 让 AIR 能把
//!   合法性折叠成单个布尔约束（非法即不可满足，fail-closed）。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::constants::{ACTION_CALL, ACTION_CHECK, ACTION_FOLD, ACTION_RAISE};

/// 下注轮状态。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct BettingRound {
    /// 当前轮最高下注。
    pub current_bet: u64,
    /// 最小加注增量（初始 = big_blind）。
    pub min_raise: u64,
}

impl BettingRound {
    /// 创建下注轮（preflop current_bet=big_blind，postflop current_bet=0）。
    #[must_use]
    pub fn new(big_blind: u64, current_bet: u64) -> Self {
        assert!(big_blind > 0, "big_blind 必须 > 0");
        Self {
            current_bet,
            min_raise: big_blind,
        }
    }

    /// 计算跟注所需筹码：`max(current_bet - seat_bet, 0)`。
    #[must_use]
    pub fn chips_to_call(&self, seat_bet: u64) -> u64 {
        self.current_bet.saturating_sub(seat_bet)
    }

    /// 是否可以 check（chips_to_call == 0）。
    #[must_use]
    pub fn can_check(&self, seat_bet: u64) -> bool {
        self.chips_to_call(seat_bet) == 0
    }

    /// 是否可以 call（chips_to_call > 0 && stack > 0）。
    #[must_use]
    pub fn can_call(&self, seat_bet: u64, stack: u64) -> bool {
        self.chips_to_call(seat_bet) > 0 && stack > 0
    }

    /// 是否可以 raise（stack > chips_to_call，允许短 all-in）。
    #[must_use]
    pub fn can_raise(&self, seat_bet: u64, stack: u64) -> bool {
        stack > self.chips_to_call(seat_bet)
    }

    /// 获取可用动作位掩码。
    #[must_use]
    pub fn available_actions(&self, seat_bet: u64, stack: u64) -> u8 {
        let mut mask = ACTION_FOLD; // fold 永远可用
        if self.can_check(seat_bet) {
            mask |= ACTION_CHECK;
        }
        if self.can_call(seat_bet, stack) {
            mask |= ACTION_CALL;
        }
        if self.can_raise(seat_bet, stack) {
            mask |= ACTION_RAISE;
        }
        mask
    }

    /// 处理 call，返回实际跟注金额（all-in 时可能 < chips_to_call）。
    #[must_use]
    pub fn process_call(&self, seat_bet: u64, stack: u64) -> u64 {
        self.chips_to_call(seat_bet).min(stack)
    }

    /// 处理 raise，返回玩家需补的筹码（needed = total_bet - seat_bet）。
    ///
    /// # 规则
    /// - 校验 `total_bet > current_bet` 且 `total_bet > seat_bet`。
    /// - all-in（needed == stack）且 `raise_amount < min_raise`：允许但不更新 min_raise
    ///   （短 all-in 不重新打开行动权）。
    /// - 非 all-in 且 `raise_amount < min_raise`：拒绝。
    ///
    /// # Errors
    /// - `total_bet <= current_bet` 或 `total_bet <= seat_bet`：`InvalidRaiseAmount`
    /// - `needed > stack`：`CannotRaise`
    /// - 非 all-in 且 `raise_amount < min_raise`：`InvalidRaiseAmount`
    pub fn process_raise(
        &mut self,
        total_bet: u64,
        seat_bet: u64,
        stack: u64,
    ) -> Result<u64, BettingError> {
        if total_bet <= self.current_bet || total_bet <= seat_bet {
            return Err(BettingError::InvalidRaiseAmount);
        }
        let raise_amount = total_bet - self.current_bet;
        let needed = total_bet - seat_bet;
        if needed > stack {
            return Err(BettingError::CannotRaise);
        }

        let is_all_in = needed == stack;
        if raise_amount >= self.min_raise {
            // 合法加注：更新 min_raise（all-in 达到 min_raise 也更新）。
            self.min_raise = raise_amount;
        } else if !is_all_in {
            // 非 all-in 且低于 min_raise：拒绝。
            return Err(BettingError::InvalidRaiseAmount);
        }
        // 短 all-in（raise_amount < min_raise）：允许但不更新 min_raise。

        self.current_bet = total_bet;
        Ok(needed)
    }
}

/// 下注错误类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BettingError {
    /// 加注金额非法（未超过当前注 / 低于 seat_bet / 非 all-in 低于最小加注增量）。
    #[error("invalid raise amount")]
    InvalidRaiseAmount,
    /// 筹码不足以完成该加注（needed > stack）。
    #[error("cannot raise: insufficient stack")]
    CannotRaise,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_preflop() {
        let round = BettingRound::new(100, 100);
        assert_eq!(round.current_bet, 100);
        assert_eq!(round.min_raise, 100);
    }

    #[test]
    fn test_new_postflop() {
        let round = BettingRound::new(100, 0);
        assert_eq!(round.current_bet, 0);
        assert_eq!(round.min_raise, 100);
    }

    #[test]
    fn test_chips_to_call() {
        let round = BettingRound::new(100, 100);
        assert_eq!(round.chips_to_call(0), 100);
        assert_eq!(round.chips_to_call(50), 50);
        assert_eq!(round.chips_to_call(100), 0);
        assert_eq!(round.chips_to_call(200), 0);
    }

    #[test]
    fn test_can_check() {
        let round = BettingRound::new(100, 100);
        assert!(!round.can_check(0));
        assert!(round.can_check(100));
    }

    #[test]
    fn test_process_call() {
        let round = BettingRound::new(100, 100);
        assert_eq!(round.process_call(0, 1000), 100);
        assert_eq!(round.process_call(0, 50), 50); // all-in call
        assert_eq!(round.process_call(100, 1000), 0);
    }

    #[test]
    fn test_process_raise_normal() {
        let mut round = BettingRound::new(100, 100);
        let needed = round.process_raise(300, 0, 1000).unwrap();
        assert_eq!(needed, 300);
        assert_eq!(round.current_bet, 300);
        assert_eq!(round.min_raise, 200);
    }

    #[test]
    fn test_process_raise_all_in_sufficient() {
        let mut round = BettingRound::new(100, 100);
        let needed = round.process_raise(300, 0, 300).unwrap();
        assert_eq!(needed, 300);
        assert_eq!(round.min_raise, 200);
    }

    #[test]
    fn test_process_raise_all_in_short() {
        let mut round = BettingRound::new(100, 100);
        round.process_raise(300, 0, 1000).unwrap(); // min_raise = 200
        // 短 all-in：raise_amount=100 < min_raise=200
        let needed = round.process_raise(400, 0, 400).unwrap();
        assert_eq!(needed, 400);
        assert_eq!(round.min_raise, 200); // 不更新
        assert_eq!(round.current_bet, 400);
    }

    #[test]
    fn test_process_raise_below_min_rejected() {
        let mut round = BettingRound::new(100, 100);
        assert_eq!(
            round.process_raise(150, 0, 1000),
            Err(BettingError::InvalidRaiseAmount)
        );
    }

    #[test]
    fn test_process_raise_insufficient_stack() {
        let mut round = BettingRound::new(100, 100);
        assert_eq!(
            round.process_raise(500, 0, 400),
            Err(BettingError::CannotRaise)
        );
    }

    #[test]
    fn test_available_actions() {
        let round = BettingRound::new(100, 100);
        // SB: bet=0, stack=1000 → fold + call + raise
        let actions = round.available_actions(0, 1000);
        assert!(actions & ACTION_FOLD != 0);
        assert!(actions & ACTION_CALL != 0);
        assert!(actions & ACTION_RAISE != 0);
        assert!(actions & ACTION_CHECK == 0);

        // BB: bet=100, stack=1000 → fold + check + raise
        let actions = round.available_actions(100, 1000);
        assert!(actions & ACTION_CHECK != 0);
        assert!(actions & ACTION_CALL == 0);
    }
}
