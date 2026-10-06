use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::player::GamePlayer;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seat {
    pub id: u32,
    pub player: Option<GamePlayer>,
    pub buyin: u64,
    pub stack: u64,
    pub hand: Vec<Card>,
    pub bet: u64,
    #[serde(default)]
    pub total_bet: u64,
    pub turn: bool,
    pub checked: bool,
    pub folded: bool,
    pub last_action: Option<String>,
    pub sitting_out: bool,
    #[serde(default)]
    pub disconnected: bool,
    #[serde(skip)]
    pub disconnected_at: Option<u64>,
    #[serde(default)]
    pub is_waiting: bool,
    #[serde(default)]
    pub has_acted: bool,
    /// 对齐 Move seat.left_during_hand：玩家在手牌进行中被踢出/离开时标记。
    /// 保留 seat 不删除，total_bet 保留供 side pot 计算，refund_all_bets 时退款。
    #[serde(default)]
    pub left_during_hand: bool,
    /// 对齐 Move seat.refunded：标记已退款，避免重复退款。
    #[serde(default)]
    pub refunded: bool,
}

impl Seat {
    pub fn new(id: u32, player: Option<GamePlayer>, buyin: u64, stack: u64) -> Self {
        Self {
            id,
            player,
            buyin,
            stack,
            hand: vec![],
            bet: 0,
            turn: false,
            checked: true,
            folded: true,
            last_action: None,
            sitting_out: false,
            disconnected: false,
            disconnected_at: None,
            is_waiting: false,
            has_acted: false,
            total_bet: 0,
            left_during_hand: false,
            refunded: false,
        }
    }

    pub fn fold(&mut self) {
        // NOTE: do NOT zero self.bet here — the bet already contributed to the pot
        // and is needed for correct side-pot calculation. Bets are cleared in
        // reset_bets_and_actions() when the round advances.
        self.folded = true;
        self.last_action = Some(actions::FOLD.to_string());
        self.turn = false;
        self.has_acted = true;
    }

    pub fn check(&mut self) {
        self.checked = true;
        self.last_action = Some(actions::CHECK.to_string());
        self.turn = false;
        self.has_acted = true;
    }

    pub fn raise(&mut self, amount: u64) {
        // saturating（audit H4）：amount 来自用户输入，正常路径保证 amount ≥ bet
        // （handle_raise 校验），异常输入下回绕会污染 total_bet/stack 记账。
        let re_raise_amount = amount.saturating_sub(self.bet);
        if re_raise_amount > self.stack {
            // all-in: put all remaining chips in
            self.bet += self.stack;
            self.total_bet += self.stack;
            self.stack = 0;
        } else {
            self.bet = self.bet.max(amount);
            self.total_bet += re_raise_amount;
            self.stack -= re_raise_amount;
        }
        self.turn = false;
        self.last_action = Some(actions::RAISE.to_string());
        self.has_acted = true;
    }

    /// 投盲注（min(amount, stack)）。调用方（set_blinds 的 dead button
    /// 推导）必须保证本座位参与本手——防御性断言：sitting out / 等待
    /// 入局 / 已离场座位不得被扣盲注（资金正确性红线）。
    pub fn place_blind(&mut self, amount: u64) -> u64 {
        debug_assert!(
            !self.sitting_out && !self.is_waiting && !self.left_during_hand,
            "place_blind on a non-participating seat (dead-button track violated)"
        );
        let actual = if amount > self.stack { self.stack } else { amount };
        self.bet = actual;
        self.total_bet += actual;
        self.stack -= actual;
        actual
    }

    pub fn call_raise(&mut self, amount: u64) {
        // saturating（audit H4）：同 raise，异常输入（amount < bet）下不得回绕
        let mut amount_called = amount.saturating_sub(self.bet);
        if amount_called >= self.stack {
            amount_called = self.stack;
        }
        self.bet += amount_called;
        self.total_bet += amount_called;
        self.stack -= amount_called;
        self.turn = false;
        self.last_action = Some(actions::CALL.to_string());
        self.has_acted = true;
    }

    pub fn win_hand(&mut self, amount: u64) {
        self.bet = 0;
        self.total_bet = 0;
        self.stack += amount;
        self.turn = false;
        self.last_action = Some(actions::WINNER.to_string());
    }

    pub fn to_client(&self) -> ClientSeat {
        ClientSeat {
            id: self.id,
            player: self.player.clone(),
            buyin: self.buyin,
            stack: self.stack,
            hand: self.hand.clone(),
            bet: self.bet,
            turn: self.turn,
            checked: self.checked,
            folded: self.folded,
            last_action: self.last_action.clone(),
            sitting_out: self.sitting_out,
            is_waiting: self.is_waiting,
            total_bet: self.total_bet,
        }
    }
}



#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSeat {
    pub id: u32,
    pub player: Option<GamePlayer>,
    pub buyin: u64,
    pub stack: u64,
    pub hand: Vec<Card>,
    pub bet: u64,
    pub turn: bool,
    pub checked: bool,
    pub folded: bool,
    pub last_action: Option<String>,
    pub sitting_out: bool,
    #[serde(default)]
    pub is_waiting: bool,
    /// 本手累计投入（含以往街；赢家派彩后清零）。供前端「你已投入 /
    /// 本手投入」显示。#[serde(default)] 兼容旧记录反序列化。
    #[serde(default)]
    pub total_bet: u64,
}
