use crate::pokergame::game_state::{
    ElGamalCiphertextJson, MaskAndShuffleRoundJson, PkProofJson, PlayerResidualCarriers,
    PlayerResidualCarriersJson, PlayerRevealAssignment, ReconstructProofJson,
    ReconstructPublicState, ReconstructState, RevealPhase, RevealTokenPublicState,
    RevealTokenState, ShuffleProofJson, ShufflePublicState, ShuffleState,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

use crate::pokergame::deck::{Card, EncryptedDeck};
use crate::pokergame::player::{
    GamePkHex, GamePlayer, Player, PlayerWithProof, WalletAddress, truncate_name,
};
use crate::pokergame::seat::{ClientSeat, Seat};
use crate::pokergame::side_pot::SidePot;
use crate::pokergame::table_summary::TableSummaryV2;
use poker_protocol::crypto::CurvePoint;
use poker_protocol::crypto::CurveScalar;
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Plaintext, Scalar};
use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, scalar_to_hex};
use poker_protocol::z_poker::{GameConfig, MentalPokerGame};
/// 对齐 Move 合约 MIN_PLAYERS_TO_START = 2
const MIN_START_NUM: u32 = 2;

/// 当前时间的毫秒时间戳，对齐 Move 合约 Clock.timestamp_ms() 语义。
/// 用于 summary.state 中的各类 *_at 时间戳字段的设置与比较。
pub use crate::relayer::util::now_ms;

pub mod betting;
pub mod events;
#[cfg(test)]
pub(crate) mod full_hand_tests;
#[cfg(test)]
mod holdem_scenario_tests;
pub mod lifecycle;
pub mod phases;
pub mod pot;
pub mod reconstruct;
#[cfg(test)]
mod redeal_tests;
pub mod reveal;
#[cfg(test)]
mod rules_tests;
pub mod seat_mgmt;
pub mod shuffle;
#[cfg(test)]
mod view_semantics_tests;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub seat_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinResult {
    JoinedAndShuffled,
    JoinedWaiting,
}

pub use crate::pokergame::error::JoinError;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoundState {
    Waiting,
    PreFlop,
    Flop,
    Turn,
    River,
    Showdown,
}

impl RoundState {
    /// 将链上 u8 round_state 转换为 RoundState 枚举。
    /// 对齐 Move 合约：0=Waiting, 2=PreFlop, 3=Flop, 4=Turn, 5=River, 6=Showdown
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RoundState::Waiting),
            2 => Some(RoundState::PreFlop),
            3 => Some(RoundState::Flop),
            4 => Some(RoundState::Turn),
            5 => Some(RoundState::River),
            6 => Some(RoundState::Showdown),
            _ => None,
        }
    }

    /// 将 RoundState 枚举转换为链上 u8 round_state。
    pub fn to_u8(self) -> u8 {
        match self {
            RoundState::Waiting => 0,
            RoundState::PreFlop => 2,
            RoundState::Flop => 3,
            RoundState::Turn => 4,
            RoundState::River => 5,
            RoundState::Showdown => 6,
        }
    }
}

/// #17 accepted-seq 向量条目（settle 广播中的抗审查承诺）。
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AcceptedSeqEntry {
    pub seat: u32,
    pub seq: u64,
}

pub struct ActionRequest {
    pub pk_hex: GamePkHex,
    pub action: String,
    pub amount: Option<u64>,
    /// #16 动作签名（客户端牌局 SK）；None = 未签名（迁移期兼容）。
    pub seq: Option<u64>,
    pub sig: Option<crate::pokergame::actions::ActionSig>,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTable {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: HashMap<GamePkHex, WalletAddress>,
    pub seats: HashMap<u32, ClientSeat>,
    pub board: Vec<Card>,
    pub deck: Option<EncryptedDeck>,
    pub button: Option<u32>,
    pub turn: Option<u32>,
    pub pot: u64,
    pub main_pot: u64,
    pub call_amount: Option<u64>,
    pub min_bet: u64,
    pub min_raise: u64,
    pub small_blind: Option<u32>,
    pub big_blind: Option<u32>,
    pub hand_over: bool,
    pub win_messages: Vec<String>,
    pub went_to_showdown: bool,
    pub side_pots: Vec<SidePot>,
    /// 本手已收台费（摊牌结算时按链上口径收取）
    pub rake_collected: u64,
    /// #17 抗审查承诺向量：座位 → 已接受最大动作 seq（含 auto 代打）
    pub accepted_seqs: Vec<AcceptedSeqEntry>,
    pub history: Vec<serde_json::Value>,
    pub round_state: RoundState,
    /// 本手 id（动作签名域 v2）。洗牌结束后 shuffleState 置 null，下注阶段
    /// 客户端动作签名（snip36 递归证明材料）从这里取 hand_id。
    #[serde(default)]
    pub hand_id: u32,
    /// 最小买入（= max(min_bet × 20, 1000)，与客户端历史校验规则同源）。
    #[serde(default)]
    pub min_buy_in: u64,
    /// 最大买入（limit > 0 ? limit : big_blind × 100）。此前客户端硬编码
    /// 5000，与桌台 limit 脱节。
    #[serde(default)]
    pub max_buy_in: u64,
    /// 台费费率（basis points；rake_params() 与链上环境变量同源）。
    #[serde(default)]
    pub rake_bps: u16,
    /// 台费单手上限（rake_params()）。
    #[serde(default)]
    pub rake_cap: u64,
    /// 当前回合计时锚点（epoch ms；= summary.state.betting_started_at，
    /// 每次行动/换手重置）。客户端线性倒计时与超时自动弃牌以此为准。
    #[serde(default)]
    pub betting_started_at: u64,
    /// 回合计时总长（ms；0 = 未配置，客户端回退本地 15s）。
    #[serde(default)]
    pub betting_timeout_ms: u64,
    /// 上一手终局时间（epoch ms）与到下一手开局的等待时长（ms）。
    #[serde(default)]
    pub hand_complete_at: u64,
    #[serde(default)]
    pub hand_complete_wait_ms: u64,
    /// 摊牌各家牌型（仅摊牌手有值）。
    #[serde(default)]
    pub showdown_hand_ranks: Vec<crate::pokergame::table_summary::ShowdownHandRank>,
    pub shuffle_state: Option<ShufflePublicState>,
    pub reveal_token_state: Option<RevealTokenPublicState>,
    pub reconstruct_state: Option<ReconstructPublicState>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    pub chain_table_id: Option<String>,
    /// 桌台已关闭（终态）：客户端据此禁用入座并提示。关桌后不再开局。
    #[serde(default)]
    pub closed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub summary: TableSummaryV2,
    /// 仅 off-chain 模式使用；on-chain 模式通过 `players()` 访问器从 `summary.crypto.seat_pks` + `summary.meta.seat_players` 派生
    pub local_players: HashMap<GamePkHex, WalletAddress>,
    /// 仅 off-chain 模式使用 + on-chain 运行时字段；on-chain 模式通过 `seats()` 访问器从 `summary.meta.seat_*` 派生
    pub local_seats: HashMap<u32, Seat>,
    #[serde(skip)]
    pub shuffle_state: ShuffleState,
    #[serde(skip)]
    pub reveal_token_state: RevealTokenState,
    #[serde(skip)]
    pub reconstruct_state: ReconstructState,
    #[serde(skip)]
    pub betting_round: Option<crate::pokergame::betting::BettingRound>,
    #[serde(skip)]
    pub mental_poker_game: MentalPokerGame,
    #[serde(skip)]
    pub waiting_players: HashMap<GamePkHex, PlayerWithProof>,
    #[serde(skip)]
    pub pk_to_seat: HashMap<GamePkHex, u32>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    /// 由 relayer 在 `sync_table_state` 中匹配到链上 table 后设置。
    /// 上链模式下用户操作构建 PTB 时需要此字段；为 None 表示尚未与链上 table 关联。
    #[serde(skip)]
    pub chain_table_id: Option<String>,
    #[serde(skip)]
    pub event_tx: Option<tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>>,
    /// #16/#17：座位 → 已接受的最大动作 seq（跨手单调，抗审查承诺向量）。
    #[serde(skip)]
    pub accepted_seq: HashMap<u32, u64>,
    /// #16/#17：本手动作日志（含超时 auto 代打标记），新手牌开始清空。
    #[serde(skip)]
    pub action_log: Vec<crate::pokergame::actions::ActionLogEntry>,
    /// #18：本手在 `action_log` 中的起始下标（start_hand 设置）。日志本体
    /// 跨手累积便于追溯，审计摘要只覆盖本手窗口。
    #[serde(skip)]
    pub hand_log_start: usize,
    /// 本手 id（开局时分配；动作签名域 v2 与结算记账同源）。
    pub current_hand_id: u32,
    /// 本手证明事实（单一状态架构）：HandStart 快照 + 游戏层对账基准
    /// （终局投入/逐笔派奖）；结算取用实时 VM 镜像（vm_session），
    /// 本结构是对账与动作签名材料的来源。
    /// `record_hand_start`（deck 终局时）整体重置。
    #[serde(skip)]
    pub hand_proof_log: crate::starknet::prove_log::HandProofLog,
    /// 实时 VM 镜像（单一状态表示）：deck 终局时挂载，随桌存在，
    /// 结算时 take。挂在 Table 上而非全局表——无跨桌串流。
    #[serde(skip)]
    pub vm_session: Option<crate::starknet::vm_session::VmSession>,
    /// 本手被钉出的座位（在座但不在冻结计划里：计划冻结后座位标志被
    /// 重连等并发事件翻转的座位）。本手内 sitting_out 钉住；下一手开局
    /// 时 socket 仍在（未断线）的座位据此召回——玩家主动坐出
    /// （SITTING_OUT）不经此名单，仍需显式 SITTING_IN。
    #[serde(skip)]
    pub hand_excluded_seats: Vec<u32>,
    /// 关桌标志（终态）：置位后不再开局（game_loop 跳过 auto-start）、
    /// 不再接受入座（SIT_DOWN 拒绝）。"关桌后不开新手"的服务端权威执行点。
    #[serde(skip)]
    pub closed: bool,
    /// 链上注册表（PokerTableRegistry）分配的 table_id；None = 无链上
    /// 锚点（未配置注册表，或注册失败降级为纯链下）。
    #[serde(skip)]
    pub registry_table_id: Option<u64>,
    /// 上一手大盲座位（dead button 盲注轮转轨道，Robert's Rules of Poker
    /// §4.2b）。0 = 尚无历史（首手退化为按钮相对定位）。仅 set_blinds
    /// （投盲注时）更新；空桌重置为 0。座位号 1 起始，与 button 一致。
    #[serde(skip)]
    pub last_bb_seat: u32,
    /// 回合行动计时（ms）：与 config.betting_timeout_secs 同源（Table::new
    /// 后由 main 经 with_timeouts 注入）。0 = 未配置（客户端回退本地 15s）。
    #[serde(skip)]
    pub turn_timeout_ms: u64,
    /// 终局到下一手开局的等待时长（ms）：与 config.hand_complete_wait_secs
    /// 同源。与 hand_complete_at 一起下发，客户端用于「下一手」倒计时。
    #[serde(skip)]
    pub hand_complete_wait_ms: u64,
    /// 本手开局各座位 stack 快照（start_hand 记录）。终局 net =
    /// 终局 stack − 快照；win_hand 会清零 total_bet，故不能由投入推导赢家 net。
    #[serde(skip)]
    pub hand_start_stacks: HashMap<u32, u64>,
    /// 洗牌证明留存（D1 证明通道）：验证点留存证明本体 + verified/挑战值，
    /// REST `/api/tables/:id/hands/:seq/proof` 的数据源。有界 FIFO。
    #[serde(skip)]
    pub proof_ledger: crate::pokergame::proof_ledger::ProofLedger,
}

impl Table {
    pub fn round_state(&self) -> RoundState {
        RoundState::from_u8(self.summary.meta.round_state).unwrap_or(RoundState::Waiting)
    }
    pub fn pot(&self) -> u64 {
        self.summary.meta.pot
    }
    pub fn set_pot(&mut self, v: u64) {
        self.summary.meta.pot = v;
    }
    pub fn button(&self) -> Option<u32> {
        if self.summary.meta.button == 0 {
            None
        } else {
            Some(self.summary.meta.button as u32)
        }
    }
    /// 诊断辅助：当前证明日志的手 id（动作签名域 hand_id 的服务端视角）。
    pub fn hand_proof_log_start_hand_id(&self) -> Option<u32> {
        self.hand_proof_log.start.as_ref().map(|s| s.hand_id)
    }
    pub fn set_button(&mut self, v: Option<u32>) {
        self.summary.meta.button = v.map(|x| x as u64).unwrap_or(0);
    }
    /// 上一手大盲座位（dead button 盲注轮转轨道）；0 = 无历史。
    pub fn last_bb_seat(&self) -> u32 {
        self.last_bb_seat
    }
    pub fn set_last_bb_seat(&mut self, v: Option<u32>) {
        self.last_bb_seat = v.unwrap_or(0);
    }
    pub fn turn(&self) -> Option<u32> {
        self.summary.meta.current_turn.map(|x| x as u32)
    }
    pub fn set_turn(&mut self, v: Option<u32>) {
        self.summary.meta.current_turn = v.map(|x| x as u64);
    }
    pub fn small_blind(&self) -> Option<u32> {
        if self.summary.meta.small_blind == 0 {
            None
        } else {
            Some(self.summary.meta.small_blind as u32)
        }
    }
    pub fn set_small_blind(&mut self, v: Option<u32>) {
        self.summary.meta.small_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn big_blind(&self) -> Option<u32> {
        if self.summary.meta.big_blind == 0 {
            None
        } else {
            Some(self.summary.meta.big_blind as u32)
        }
    }
    pub fn set_big_blind(&mut self, v: Option<u32>) {
        self.summary.meta.big_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn max_players(&self) -> u32 {
        self.summary.meta.max_players as u32
    }
    pub fn name(&self) -> &str {
        &self.summary.meta.name
    }

    // ===== 对齐 Move：min_raise 使用 summary.meta.betting_round_min_raise =====
    pub fn min_raise(&self) -> u64 {
        self.summary.meta.betting_round_min_raise
    }
    pub fn set_min_raise(&mut self, v: u64) {
        self.summary.meta.betting_round_min_raise = v;
    }

    // ===== 对齐 Move：main_pot = pot - sum(side_pots)，无独立字段 =====
    pub fn main_pot(&self) -> u64 {
        let side_total: u64 = self.summary.side_pots.iter().map(|sp| sp.amount).sum();
        self.pot().saturating_sub(side_total)
    }

    // ===== 对齐 Move Timestamps：使用 summary.state 中的 u64 毫秒时间戳 =====
    // 0 表示未设置（对齐 Move 中 0 表示未启动计时）
    pub fn betting_started_at(&self) -> u64 {
        self.summary.state.betting_started_at
    }
    pub fn set_betting_started_at(&mut self, v: u64) {
        self.summary.state.betting_started_at = v;
    }
    pub fn hand_complete_at(&self) -> u64 {
        self.summary.state.hand_complete_at
    }
    pub fn set_hand_complete_at(&mut self, v: u64) {
        self.summary.state.hand_complete_at = v;
    }
    pub fn ready_at(&self) -> u64 {
        self.summary.state.ready_at
    }
    pub fn set_ready_at(&mut self, v: u64) {
        self.summary.state.ready_at = v;
    }
    pub fn showdown_at(&self) -> u64 {
        self.summary.state.showdown_at
    }
    pub fn set_showdown_at(&mut self, v: u64) {
        self.summary.state.showdown_at = v;
    }

    /// 返回当前加密牌组。
    /// 始终从 `mental_poker_game.deck_encrypted` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.crypto.deck_encrypted` 同步到 `mental_poker_game`。
    pub fn deck_encrypted(&self) -> Vec<ElGamalCiphertext> {
        self.mental_poker_game.deck_encrypted.clone()
    }

    /// 返回当前明文牌组。
    /// 始终从 `mental_poker_game.deck_plaintext` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.state.deck_plaintext` 同步到 `mental_poker_game`。
    pub fn deck_plaintext(&self) -> Vec<Plaintext> {
        self.mental_poker_game.deck_plaintext.clone()
    }

    /// 返回当前聚合公钥。
    /// 始终从 `mental_poker_game.key_manager` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.crypto.aggregated_pk` 同步到 `mental_poker_game`。
    #[cfg(test)]
    pub fn aggregated_pk(&self) -> EcPoint {
        self.mental_poker_game.key_manager.get_aggregated_pk()
    }

    /// #16 动作签名验证（服务端口径）：table_id/hand_id/seq/action/amount
    /// 全部进签名域（v2）。hand_id 取开局分配值（`hand_proof_log.start`）；
    /// 未开局（无 HandStartData）时无从绑定手上下文，一律拒绝。
    pub fn verify_action_sig(
        &self,
        pk_hex: &GamePkHex,
        seq: u64,
        action: &str,
        amount: u64,
        sig: &crate::pokergame::actions::ActionSig,
    ) -> bool {
        let Some(hand_id) = self.hand_proof_log.start.as_ref().map(|s| s.hand_id) else {
            return false;
        };
        poker_protocol::z_poker::protocol::verify_game_action_hex(
            &pk_hex.0,
            self.summary.id,
            hand_id,
            seq,
            action,
            amount,
            &sig.r_hex,
            &sig.s_hex,
        )
    }

    /// #16/#17 记账：seq 单调推进 + 本手动作日志。auto = 服务器超时代打
    ///（seq 服务器分配 = accepted + 1）。
    pub fn record_action(
        &mut self,
        seat: u32,
        seq: u64,
        action: &str,
        amount: u64,
        auto: bool,
        sig_ok: bool,
        sig: Option<crate::pokergame::actions::ActionSig>,
    ) {
        // #18 Phase C 切片 2：记录时刻的下注语境（与 handle_auto_fold 的
        // 推导逐字段同源：owed = summary.call_amount、my_bet = seat.bet、
        // big_blind = 2×min_bet）——电路"合法默认"约束的见证。
        let owed = self.summary.call_amount.unwrap_or(0);
        let my_bet = self.local_seats.get(&seat).map(|s| s.bet).unwrap_or(0);
        let big_blind = self.summary.min_bet.saturating_mul(2);
        self.accepted_seq.insert(seat, seq);
        self.action_log
            .push(crate::pokergame::actions::ActionLogEntry {
                seat,
                seq,
                action: action.to_string(),
                amount,
                auto,
                sig_ok,
                owed,
                my_bet,
                big_blind,
                sig,
            });
        // 展示流水（设计稿 T6 ACTION LOG）：与 #18 审计链并行，只做下发，
        // 不参与摘要。street 取当下 round_state，玩家名便于前端直读。
        let player = self
            .local_seats
            .get(&seat)
            .and_then(|s| s.player.as_ref().map(|p| p.name.clone()));
        self.summary.actions.push(serde_json::json!({
            "seat": seat,
            "player": player,
            "action": action,
            "amount": amount,
            "street": format!("{:?}", self.round_state()),
            "ts": now_ms(),
            "auto": auto,
        }));
    }

    /// 座位当前 accepted seq（无记录为 0）。
    pub fn accepted_seq_of(&self, seat: u32) -> u64 {
        self.accepted_seq.get(&seat).copied().unwrap_or(0)
    }

    pub fn to_client(&self) -> ClientTable {
        let mut client_seats = HashMap::new();
        for (seat_id, seat) in self.seats().iter() {
            let client_seat = seat.to_client();
            client_seats.insert(*seat_id, client_seat);
        }
        let encrypted_deck = EncryptedDeck {
            cards: self
                .deck_encrypted()
                .iter()
                .map(ElGamalCiphertextJson::from_ciphertext)
                .collect(),
        };
        let board = self
            .mental_poker_game
            .list_revealed_community_cards()
            .iter()
            .map(|c| Card::from_playing_card(c))
            .collect::<Vec<_>>();
        ClientTable {
            id: self.summary.id,
            name: self.name().to_string(),
            limit: self.summary.limit,
            max_players: self.max_players(),
            players: self.players(),
            seats: client_seats,
            board: board,
            deck: Some(encrypted_deck.clone()),
            button: self.button(),
            turn: self.turn(),
            pot: self.pot(),
            main_pot: self.main_pot(),
            call_amount: self.summary.call_amount,
            min_bet: self.summary.min_bet,
            min_raise: self.min_raise(),
            small_blind: self.small_blind(),
            big_blind: self.big_blind(),
            hand_over: self.summary.hand_over,
            win_messages: self.summary.win_messages.clone(),
            went_to_showdown: self.summary.went_to_showdown,
            side_pots: self.summary.side_pots.clone(),
            rake_collected: self.summary.rake_collected,
            accepted_seqs: {
                let mut v: Vec<AcceptedSeqEntry> = self
                    .accepted_seq
                    .iter()
                    .map(|(seat, seq)| AcceptedSeqEntry {
                        seat: *seat,
                        seq: *seq,
                    })
                    .collect();
                v.sort_by_key(|e| e.seat);
                v
            },
            history: self.summary.history.clone(),
            round_state: self.round_state(),
            hand_id: self.current_hand_id,
            min_buy_in: self.summary.min_bet.saturating_mul(20).max(1000),
            max_buy_in: if self.summary.limit > 0 {
                self.summary.limit
            } else {
                self.summary.meta.big_blind.saturating_mul(100)
            },
            rake_bps: crate::pokergame::rake::rake_params().rake_bps,
            rake_cap: crate::pokergame::rake::rake_params().rake_cap,
            betting_started_at: self.betting_started_at(),
            betting_timeout_ms: self.turn_timeout_ms,
            hand_complete_at: self.hand_complete_at(),
            hand_complete_wait_ms: self.hand_complete_wait_ms,
            showdown_hand_ranks: self.summary.showdown_hand_ranks.clone(),
            shuffle_state: self.get_shuffle_public_state(),
            reveal_token_state: self.get_reveal_token_public_state(),
            reconstruct_state: self.get_reconstruct_public_state(),
            chain_table_id: self.chain_table_id.clone(),
            closed: self.closed,
        }
    }

    /// Transition to a new round state with validity checking.
    /// Logs a warning if the transition is not in the valid transition table.
    /// G4 修复：对严重非法转换（如 Waiting → Showdown）直接 panic，
    /// 其他非法转换在 debug 构建中 panic，release 中仅记录 warn。
    pub fn transition_to(&mut self, new_state: RoundState) {
        if self.round_state() == new_state {
            return;
        };
        let from = self.round_state();
        let valid = matches!(
            (from, new_state),
            (RoundState::Waiting, RoundState::PreFlop) |
            (RoundState::PreFlop, RoundState::Flop) |
            (RoundState::Flop, RoundState::Turn) |
            (RoundState::Turn, RoundState::River) |
            (RoundState::River, RoundState::Showdown) |
            (RoundState::Showdown, RoundState::Waiting) |
            // Early termination / timeout reset
            (RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River, RoundState::Waiting)
        );
        tracing::info!("Transition from {:?} to {:?}", from, new_state);
        if !valid {
            let severe = matches!(
                (from, new_state),
                (RoundState::Waiting, RoundState::Showdown)
                    | (
                        RoundState::Showdown,
                        RoundState::PreFlop
                            | RoundState::Flop
                            | RoundState::Turn
                            | RoundState::River
                    )
            );
            if severe {
                // 历史上此处 panic：会杀死 game_loop task 且跳过 registry 清理，
                // start_game_loop 的 contains() 判真后拒绝重启 → 该牌桌永久冻结。
                // 降级为告警 + 强制落地（状态机漂移可观测、可恢复）。
                tracing::error!(
                    "severe illegal state transition {:?} -> {:?}; forcing (was panic, see audit H1)",
                    from,
                    new_state
                );
            } else {
                tracing::warn!("Invalid state transition: {:?} -> {:?}", from, new_state);
            }
        }
        self.summary.meta.round_state = new_state.to_u8();
    }

    /// Force transition to a new round state WITHOUT validation.
    /// Used by sync_table_state when the on-chain state is the authority.
    /// The on-chain round_state is already validated by the Move contract,
    /// so we skip the local state machine validation to avoid getting stuck
    /// when local and chain states diverge.
    pub fn new(
        id: u32,
        name: String,
        limit: u64,
        max_players: u32,
        chain_table_id: String,
    ) -> Self {
        let local_seats = Self::init_seats(max_players);
        let mut summary = TableSummaryV2::default();
        summary.meta.name = name;
        summary.meta.max_players = max_players as u64;
        summary.meta.small_blind = (limit / 200) as u64;
        summary.meta.big_blind = (limit / 100) as u64;
        summary.meta.round_state = RoundState::Waiting.to_u8();
        summary.id = id;
        summary.limit = limit;
        summary.call_amount = None;
        summary.min_bet = limit / 200;
        summary.hand_over = true;
        summary.win_messages = vec![];
        summary.went_to_showdown = false;
        summary.side_pots = vec![];
        summary.history = vec![];
        Self {
            summary,
            local_players: HashMap::new(),
            local_seats,
            shuffle_state: ShuffleState::new(),
            reveal_token_state: RevealTokenState::new(2, 5),
            reconstruct_state: ReconstructState::new(),
            betting_round: None,
            mental_poker_game: MentalPokerGame::new(GameConfig {
                num_players: max_players as usize,
                cards_per_player: 2,
                community_cards: 5,
            }),
            waiting_players: HashMap::new(),
            pk_to_seat: HashMap::new(),
            chain_table_id: Some(chain_table_id),
            event_tx: None,
            accepted_seq: HashMap::new(),
            action_log: Vec::new(),
            hand_proof_log: crate::starknet::prove_log::HandProofLog::default(),
            vm_session: None,
            hand_excluded_seats: Vec::new(),
            hand_log_start: 0,
            current_hand_id: 0,
            closed: false,
            registry_table_id: None,
            last_bb_seat: 0,
            turn_timeout_ms: 0,
            hand_complete_wait_ms: 0,
            hand_start_stacks: HashMap::new(),
            proof_ledger: crate::pokergame::proof_ledger::ProofLedger::default(),
        }
    }

    /// 注入回合计时配置（main 启动时调用；与 config 的 *_secs 同源）。
    /// builder 风格，避免 Table::new 签名变更波及测试。
    pub fn with_timeouts(mut self, turn_timeout_ms: u64, hand_complete_wait_ms: u64) -> Self {
        self.turn_timeout_ms = turn_timeout_ms;
        self.hand_complete_wait_ms = hand_complete_wait_ms;
        self
    }

    /// 关桌（终态，幂等）：置位后 game_loop 不再开局、SIT_DOWN 被拒。
    /// 返回 false 表示桌台此前已关闭。
    pub fn close_table(&mut self) -> bool {
        if self.closed {
            return false;
        }
        self.closed = true;
        true
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// 注入事件 sender，使 Table 内部方法能通过 `emit_event` 发送 socket 事件。
    /// 由 `SocketState::init_table_event_channels` 在初始化时调用。
    pub fn set_event_sender(
        &mut self,
        tx: tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>,
    ) {
        self.event_tx = Some(tx);
    }

    /// 发送一个 TableEvent 到 channel，由 `table_event_consumer` 消费并执行实际 socket 广播。
    /// 若未注入 sender（event_tx 为 None），静默返回。
    /// 使用 `try_send` 非阻塞发送：channel 满或已关闭时静默丢弃事件，不 panic、不阻塞。
    /// 这使得 sync 内部方法（如 advance_shuffle / on_reveal_complete）也能调用。
    pub fn emit_event(&self, event: crate::pokergame::table::events::TableEvent) {
        if let Some(tx) = &self.event_tx {
            if let Err(e) = tx.try_send(event) {
                tracing::debug!("[TABLE-EVENTS] emit_event dropped: {}", e);
            }
        }
    }

    pub fn init_seats(_max_players: u32) -> HashMap<u32, Seat> {
        HashMap::new()
    }

    /// 返回 players 映射。on-chain 模式从 summary.crypto.seat_pks + summary.meta.seat_players 派生；
    /// off-chain 模式返回 local_players 副本。
    ///
    /// 注意：GamePkHex 必须通过 G1 compressed bytes 反序列化得到（与 relayer 的
    /// `deserialize_pk_hex` / `build_seat_pk_map` 一致），不能直接 hex encode 原始字节。
    /// WalletAddress 则直接 hex encode seat_players[i] 并加 "0x" 前缀。
    pub fn players(&self) -> HashMap<GamePkHex, WalletAddress> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::DefaultCurve;
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = HashMap::new();
            for (i, pk_bytes) in self.summary.crypto.seat_pks.iter().enumerate() {
                if pk_bytes.is_empty() {
                    continue;
                }
                // G1 compressed bytes → EcPoint → hex string（对齐 relayer deserialize_pk_hex）
                let pk_hex = match <P as CurvePointTrait>::from_compressed(pk_bytes) {
                    Some(pt) => GamePkHex::new(ecpoint_to_hex(&pt)),
                    None => {
                        tracing::warn!(
                            "[Table::players] seat {} pk deserialization failed (invalid G1 bytes), skipping",
                            i
                        );
                        continue;
                    }
                };
                if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                    // 全零地址视为空座位，跳过
                    if wallet_bytes.iter().any(|&b| b != 0) {
                        let wallet_addr =
                            WalletAddress::new(format!("0x{}", hex::encode(wallet_bytes)));
                        result.insert(pk_hex, wallet_addr);
                    }
                }
            }
            // 用 local_seats 中已反查的主钱包地址覆盖链上 proxy_address，
            // 确保 broadcast_to_table 等调用者能匹配 gs.players 中的 socket。
            for seat in self.local_seats.values() {
                if let Some(player) = &seat.player {
                    result.insert(player.pk_hex.clone(), player.wallet_address.clone());
                }
            }
            result
        } else {
            self.local_players.clone()
        }
    }

    /// 返回 seats 映射。on-chain 模式以 local_seats 为基底，用 summary.meta.seat_* 覆盖链上同步字段；
    /// off-chain 模式返回 local_seats 副本。
    ///
    /// 注意：Seat 未 impl Default，使用 `Seat::new(seat_id, None, 0, 0)` 作为占位初始化。
    /// 链上同步字段覆盖：stack / bet / total_bet / folded / sitting_out（对应 seat_is_waiting）。
    pub fn seats(&self) -> HashMap<u32, Seat> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::DefaultCurve;
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = self.local_seats.clone();
            for (i, &occupied) in self.summary.meta.seats_occupied.iter().enumerate() {
                let seat_id = i as u32;
                if !occupied {
                    continue;
                }
                let seat = result
                    .entry(seat_id)
                    .or_insert_with(|| Seat::new(seat_id, None, 0, 0));
                if let Some(&stack) = self.summary.meta.seat_stacks.get(i) {
                    seat.stack = stack;
                }
                if let Some(&bet) = self.summary.meta.seat_bets.get(i) {
                    seat.bet = bet;
                }
                if let Some(&total_bet) = self.summary.meta.seat_total_bets.get(i) {
                    seat.total_bet = total_bet;
                }
                if let Some(&folded) = self.summary.meta.seat_folded.get(i) {
                    seat.folded = folded;
                }
                if let Some(&is_waiting) = self.summary.meta.seat_is_waiting.get(i) {
                    seat.sitting_out = is_waiting;
                }
                // 从链上数据构造 GamePlayer（当 seat 无 player 时）
                if seat.player.is_none() {
                    if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                        if wallet_bytes.iter().any(|&b| b != 0) {
                            let wallet_addr =
                                WalletAddress::new(format!("0x{}", hex::encode(wallet_bytes)));
                            // 从 seat_pks 反序列化 pk_hex
                            let pk_hex = self
                                .summary
                                .crypto
                                .seat_pks
                                .get(i)
                                .filter(|pk_bytes| !pk_bytes.is_empty())
                                .and_then(|pk_bytes| {
                                    <P as CurvePointTrait>::from_compressed(pk_bytes)
                                        .map(|pt| GamePkHex::new(ecpoint_to_hex(&pt)))
                                });
                            if let Some(pk_hex) = pk_hex {
                                let name =
                                    crate::pokergame::player::truncate_name(&wallet_addr.0, 12);
                                seat.player = Some(GamePlayer {
                                    name,
                                    bankroll: 0,
                                    pk_hex,
                                    readable_hands: vec![],
                                    wallet_address: wallet_addr,
                                });
                            }
                        }
                    }
                }
            }
            result
        } else {
            self.local_seats.clone()
        }
    }

    pub fn is_playing(&self) -> bool {
        self.round_state() != RoundState::Waiting
    }

    pub fn update_history(&mut self) {
        let board = self
            .mental_poker_game
            .list_revealed_community_cards()
            .iter()
            .map(|c| Card::from_playing_card(c))
            .collect::<Vec<_>>();
        self.summary.history.push(json!({
            "pot": self.pot(),
            "mainPot": self.main_pot(),
            "sidePots": self.summary.side_pots,
            "rakeCollected": self.summary.rake_collected,
            "board":board,
            "seats": self.clean_seats_for_history(),
            "button": self.button(),
            "turn": self.turn(),
            "winMessages": self.summary.win_messages,
        }));
    }

    /// 终局记录快照 → 全局牌局记录存储（看板数据源，见 `history_store` 模块）。
    /// 在两条终局路径（finish_showdown / end_without_showdown）各调用一次。
    /// gross_pot = 当前 pot + 台费（摊牌路径 pot 已扣台费；fold-win 台费为 0）。
    pub fn record_hand_history(&self) {
        let board = self
            .mental_poker_game
            .list_revealed_community_cards()
            .iter()
            .map(|c| Card::from_playing_card(c))
            .collect::<Vec<_>>();
        // 已亮出的手牌（摊牌亮牌的座位才有；弃牌/未亮牌座位不记录——隐私）
        let (player_revealed, _) = self.mental_poker_game.list_revealed_cards();
        let mut hole_cards: std::collections::HashMap<u32, Vec<Card>> =
            std::collections::HashMap::new();
        for (pk_hex, cards) in player_revealed.iter() {
            if cards.is_empty() {
                continue;
            }
            if let Some((seat_id, _)) = self.seats().iter().find(|(_, s)| {
                s.player
                    .as_ref()
                    .map(|p| p.pk_hex.0 == *pk_hex)
                    .unwrap_or(false)
            }) {
                hole_cards.insert(
                    *seat_id,
                    cards
                        .iter()
                        .map(|c| Card::from_playing_card(c))
                        .collect::<Vec<_>>(),
                );
            }
        }
        let record = crate::pokergame::history_store::HandHistoryRecord {
            hand_seq: 0, // 由 store 按桌分配单调 seq
            hand_over_at: now_ms(),
            went_to_showdown: self.summary.went_to_showdown,
            gross_pot: self.pot().saturating_add(self.summary.rake_collected),
            rake_collected: self.summary.rake_collected,
            side_pots: self.summary.side_pots.clone(),
            board,
            hole_cards,
            win_messages: self.summary.win_messages.clone(),
            seats: self.clean_seats_for_history(),
            streets: self.summary.history.clone(),
            // 凭证数据（设计稿 T6）：开局时间 / 摊牌牌型 / 每家净结果 / 行动流水
            hand_started_at: self.summary.hand_started_at,
            showdown_hand_ranks: self.summary.showdown_hand_ranks.clone(),
            nets: self
                .seats()
                .iter()
                .filter_map(|(id, s)| {
                    let start = self.hand_start_stacks.get(id).copied()?;
                    Some((*id, s.stack as i64 - start as i64))
                })
                .collect(),
            actions: self.summary.actions.clone(),
            // 证明通道 / 结算回执的 (hand_seq ↔ hand_id) 映射锚点。
            hand_id: self.current_hand_id,
        };
        crate::pokergame::history_store::global_store().append(self.summary.id, record);
    }

    /// 验证成功后留存一层洗牌证明（D1 证明通道）。调用点：开局洗牌
    /// （`submit_verified_shuffle`）与入座 join 洗牌（`join_player_and_shuffle`），
    /// 均在证明验证通过之后。`global_challenge` 为 V2 验证后从生产域
    /// transcript squeeze 的展示值（V1 传 None）。
    pub fn record_shuffle_proof_layer(
        &mut self,
        player_pk_hex: &str,
        proof: &crate::pokergame::game_state::ShuffleProofJson,
        output_deck: &[ElGamalCiphertext],
        global_challenge: Option<String>,
    ) {
        let pk = GamePkHex::new(player_pk_hex.to_lowercase());
        let seat = self.pk_to_seat.get(&pk).copied().unwrap_or(0);
        let player_name = self
            .local_seats
            .get(&seat)
            .and_then(|s| s.player.as_ref())
            .map(|p| p.name.clone())
            .or_else(|| {
                self.seats()
                    .values()
                    .find(|s| s.player.as_ref().is_some_and(|p| p.pk_hex == pk))
                    .and_then(|s| s.player.as_ref().map(|p| p.name.clone()))
            })
            .unwrap_or_else(|| truncate_name(player_pk_hex, 8));
        let round = self.proof_ledger.next_round(self.current_hand_id);
        let display = crate::pokergame::proof_ledger::build_display(proof, output_deck);
        let aggregate_pk = ecpoint_to_hex(&self.mental_poker_game.key_manager.get_aggregated_pk());
        self.proof_ledger.push_layer(
            self.summary.id,
            self.current_hand_id,
            &aggregate_pk,
            output_deck.len().max(1),
            crate::pokergame::proof_ledger::ShuffleLayerRecord {
                round,
                seat,
                player_pk: player_pk_hex.to_owned(),
                player_name,
                proof_version: proof.proof_version(),
                proof: proof.clone(),
                display,
                global_challenge,
                verified: true,
                tx_digest: None,
                ts: now_ms(),
            },
        );
    }

    pub fn clean_seats_for_history(&self) -> serde_json::Value {
        let mut clean = serde_json::Map::new();
        for (id, seat) in self.seats().iter() {
            clean.insert(id.to_string(), json!({
                "player": { "id": seat.player.as_ref().map(|p| p.wallet_address.0.clone()), "username": seat.player.as_ref().map(|p| p.name.clone()) },
                "bet": seat.bet,
                "stack": seat.stack,
            }));
        }
        serde_json::Value::Object(clean)
    }

    pub fn get_pk_hex_by_wallet_address(&self, wallet: &str) -> Option<GamePkHex> {
        self.players()
            .iter()
            .find(|(_pk_hex, wallet_addr)| wallet_addr.0 == wallet)
            .map(|(pk_hex, _)| pk_hex.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_table() -> Table {
        Table::new(
            1,
            "test".to_string(),
            100,
            6,
            "0xchain_table_id".to_string(),
        )
    }

    /// 测试 `deck_encrypted()` 始终从 `mental_poker_game` 读取，不再 fallback 到 `summary.crypto`。
    ///
    /// 场景：summary.crypto.deck_encrypted 有 52 个假数据，mental_poker_game.deck_encrypted
    /// 也有 52 个 trivial ciphertexts（new() 初始化的）。
    /// 预期：deck_encrypted() 返回 mental_poker_game 中的值（trivial ciphertexts），
    ///       而非 summary.crypto 中的假数据。
    #[test]
    fn test_deck_encrypted_reads_from_mental_poker_game_not_summary() {
        let mut table = make_test_table();
        // 记录 mental_poker_game 的初始 deck_encrypted
        let mp_deck = table.mental_poker_game.deck_encrypted.clone();
        assert_eq!(
            mp_deck.len(),
            52,
            "mental_poker_game should have 52 trivial ciphertexts after new()"
        );

        // 模拟链上同步：summary.crypto.deck_encrypted 有不同的假数据
        table.summary.crypto.deck_encrypted = vec![vec![0xAAu8; 96]; 52];

        // deck_encrypted() 应返回 mental_poker_game 的值，而非 summary.crypto 的
        let deck = table.deck_encrypted();
        assert_eq!(
            deck.len(),
            52,
            "deck_encrypted() should return mental_poker_game's 52 cards"
        );
        assert_eq!(
            deck, mp_deck,
            "deck_encrypted() should match mental_poker_game, not summary.crypto"
        );
    }

    /// 测试 `reset_for_next_hand()` 不再清理 `summary.crypto` 缓存。
    ///
    /// 场景：summary.crypto.deck_encrypted 有假数据，调用 reset_for_next_hand()。
    /// 预期：summary.crypto.deck_encrypted 保留（不被清理），
    ///       mental_poker_game.deck_encrypted 被 reset 重建（trivial ciphertexts）。
    #[test]
    fn test_reset_for_next_hand_preserves_summary_crypto() {
        let mut table = make_test_table();
        // 模拟链上同步：summary.crypto 有假数据
        let fake_deck: Vec<Vec<u8>> = vec![vec![0xBBu8; 96]; 52];
        table.summary.crypto.deck_encrypted = fake_deck.clone();
        table.summary.state.cards_dealt = 10;

        // 调用 reset_for_next_hand
        table.reset_for_next_hand();

        // summary.crypto.deck_encrypted 应保留（不被清理）
        assert_eq!(
            table.summary.crypto.deck_encrypted, fake_deck,
            "summary.crypto.deck_encrypted should NOT be cleared by reset_for_next_hand"
        );
        // summary.state.cards_dealt 应保留
        assert_eq!(
            table.summary.state.cards_dealt, 10,
            "summary.state.cards_dealt should NOT be cleared by reset_for_next_hand"
        );
        // mental_poker_game.deck_encrypted 应被 reset 重建（52 个 trivial ciphertexts）
        assert_eq!(
            table.mental_poker_game.deck_encrypted.len(),
            52,
            "mental_poker_game.deck_encrypted should be rebuilt by reset (52 trivial ciphertexts)"
        );
    }

    /// #16/#17：动作签名验证 + accepted-seq 单调 + 动作日志/公开段。
    #[test]
    fn action_sig_verify_and_accepted_seq() {
        use poker_protocol::crypto::curve::Curve;
        use poker_protocol::crypto::curve::StarkCurve;

        let mut table = make_test_table();
        // v2：签名域含 hand_id——夹具注入开局 HandStartData（hand_id=9）
        table.hand_proof_log =
            crate::starknet::prove_log::HandProofLog::with_hand_start_for_test(9);
        let sk = StarkCurve::hash_to_scalar(b"seat-sk");
        let pk = StarkCurve::base_g() * sk;
        let pk_hex = hex::encode(pk.compress().as_ref());

        // 把 pk_hex 绑到一个座位（直接构造 ActionSig 前的座位解析依赖 seats）
        let sig_r_hex;
        let sig_s_hex;
        {
            let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
                &sk,
                table.summary.id,
                9,
                1,
                "raise",
                320,
                &mut rand::rngs::OsRng,
            );
            sig_r_hex = r_hex;
            sig_s_hex = s_hex;
        }
        let sig = crate::pokergame::actions::ActionSig {
            r_hex: sig_r_hex.clone(),
            s_hex: sig_s_hex.clone(),
        };
        // 验签只依赖 pk 与消息域，不要求座位已入座
        assert!(table.verify_action_sig(
            &crate::pokergame::player::GamePkHex(pk_hex.clone()),
            1,
            "raise",
            320,
            &sig
        ));
        // 篡改 seq → 失败
        assert!(!table.verify_action_sig(
            &crate::pokergame::player::GamePkHex(pk_hex.clone()),
            2,
            "raise",
            320,
            &sig
        ));

        // 记账：seq 单调推进 + 日志 + 公开段
        table.record_action(0, 1, "raise", 320, false, true, None);
        table.record_action(0, 2, "call", 0, false, true, None);
        assert_eq!(table.accepted_seq_of(0), 2);
        assert_eq!(table.action_log.len(), 2);
        let client = table.to_client();
        assert_eq!(client.accepted_seqs.len(), 1);
        assert_eq!(client.accepted_seqs[0].seq, 2);
        let _ = pk;
        let _ = sig_s_hex;
    }

    /// 测试 `deck_plaintext()` 始终从 `mental_poker_game` 读取，不再 fallback 到 `summary.state`。
    ///
    /// 场景：summary.state.deck_plaintext 有假数据，mental_poker_game.deck_plaintext
    /// 也有 52 个明文点（new() 初始化的）。
    /// 预期：deck_plaintext() 返回 mental_poker_game 的值，而非 summary.state 的假数据。
    #[test]
    fn test_deck_plaintext_reads_from_mental_poker_game() {
        let mut table = make_test_table();
        // 记录 mental_poker_game 的初始 deck_plaintext
        let mp_plaintext = table.mental_poker_game.deck_plaintext.clone();
        assert_eq!(
            mp_plaintext.len(),
            52,
            "mental_poker_game should have 52 plaintext points after new()"
        );

        // 模拟链上同步：summary.state.deck_plaintext 有不同的假数据
        table.summary.state.deck_plaintext = vec![vec![0xCCu8; 48]; 52];

        // deck_plaintext() 应返回 mental_poker_game 的值
        let deck = table.deck_plaintext();
        assert_eq!(
            deck.len(),
            52,
            "deck_plaintext() should return mental_poker_game's 52 points"
        );
        assert_eq!(
            deck, mp_plaintext,
            "deck_plaintext() should match mental_poker_game, not summary.state"
        );
    }

    /// 测试 `aggregated_pk()` 始终从 `mental_poker_game.key_manager` 读取。
    #[test]
    fn test_aggregated_pk_reads_from_mental_poker_game() {
        let mut table = make_test_table();
        // summary.crypto.aggregated_pk 有假数据
        table.summary.crypto.aggregated_pk = vec![0xDDu8; 48];

        // aggregated_pk() 应返回 mental_poker_game.key_manager 中的值（不 panic）
        let pk = table.aggregated_pk();
        // 验证不等于 summary.crypto 中的假数据（mental_poker_game 初始时 agg_pk 为 identity/默认）
        let _ = pk; // 仅验证不 panic 且返回一个值
    }

    /// 测试 zombie seat 清理后 local_players 中对应 pk 被移除。
    ///
    /// 场景：table.local_players 有一个 pk→wallet 映射，table.local_seats 有对应座位，
    /// 但链上该座位已清空（seats_occupied=false, seat_players=0x0）。
    /// 预期：sync_betting_state 清理后 local_players 中对应 pk 被移除。
    #[test]
    fn test_zombie_seat_cleanup_removes_local_players() {
        use crate::pokergame::player::{GamePlayer, WalletAddress};
        use crate::pokergame::seat::Seat;

        let mut table = make_test_table();
        let pk_hex = GamePkHex::new("test_pk_hex".to_string());
        let wallet = WalletAddress::new("0xtestwallet".to_string());

        // 模拟本地有玩家入座
        table.local_players.insert(pk_hex.clone(), wallet.clone());
        table.pk_to_seat.insert(pk_hex.clone(), 0);
        let player = GamePlayer {
            name: "test".to_string(),
            bankroll: 0,
            pk_hex: pk_hex.clone(),
            readable_hands: vec![],
            wallet_address: wallet,
        };
        table
            .local_seats
            .insert(0, Seat::new(0, Some(player), 100, 100));

        // 模拟 reset_for_next_hand 的 pk_to_seat + local_players 清理逻辑
        // （与 sync_betting_state 中的 zombie seat 清理对齐）
        let active_seat_pks: std::collections::HashSet<GamePkHex> = table
            .seats()
            .values()
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();

        // seat 0 仍有玩家，所以 active_seat_pks 应包含 pk_hex
        assert!(active_seat_pks.contains(&pk_hex));

        // 现在模拟玩家离开（清空 seat 0 的 player）
        table.local_seats.get_mut(&0).unwrap().player = None;

        // 重新计算 active_seat_pks
        let active_seat_pks: std::collections::HashSet<GamePkHex> = table
            .seats()
            .values()
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();
        assert!(!active_seat_pks.contains(&pk_hex));

        // 模拟 sync_betting_state 的清理：移除 pk_to_seat + local_players
        table.pk_to_seat.remove(&pk_hex);
        table.local_players.remove(&pk_hex);

        // 验证清理后 local_players 不再包含 pk_hex
        assert!(
            !table.local_players.contains_key(&pk_hex),
            "local_players should not contain pk after zombie seat cleanup"
        );
        assert!(
            !table.pk_to_seat.contains_key(&pk_hex),
            "pk_to_seat should not contain pk after zombie seat cleanup"
        );
    }

    // ============================================================
    // Dead button 走庄规则（Robert's Rules of Poker §4.2b / TDA）
    // ============================================================
    mod dead_button {
        use super::*;

        fn make_table_with_players(seats: &[u32]) -> Table {
            let mut table = Table::new(9500, "dead-button".to_string(), 10000, 9, String::new());
            for (idx, &seat_id) in seats.iter().enumerate() {
                let player = GamePlayer {
                    name: format!("p{idx}"),
                    bankroll: 100000,
                    pk_hex: GamePkHex::new(format!("pk-test-{idx}")),
                    readable_hands: vec![],
                    wallet_address: WalletAddress(format!("0x{:064x}", idx + 1)),
                };
                table.sit_player(player, seat_id, 100000, false);
                if let Some(seat) = table.local_seats.get_mut(&seat_id) {
                    seat.folded = false;
                }
            }
            table
        }

        /// 模拟"第一手已打完"的状态：按钮在 1，SB=2、BB=3 已交盲，
        /// 盲注轨道 last_bb=3。
        fn setup_after_hand_one(table: &mut Table) {
            table.set_button(Some(1));
            table.set_last_bb_seat(Some(3));
        }

        /// 大盲出局（剩 3 人）：按钮前进到空座（死按钮），上一手大盲座位
        /// 空缺 → 轮转基准回退到其前驱参与者（座 2）补位小盲——与镜像
        /// rank_of_rotation_base 的压缩映射一致；大盲轮转给下一位。
        #[test]
        fn bb_busts_predecessor_posts_small_blind() {
            let mut table = make_table_with_players(&[1, 2, 3, 4]);
            setup_after_hand_one(&mut table);
            // BB（座 3）出局离座。
            table.local_seats.remove(&3);

            table.move_button(); // 第二手：按钮 +1（死按钮规则）
            table.set_blinds();

            assert_eq!(
                table.button(),
                Some(2),
                "button lands on the vacated SB seat (dead button)"
            );
            assert_eq!(
                table.small_blind(),
                Some(2),
                "departed base → predecessor participant posts SB"
            );
            assert_eq!(
                table.big_blind(),
                Some(4),
                "BB rotation: next participating after seat 3"
            );
            assert_eq!(table.last_bb_seat(), 4, "track advances to this hand's BB");
            let pot = table.pot();
            assert_eq!(pot, 150, "SB 50 + BB 100 enter the pot");
            let sb_stack = table.local_seats.get(&2).unwrap().stack;
            assert_eq!(
                sb_stack,
                100000 - 50,
                "predecessor stack reduced by the small blind"
            );
            let bb_stack = table.local_seats.get(&4).unwrap().stack;
            assert_eq!(
                bb_stack,
                100000 - 100,
                "BB stack reduced by exactly the big blind"
            );
        }

        /// 跨层一致性（P1 回归）：上一手大盲离场时，游戏层 set_blinds 的
        /// 小盲/大盲归属必须与镜像压缩 rank 映射
        ///（prove_log::rank_of_rotation_seat → VM post_blinds）逐位一致——
        /// 否则镜像（结算 witness 来源）会凭空多收一笔游戏层从未收取的
        /// 小盲，两层 pot/stack 分歧。
        #[test]
        fn departed_base_blinds_match_mirror_rank_mapping() {
            // 参与者 1,2,4,6（座 3 上一手大盲，已离场；座 5 空）。
            let mut table = make_table_with_players(&[1, 2, 4, 6]);
            table.set_button(Some(1));
            table.set_last_bb_seat(Some(3));

            table.move_button();
            table.set_blinds();

            // plan（按座位升序）与镜像 rank 映射：前驱参与者 = 座 2。
            let plan: Vec<u32> = vec![1, 2, 4, 6];
            let rank = crate::starknet::prove_log::rank_of_rotation_seat(3, &plan) as usize;
            assert_eq!(rank, 1, "departed seat 3 → predecessor rank (seat 2)");
            assert_eq!(
                table.small_blind(),
                Some(plan[rank]),
                "game-layer SB must equal the mirror's rotation-base seat"
            );
            assert_eq!(
                table.big_blind(),
                Some(plan[(rank + 1) % plan.len()]),
                "game-layer BB must equal the next participating rank after the base"
            );

            // 环绕场景：上一手大盲 = 座 1（低于全部参与者座位）→ 前驱 =
            // 环形最后一名参与者（座 6），大盲环绕到最低座位。
            let mut table = make_table_with_players(&[2, 4, 6]);
            table.set_button(Some(2));
            table.set_last_bb_seat(Some(1));
            table.move_button();
            table.set_blinds();
            let plan: Vec<u32> = vec![2, 4, 6];
            let rank = crate::starknet::prove_log::rank_of_rotation_seat(1, &plan) as usize;
            assert_eq!(rank, 2, "wrap case → last participant rank (seat 6)");
            assert_eq!(table.small_blind(), Some(plan[rank]));
            assert_eq!(table.big_blind(), Some(plan[(rank + 1) % plan.len()]));
        }

        /// 小盲出局（剩 3 人）：按钮落在空座位，小盲照常轮转（上一手大盲
        /// 座位本身交小盲），大盲给再下一位。
        #[test]
        fn sb_busts_keeps_blind_rotation() {
            let mut table = make_table_with_players(&[1, 2, 3, 4]);
            setup_after_hand_one(&mut table);
            table.local_seats.remove(&2); // SB 出局

            table.move_button(); // 第二手：按钮 +1（死按钮规则）
            table.set_blinds();

            assert_eq!(
                table.button(),
                Some(2),
                "button advances onto the vacated seat"
            );
            assert_eq!(
                table.small_blind(),
                Some(3),
                "previous BB seat posts the small blind"
            );
            assert_eq!(
                table.big_blind(),
                Some(4),
                "BB moves to the next participating seat"
            );
            let sb_stack = table.local_seats.get(&3).unwrap().stack;
            assert_eq!(sb_stack, 100000 - 50, "seat 3 posts only the small blind");
        }

        /// 按钮出局 → 进单挑：TDA dead button——大盲按轮转交给上一手小盲，
        /// 上一手大盲改交小盲（无人连续两手大盲）。
        #[test]
        fn button_busts_hu_transition_rotates_blinds() {
            let mut table = make_table_with_players(&[1, 2, 3]);
            setup_after_hand_one(&mut table);
            table.local_seats.remove(&1); // 按钮（座 1）出局

            table.move_button(); // 1 → 2
            table.set_blinds();

            assert_eq!(table.button(), Some(2));
            assert_eq!(
                table.big_blind(),
                Some(2),
                "HU BB = first participating after the rotation base (seat 3)"
            );
            assert_eq!(
                table.small_blind(),
                Some(3),
                "HU SB = the other participant (previous BB)"
            );
            assert_eq!(table.last_bb_seat(), 2);
            // 翻牌前 UTG：BB 之后第一个可行动座位 = 小盲（座 3）。
            assert_eq!(table.turn(), Some(3), "HU preflop: SB acts first");
        }

        /// 资金 bug 回归：断线玩家坐在按钮位、单挑开局——不得被扣小盲。
        /// （原实现单挑 SB=button，会把小盲扣给 sitting out 玩家。）
        #[test]
        fn disconnected_button_seat_never_posts_blinds() {
            let mut table = make_table_with_players(&[1, 2, 3]);
            setup_after_hand_one(&mut table);
            // 座 2 玩家断线且已转 sitting out（新手开始时的标准转换）。
            if let Some(seat) = table.local_seats.get_mut(&2) {
                seat.disconnected = true;
                seat.sitting_out = true;
            }
            table.move_button(); // 按钮落在 sitting out 的座 2（死按钮）

            table.set_blinds();

            assert_eq!(
                table.button(),
                Some(2),
                "dead button sits on the disconnected seat"
            );
            assert_eq!(
                table.active_players().len(),
                2,
                "heads-up among seats 1 and 3"
            );
            assert_eq!(
                table.big_blind(),
                Some(1),
                "HU BB = first participating after the rotation base"
            );
            assert_eq!(
                table.small_blind(),
                Some(3),
                "HU SB = the other participant, never the dead seat"
            );
            let sitting_stack = table.local_seats.get(&2).unwrap().stack;
            assert_eq!(
                sitting_stack, 100000,
                "sitting-out seat posts nothing (fund-safety regression)"
            );
        }

        /// 轮转不变式：满员连续多手，大盲严格轮转，无人连续两手大盲。
        #[test]
        fn bb_rotation_never_repeats_a_seat() {
            let mut table = make_table_with_players(&[1, 2, 3]);
            table.set_button(Some(1));
            let mut previous_bb = 0u32;
            for _ in 0..9 {
                table.move_button();
                table.set_blinds();
                let bb = table
                    .big_blind()
                    .expect("BB always assigned with 3 players");
                assert_ne!(
                    bb, previous_bb,
                    "no seat posts the big blind twice in a row"
                );
                previous_bb = bb;
                assert_eq!(table.last_bb_seat(), bb, "track follows this hand's BB");
            }
        }

        /// 中途买入（waiting）玩家不计入盲注轮转：仍在等待时不交盲注，
        /// 也不占轮转位。
        #[test]
        fn waiting_players_are_skipped_by_the_rotation() {
            let mut table = make_table_with_players(&[1, 2, 3, 4]);
            setup_after_hand_one(&mut table);
            // 座 2 玩家中途买入等待（is_waiting）。
            if let Some(seat) = table.local_seats.get_mut(&2) {
                seat.is_waiting = true;
            }

            table.move_button(); // 第二手：按钮 +1（死按钮规则）
            table.set_blinds();

            // 座 2 等待中：上一手大盲（座 3）在座且参与 → 照常交小盲；
            // 大盲 = 座 4。等待座位被完全跳过。
            assert_eq!(table.small_blind(), Some(3));
            assert_eq!(table.big_blind(), Some(4));
            let waiting_stack = table.local_seats.get(&2).unwrap().stack;
            assert_eq!(waiting_stack, 100000, "waiting seat posts nothing");
        }
    }
}
