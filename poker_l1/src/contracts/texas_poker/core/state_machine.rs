//! Texas Poker 状态机推进（移植自 `texas_poker_move/sources/table.move` 内部函数）。
//!
//! 本模块实现桌台状态机的所有状态转换逻辑，包括：
//! - 洗牌协议（submit_shuffle_v2 / advance_shuffle）
//! - 揭示协议（start_*_reveal_phase / check_reveal_phase_complete）
//! - 重构协议（start_reconstruct / on_complete_reconstruct）
//! - 下注流程（post_blinds / start_betting_round / advance_turn / advance_round）
//! - 玩家动作（fold / check / call / raise / fold_with_proof）
//! - 结算与重置（settle_hand / end_without_showdown / reset_for_next_hand）
//! - 超时驱动（advance_deadline / on_*_timeout）
//!
//! # ZK 验证策略
//!
//! 所有 verify 调用经 `utils::verify_or_skip(utils::test_only_crypto_skip(), ...)`
//! 包装。dev chain 默认全部 skip，mainnet 由 governance 强制 false。
//!
//! # 调用约定
//!
//! 所有公开函数签名：
//! ```text
//! fn apply_xxx(table: &mut TexasPokerTable, ..., events: &mut Vec<TexasPokerEvent>) -> PokerL1Result<T>
//! ```
//! - `events` 由调用方（dispatch.rs）创建并传入，函数内通过 `events::emit_event` 追加
//! - 外部命令序号仅由 dispatch 原子提交边界递增 `call_seq`
//! - 错误用 `PokerL1Error::Serialization` 包裹（带上下文 message）

use super::utils::{G1Projective, g1_identity};
use borsh::{BorshDeserialize, BorshSerialize};

use poker_protocol::crypto::types::{DefaultCurve, ECPoint, ElGamalCiphertext};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, LeaveKind};
use poker_protocol::zk_shuffle::reconstruction::{
    ReconstructProof, ReconstructionStatement, apply_reconstruction_contributions,
    canonical_base_deck,
};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;

use super::betting::BettingRound;
#[cfg(test)]
use super::card::BoardCards;
use super::card::{Card, HoleCards};
use super::constants::*;
use super::events::{
    self, DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE, DECK_REBUILT_REASON_SHUFFLE_TIMEOUT,
    POT_TYPE_MAIN, POT_TYPE_SIDE, TRIGGER_ACTION_CALL_ALL_IN, TRIGGER_ACTION_RAISE_ALL_IN,
    TexasPokerEvent,
};
use super::settlement::{self, SettlementPlan};
use super::types::{
    CipherDeck, HandPhase, NO_SEAT, PartialHoleCard, PlayingSeatStatus, RevealAssignment,
    RevealPurpose, RevealTarget, RitStartStreet, RunItTwiceState, Seat, SeatMask, SeatStatus,
    TexasPokerTable, seat_mask_contains, seat_mask_count, seat_mask_first, seat_mask_insert,
    seat_mask_remove, seat_mask_to_indices,
};
// 适配层（保留原 crypto/ 的自由函数 API：g1_add/g1_equal/verify_or_skip/...）。
// typed 化后字段已是 G1Projective / ElGamalCiphertext，parse_g1/serialize_g1 仅在 RPC 边界使用。
use super::utils::{
    self, g1_equal, g1_generator, g1_is_identity, g1_sub, generate_plaintext_cards,
};
#[cfg(test)]
use super::utils::{g1_add, scalar_from_u64};
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};

/// Maximum number of deterministic micro-transitions a single command may normalize.
///
/// This is a per-command bound, not a per-hand budget. One hand may run up to ~N-1 reconstruct
/// cycles, but a cycle never advances inside one normalize call: pending contributions block
/// immediately, and every timeout, contribution, and shuffler proof is its own signed command.
/// Since normalize never invents external input, a single command's cascade stays in the
/// single digits (e.g. final reconstruct contribution → reshuffle starts → blocked). The bound
/// exists so corrupt state can never turn a command into an unbounded host loop, and later
/// becomes the fixed upper bound of the Stage transition plan consumed by the tagged-union AIR.
pub const MAX_NORMALIZATION_STEPS: usize = 32;

/// One deterministic state-machine stage performed without new caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum NormalizationStep {
    /// Finalize a fully collected reconstruction and enter reconstruct shuffle.
    CompleteReconstruct,
    /// Select the next canonical shuffler or complete the shuffle phase.
    AdvanceShuffle,
    /// Materialize a fully decrypted reveal phase and enter its next phase.
    CompleteReveal,
    /// Award an uncontested hand and reset it.
    EndWithoutShowdown,
    /// Collect current bets and advance to the next street.
    AdvanceBettingRound,
}

/// Bounded deterministic suffix appended to an externally authorized command.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct NormalizationReport {
    /// Ordered stages applied after the command itself.
    pub steps: Vec<NormalizationStep>,
}

/// 控制逻辑入 AIR：单个 normalize micro-step 的执行轨迹——该步前后的
/// 完整表快照（witness 生产的原料；`pre` 与原子回滚用的 before 克隆
/// 同源，零额外语义）。
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct NormalizationStepTrace {
    pub step: NormalizationStep,
    pub pre: TexasPokerTable,
    pub post: TexasPokerTable,
}

/// 一次（或一段）dispatch 的规范化轨迹：按执行顺序的全部 micro-step。
/// 经线程局部槽捕获（[`arm_normalization_trace`] / [`take_normalization_trace`]），
/// 仅证明 armed 的会话开启——关闭时零开销，不进 DispatchOutput。
#[derive(Clone, Debug, Default, BorshSerialize, BorshDeserialize)]
pub struct NormalizationTrace {
    pub steps: Vec<NormalizationStepTrace>,
}

thread_local! {
    static NORMALIZE_TRACE_SLOT: std::cell::RefCell<Option<NormalizationTrace>> =
        const { std::cell::RefCell::new(None) };
}

/// 武装本线程的轨迹捕获：此后 [`normalize_until_blocked`] 族执行的每个
/// micro-step 追加到槽内（含命令内部级联与 dispatch 级收尾）。调用方
/// （texas VmTable，证明 armed）负责在 dispatch 前后 arm/take 配对。
pub fn arm_normalization_trace() {
    NORMALIZE_TRACE_SLOT.with(|slot| {
        *slot.borrow_mut() = Some(NormalizationTrace::default());
    });
}

/// 取走并解除本线程的轨迹捕获（未武装返回 None）。与
/// [`arm_normalization_trace`] 配对；间隙期（未 armed）的 normalize 零开销。
pub fn take_normalization_trace() -> Option<NormalizationTrace> {
    NORMALIZE_TRACE_SLOT.with(|slot| slot.borrow_mut().take())
}

/// 轨迹槽是否已武装（命令内联级联的快照克隆据此门控——关闭时零开销）。
pub fn normalization_trace_armed() -> bool {
    NORMALIZE_TRACE_SLOT.with(|slot| slot.borrow().is_some())
}

thread_local! {
    /// CompleteReveal 行的边界锚：窗口完成在 `start_betting_round` 内触发
    /// all-in runout 时，canonical 行链要求 SubmitReveal（RevealStreet
    /// opening）的 post 停在**新开的下注轮**、runout 以独立 AdvanceRound
    /// 行呈现。该槽由 runout 分支写入（armed 时），witness 生产者的捕获
    /// 包装读取后清除。
    static COMPLETION_BOUNDARY: std::cell::RefCell<Option<TexasPokerTable>> =
        const { std::cell::RefCell::new(None) };
}

/// runout 边界写/读（见 [`COMPLETION_BOUNDARY`]）。
pub fn set_completion_boundary(state: &TexasPokerTable) {
    COMPLETION_BOUNDARY.with(|slot| {
        *slot.borrow_mut() = Some(state.clone());
    });
}

/// 取走边界锚（无则 None）。
pub fn take_completion_boundary() -> Option<TexasPokerTable> {
    COMPLETION_BOUNDARY.with(|slot| slot.borrow_mut().take())
}

fn record_step_trace(step: NormalizationStep, pre: &TexasPokerTable, post: &TexasPokerTable) {
    // 未武装时 borrow_mut 后立即返回——仅一次 RefCell 检查的开销。
    NORMALIZE_TRACE_SLOT.with(|slot| {
        let mut guard = slot.borrow_mut();
        if let Some(trace) = guard.as_mut() {
            trace.steps.push(NormalizationStepTrace {
                step,
                pre: pre.clone(),
                post: post.clone(),
            });
        }
    });
}

/// Canonical timeout class consumed by `AdvanceDeadline`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(missing_docs)]
pub enum DeadlineKind {
    Reconstruct,
    Shuffle,
    Reveal,
    Betting,
    ShowdownDisplay,
}

/// Result of attempting to consume the table's single currently actionable deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(missing_docs)]
pub enum AdvanceDeadlineOutcome {
    /// The table is waiting for a signed command or crypto proof, not time.
    NoDeadline,
    /// A deadline exists but consensus time has not reached it.
    NotDue {
        kind: DeadlineKind,
        subject: u8,
        deadline_ms: u64,
    },
    /// Betting time-bank was consumed and the same deadline was extended.
    TimeBankExtended { seat_index: u8, deadline_ms: u64 },
    /// The expired deadline was consumed and its timeout transition applied.
    Advanced { kind: DeadlineKind, subject: u8 },
}

/// Exact canonical execution trace of one `advance_deadline` command.
///
/// The state machine normalizes deterministic work both before inspecting the
/// active deadline and after applying an expired-deadline transition.  Keeping
/// both reports prevents a native prover from inferring an outcome only
/// from the final table image and accidentally accepting a mixed cascade under
/// a narrower relation identity.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdvanceDeadlineExecution {
    /// Deterministic stages applied before the active deadline was inspected.
    pub pre_normalization: NormalizationReport,
    /// Typed result of inspecting or consuming the active deadline.
    pub outcome: AdvanceDeadlineOutcome,
    /// Deterministic stages applied after a deadline transition.
    pub post_normalization: NormalizationReport,
}

/// Canonical player action used by the state machine and method-batch planner.
///
/// The legacy `check`, `call`, `raise`, `bet`, `auto_fold`, and `force_fold`
/// selectors remain ABI wrappers, but all of them are lowered to this small
/// tagged union before mutating table state.  Keeping the fold cause in the
/// tag preserves authorization/audit semantics without another implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlayerAction {
    /// Fold the current player for the supplied canonical event reason.
    Fold {
        /// 弃牌原因（见 `FOLD_REASON_*` 常量：0=manual, 1=auto_timeout, 2=force_admin）。
        reason: u8,
    },
    /// Match the current bet; this is a check when no chips are owed and a
    /// call/all-in call otherwise.
    MatchBet,
    /// Raise the player's round bet to an absolute amount.
    RaiseTo(u64),
}

/// Canonical funding timing for the `addon`/`rebuy` compatibility selectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundTiming {
    /// Credit the amount to the seat's next-hand pending balance.
    NextHand,
    /// Credit the amount to the current stack immediately.
    Immediate,
}

// ========== 工具：bytes↔G1 转换（typed 化后大部分不再需要） ==========

// 注：types.rs 字段已 typed 化为 G1Projective / ElGamalCiphertext，
// 原 `bytes_ct_to_g1` / `g1_ct_to_bytes` / `pk_to_g1` 已删除。
// 残余 RPC 边界转换直接使用 `utils::parse_g1` / `utils::serialize_g1`。

// ========== 状态谓词 ==========

/// 是否处于 ROUND_WAITING（允许 join/leave）。
#[must_use]
pub fn can_join_state(table: &TexasPokerTable) -> bool {
    table.round_state() == ROUND_WAITING
}

/// `can_leave_state` 与 `can_join_state` 同义。
#[must_use]
pub fn can_leave_state(table: &TexasPokerTable) -> bool {
    can_join_state(table)
}

/// 是否处于下注轮（betting_round.is_some() 且 round 在 preflop..=river）。
#[must_use]
pub fn is_betting_round(table: &TexasPokerTable) -> bool {
    table.betting_round().is_some()
        && matches!(
            table.round_state(),
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
        )
}

/// Reconcile the embedded TableVault against every canonical custody bucket.
///
/// `total_bet` is an accounting view, not an additional asset. The actual locked value is
/// represented exactly once by seat stacks,
/// pending addons, current-round bets and the collected pot. Settlement rake is not table state:
/// its matching value leaves `chip_pool` and is carried by the dispatch settlement receipt.
pub fn reconcile_table_vault(table: &TexasPokerTable) -> PokerL1Result<u64> {
    table.validate_state_schema()?;
    let _ = table.canonical_hand_phase()?;
    let mut stacks = 0u64;
    let mut pending_addons = 0u64;
    let mut current_bets = 0u64;
    let mut total_bets = 0u64;
    for seat in &table.seats {
        stacks = stacks
            .checked_add(seat.stack())
            .ok_or_else(|| PokerL1Error::Other("Texas seat stack sum overflow".into()))?;
        pending_addons = pending_addons
            .checked_add(seat.pending_addon())
            .ok_or_else(|| PokerL1Error::Other("Texas pending addon sum overflow".into()))?;
        current_bets = current_bets
            .checked_add(seat.bet())
            .ok_or_else(|| PokerL1Error::Other("Texas current bet sum overflow".into()))?;
        total_bets = total_bets
            .checked_add(seat.total_bet())
            .ok_or_else(|| PokerL1Error::Other("Texas total bet sum overflow".into()))?;
    }
    let wagers_in_custody = table
        .pot
        .checked_add(current_bets)
        .ok_or_else(|| PokerL1Error::Other("Texas wager custody sum overflow".into()))?;
    if wagers_in_custody != total_bets {
        return Err(PokerL1Error::Other(format!(
            "Texas wager ledger mismatch: pot={} current_bets={current_bets}, total_bets={total_bets}",
            table.pot
        )));
    }
    let accounted = stacks
        .checked_add(pending_addons)
        .and_then(|value| value.checked_add(wagers_in_custody))
        .ok_or_else(|| PokerL1Error::Other("Texas TableVault accounting overflow".into()))?;
    if accounted != table.chip_pool {
        return Err(PokerL1Error::Other(format!(
            "Texas TableVault invariant violated: stacks={stacks}, pending_addons={pending_addons}, pot={}, current_bets={current_bets}, accounted={accounted}, chip_pool={}",
            table.pot, table.chip_pool
        )));
    }
    Ok(accounted)
}

/// 当前是否轮到指定座位行动。
#[must_use]
pub fn is_player_turn(table: &TexasPokerTable, seat_index: u8) -> bool {
    table.current_turn() == seat_index
}

/// 是否已注册 pk（occupied 且 pk 匹配）。
#[must_use]
pub fn is_pk_registered(seats: &[Seat], pk: &G1Projective) -> bool {
    seats
        .iter()
        .any(|s| s.pk().is_some_and(|registered| &registered.0 == pk))
}

// ========== 座位/玩家辅助 ==========

/// 统计活跃玩家数（occupied && !folded && !is_waiting）。
#[must_use]
pub fn count_active_players(seats: &[Seat]) -> u8 {
    seats
        .iter()
        .filter(|s| s.is_occupied() && !s.is_folded() && !s.is_waiting())
        .count() as u8
}

/// 统计活跃占用座位数（occupied && !is_waiting，含 folded）。
#[must_use]
pub fn count_active_occupied(seats: &[Seat]) -> u8 {
    seats
        .iter()
        .filter(|s| s.is_occupied() && !s.is_waiting())
        .count() as u8
}

/// 取所有 occupied && !is_waiting 的座位索引。
#[must_use]
pub fn get_active_seat_indices(seats: &[Seat]) -> Vec<u8> {
    seats
        .iter()
        .enumerate()
        .filter(|(_, s)| s.is_occupied() && !s.is_waiting())
        .map(|(i, _)| i as u8)
        .collect()
}

/// Seat-mask form of [`get_active_seat_indices`].
#[must_use]
pub fn get_active_seat_mask(seats: &[Seat]) -> SeatMask {
    seats.iter().enumerate().fold(0, |mask, (index, seat)| {
        if seat.is_occupied() && !seat.is_waiting() {
            mask | (1u16 << index)
        } else {
            mask
        }
    })
}

/// 取 occupied && !is_waiting && !in completed 的座位集合（待洗牌者）。
#[must_use]
pub fn get_pending_seat_mask(completed: SeatMask, seats: &[Seat]) -> SeatMask {
    seats.iter().enumerate().fold(0, |mask, (index, seat)| {
        let seat_index = index as u8;
        if seat.is_occupied() && !seat.is_waiting() && !seat_mask_contains(completed, seat_index) {
            mask | (1u16 << seat_index)
        } else {
            mask
        }
    })
}

/// 环形查找下一个可行动座位（occupied && !folded && !all_in && !waiting）。
#[must_use]
pub fn find_next_active_seat(seats: &[Seat], from: u8, max: u8) -> Option<u8> {
    let n = max;
    for offset in 1..=n {
        let idx = (from + offset) % n;
        let s = &seats[idx as usize];
        if s.is_occupied() && !s.is_folded() && !s.is_all_in() && !s.is_waiting() {
            return Some(idx);
        }
    }
    None
}

/// 环形查找下一个参与本局的座位（occupied && !is_waiting）。
///
/// 与 [`find_next_active_seat`] 的区别：**不过滤 folded / all_in**。
/// 用于盲注定位（SB/BB）——盲注阶段所有参与本局的玩家都要投盲注，
/// 即使某玩家理论上已 all-in（实际盲注是第一步，不会有 folded/all_in，
/// 但保持语义清晰：只要参与本局就应被考虑为盲注候选）。
///
/// 这是 P0 修复的核心辅助：传统德州扑克的 SB/BB/UTG 必须顺时针跳过空座位
/// 找下一个参与本局的玩家，不能简单 `(button+k) % n` 取模。
#[must_use]
pub fn find_next_participating_seat(seats: &[Seat], from: u8, max: u8) -> Option<u8> {
    let n = max;
    for offset in 1..=n {
        let idx = (from + offset) % n;
        let s = &seats[idx as usize];
        if s.is_occupied() && !s.is_waiting() {
            return Some(idx);
        }
    }
    None
}

/// 是否存在可行动玩家（occupied && !folded && !all_in && !waiting）。
#[must_use]
pub fn has_actionable_player(seats: &[Seat]) -> bool {
    seats
        .iter()
        .any(|s| s.is_occupied() && !s.is_folded() && !s.is_all_in() && !s.is_waiting())
}

/// Number of live players who can still wager chips.
fn count_actionable_players(seats: &[Seat]) -> usize {
    seats
        .iter()
        .filter(|seat| {
            seat.is_occupied()
                && !seat.is_folded()
                && !seat.is_all_in()
                && !seat.is_waiting()
                && !seat.has_left_hand()
        })
        .count()
}

/// Whether no further contested betting decision is possible.
///
/// 判定 =（≥2 未弃牌）且（可行动玩家 ≤ 1）且**没有可行动玩家还欠注**：
/// 面对未跟注的水位（bet < current_bet），唯一留有筹码的玩家仍须
/// call/fold，不得跳过——all-in 加注后对手保留行动权（2026-09-14 all-in
/// e2e 复现：VM 在加注 dispatch 的 normalize 内连跳收注，对手随后的
/// call 被 "not in betting round" 拒绝，游戏层/VM 失步）。欠注且已
/// all-in 的玩家无需行动（缺口由边池处理）。与游戏层
/// `is_betting_round_complete` 及 canonical prover 侧 AdvanceRound 边界
/// （actionable seat 必须已匹配）对齐。
fn no_further_betting_possible(table: &TexasPokerTable) -> bool {
    if count_active_players(&table.seats) < 2 || count_actionable_players(&table.seats) > 1 {
        return false;
    }
    let Some(round) = table.betting_round() else {
        return false;
    };
    table.seats.iter().all(|seat| {
        let actionable = seat.is_occupied()
            && !seat.is_folded()
            && !seat.is_all_in()
            && !seat.is_waiting()
            && !seat.has_left_hand();
        !actionable || seat.bet() == round.current_bet
    })
}

// ========== PK 聚合 ==========

/// 将 pk 加入聚合 pk：None + pk = Some(pk)；Some(old) + pk = Some(old + pk)。
///
/// typed 化后 `aggregated_pk: Option<G1Projective>`，不再使用字节表示。
#[cfg(test)]
fn add_pk_to_aggregated(old: Option<&G1Projective>, new_pk: &G1Projective) -> Option<G1Projective> {
    match old {
        None => Some(*new_pk),
        Some(old_pt) => Some(g1_add(old_pt, new_pk)),
    }
}

/// 从聚合 pk 移除 pk：None 直接返回 None；Some(old) - pk 返回 Some(old - pk) 或 None（若为单位元）。
///
/// 若结果为单位元，返回 None（与 Move 端"空 Vec"语义一致）。
#[cfg(test)]
fn remove_pk_from_aggregated(
    old: Option<&G1Projective>,
    pk: &G1Projective,
) -> Option<G1Projective> {
    let old_pt = old?;
    let diff = g1_sub(old_pt, pk);
    if g1_is_identity(&diff) {
        None
    } else {
        Some(diff)
    }
}

// ========== 牌组管理 ==========

/// 初始化加密牌组：每张牌密文 = (G, plaintext_i)，相当于 sk=0 加密。
///
/// 镜像 `table.move::set_initial_encrypted_deck`（line 1121-1142）。
/// 仅覆写 `deck_state.encrypted`；明文牌点是协议常量，不再按桌持久化。
pub fn set_initial_encrypted_deck(table: &mut TexasPokerTable) -> PokerL1Result<()> {
    let plaintexts = generate_plaintext_cards(); // 52 个 G1
    let g = g1_generator();

    table.deck_state.encrypted = CipherDeck::try_from(
        plaintexts
            .iter()
            .map(|m| {
                // c1 = G, c2 = m
                ElGamalCiphertext { c1: g, c2: *m }
            })
            .collect::<Vec<_>>(),
    )?;
    table.deck_state.cards_dealt = 0;
    table.deck_state.owner_readable_hole_cards.clear();
    Ok(())
}

/// Rebuild a fresh aggregate-key deck from verified V3 contributions.
///
/// The base is the deterministic canonical encryption of every public card
/// under the table aggregate key. Each player contributes one canonical-slot
/// vector whose plaintexts are proven to be either zero or `-card[i]`.
fn rebuild_deck_from_reconstruct_deck(table: &mut TexasPokerTable) -> PokerL1Result<()> {
    let new_cts = table
        .deck_state
        .reconstruct_accumulated
        .clone()
        .ok_or_else(|| {
            PokerL1Error::Serialization(
                "rebuild_deck V3 requires at least one verified contribution".into(),
            )
        })?;
    if new_cts.len() != 52 {
        return Err(PokerL1Error::Serialization(format!(
            "rebuild_deck V3 accumulator has {} cards, expected 52",
            new_cts.len()
        )));
    }

    table.deck_state.encrypted = CipherDeck::try_from(new_cts)?;
    // reconstruct 重建的是一副全新牌组，与旧 deck 的 index 空间无关。
    // 新 deck 必须从 index=0 开始顺序发牌（见 restart_reveal_after_reconstruct
    // 的注释），因此重置 cards_dealt=0。
    //
    // 已发出的旧牌不依赖新 deck 的 index：
    // - 已解出的公共牌明文存于 community_cards（不依赖 index）
    // - 固定 `(seat, hole_slot)` 账本中已部分解密的手牌记录
    //   自包含 partial c2，showdown 解密时不访问 deck_state.encrypted（见
    //   apply_submit_player_reveal_tokens 的 showdown 分支）
    // 因此保留 owner_readable_hole_cards（不清空），仅重置 cards_dealt。
    table.deck_state.cards_dealt = 0;
    Ok(())
}

// ========== 庄家位与盲注 ==========

/// 移动庄家位：dead button 规则（Robert's Rules of Poker §4.2b）下按钮
/// 每手严格前进一个座位——即使落点是空座位（该手即为"死按钮"，不承担
/// button 职责），**不**跳过空座位。跳过空座位会把过渡手的盲注轨道整体
/// 前移，偏离标准 dead button 语义。
fn move_button(table: &mut TexasPokerTable) {
    table.button = (table.button + 1) % table.max_players;
}

/// 投盲注，返回 (sb_seat, bb_seat, first_to_act)。
///
/// **完整实现 dead button 规则**（Robert's Rules of Poker §4.2b；TDA 锦标赛
/// 规则同）：盲注按"轮转归属"而非纯按钮相对位置定位——
/// - **大盲**：上一手大盲（`last_bb_seat`）之后顺时针第一个参与本局的座位。
///   轮转永不跳人、永不重复（无人连续两手交大盲）。
/// - **小盲（非单挑）**：上一手大盲座位本身——该座位已空/离场/等待时，
///   本手**无小盲**（dead small blind），不向其后顺延。
/// - **单挑（2 名参与者）**：大盲按轮转归属，小盲 = 大盲之外另一参与者
///   （承担 button 职责：翻牌前先行动、翻牌后后行动）。
/// - **首手**（`last_bb_seat == NO_SEAT`，无盲注历史）：退回位置式定位，
///   SB = button 后第一个参与座位，BB = SB 之后下一个。
///
/// 返回值的 `sb_seat` 在 dead small blind 时为 [`NO_SEAT`]（该手不收小盲）。
fn post_blinds(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<(u8, u8, u8)> {
    let n = table.max_players;
    let active = count_active_occupied(&table.seats);
    let rotation_base = if table.last_bb_seat != NO_SEAT {
        debug_assert!(usize::from(table.last_bb_seat) < usize::from(n));
        table.last_bb_seat
    } else {
        table.button
    };
    let (sb_seat, bb_seat) = if active == 2 {
        // heads-up：BB 按轮转归属，SB = BB 之外另一参与者（死按钮时该
        // 座位可能与 button 座位不同）。
        let bb =
            find_next_participating_seat(&table.seats, rotation_base, n).unwrap_or(rotation_base);
        let sb = find_next_participating_seat(&table.seats, bb, n).unwrap_or(bb);
        (sb, bb)
    } else {
        // 非 heads-up：BB = 上一手 BB 之后第一个参与座位；SB = 上一手 BB
        // 座位本身（仍参与时），否则 dead small blind。
        let bb =
            find_next_participating_seat(&table.seats, rotation_base, n).unwrap_or(rotation_base);
        let base = &table.seats[usize::from(rotation_base)];
        let sb = if rotation_base != bb && base.is_occupied() && !base.is_waiting() {
            rotation_base
        } else {
            NO_SEAT
        };
        (sb, bb)
    };
    // 大盲轮转轨道落点记录：下一手的大盲/小盲据此定位（跨手持久）。
    table.last_bb_seat = bb_seat;
    // first_to_act 仅作事件参考，实际由 start_betting_round 基于 BB 精确定位。
    let first_to_act = bb_seat;

    let bb_amt = table.big_blind.min(table.seats[bb_seat as usize].stack());

    let sb_seat_idx = usize::from(sb_seat);
    let bb_seat_idx = bb_seat as usize;
    let sb_amt = if sb_seat == NO_SEAT {
        0
    } else {
        table.small_blind.min(table.seats[sb_seat_idx].stack())
    };
    if sb_seat != NO_SEAT {
        let seat = table.seats[sb_seat_idx].playing_mut()?;
        seat.occupied.stack = seat.occupied.stack.checked_sub(sb_amt).ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: sb stack -= sb_amt underflow".into())
        })?;
        seat.bet = sb_amt;
        seat.total_bet = seat.total_bet.checked_add(sb_amt).ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: sb total_bet += sb_amt overflow".into())
        })?;
        if table.seats[sb_seat_idx].stack() == 0 {
            table.seats[sb_seat_idx].set_status(SeatStatus::AllIn);
        }
    }

    {
        let seat = table.seats[bb_seat_idx].playing_mut()?;
        seat.occupied.stack = seat.occupied.stack.checked_sub(bb_amt).ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: bb stack -= bb_amt underflow".into())
        })?;
        seat.bet = bb_amt;
        seat.total_bet = seat.total_bet.checked_add(bb_amt).ok_or_else(|| {
            PokerL1Error::Serialization("post_blinds: bb total_bet += bb_amt overflow".into())
        })?;
    }
    if table.seats[bb_seat_idx].stack() == 0 {
        table.seats[bb_seat_idx].set_status(SeatStatus::AllIn);
    }

    events::emit_event(
        events,
        TexasPokerEvent::BlindsPosted {
            table_id: table.id,
            sb_seat,
            bb_seat,
            sb_amount: sb_amt,
            bb_amount: bb_amt,
            first_to_act: first_to_act,
        },
    );
    Ok((sb_seat, bb_seat, first_to_act))
}

/// 启动下注轮。
///
/// 镜像 `table.move::start_betting_round`（line 2715-2762），并修正 first-to-act 定位（P0-2/P0-3）。
///
/// # 参数
/// - `is_preflop`: 是否 preflop（决定 current_bet 初始化与 first-to-act 规则）。
/// - `bb_seat`: preflop 时传入大盲位座位（用于定位 UTG = BB 之后第一个可行动玩家）；
///   postflop 传 `None`。
///
/// # first-to-act 规则（P0-2/P0-3 修复）
/// - **preflop 非 heads-up**：UTG = BB 之后第一个可行动座位
///   （`find_next_active_seat(seats, bb_seat, n)`），跳过空/folded/all_in 座位。
///   原实现硬编码 `button+3`，不跳过空座位。
/// - **preflop heads-up**：SB(button) 先行动。
/// - **postflop 非 heads-up**：button 之后第一个可行动座位。
/// - **postflop heads-up**：SB(button) 先行动（heads-up postflop 由 button 先行动）。
///   原实现未区分 heads-up，导致 heads-up postflop 行动权反转。
fn start_betting_round(
    table: &mut TexasPokerTable,
    is_preflop: bool,
    bb_seat: Option<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let bb = table.big_blind;
    let round = if is_preflop {
        // Ante goes directly to the pot and does not buy down the amount to call. Only blinds
        // and voluntary wagers participate in the current betting-round price.
        let max_bet = table
            .seats
            .iter()
            .map(Seat::bet)
            .max()
            .unwrap_or(bb)
            .max(bb);
        let mut r = BettingRound::new(bb, bb);
        r.current_bet = max_bet;
        r
    } else {
        // postflop 清零 seat.bet()
        for s in &mut table.seats {
            if let Ok(playing) = s.playing_mut() {
                playing.bet = 0;
            }
        }
        BettingRound::new(bb, 0)
    };
    let street = table.round_state();
    table.enter_betting(street, round, NO_SEAT, 0)?;

    // 关键修复：每个新下注轮开始时重置所有座位的 acted_this_round 标记。
    // 否则上一轮的 acted 标记会泄漏到下一轮，导致 is_betting_complete 误判
    // （例如 preflop raise 后 Alice.acted=true，flop 开始时未重置，
    //  Bob check 后 is_betting_complete 检测到 Alice 已 acted 且 bet 匹配，
    //  错误地认为本轮下注完成并提前 advance_round）。
    // 盲注 all-in 座位（#22② 封顶盲注）补 acted 位：all-in 玩家本轮无
    // 行动权，canonical 镜像不变量要求 Folded/AllIn 座位带 acted 标记。
    // 本轮无行动权的座位（folded/all-in）补 acted 位——canonical 镜像
    // 不变量 "Folded/AllIn seat must be acted"。
    table.acted_mask = 0;
    for (index, seat) in table.seats.iter().enumerate() {
        if seat.is_all_in() || seat.is_folded() {
            table.acted_mask |= 1u16 << index;
        }
    }

    let is_heads_up = count_active_occupied(&table.seats) == 2;
    let n = table.max_players;
    // 选第一个可行动玩家作为 current_turn。
    let start_seat = if is_preflop {
        // UTG = BB 之后第一个可行动座位（BB 本身已投盲不行动）。单挑时该
        // 座位即 SB——dead button 规则下 SB = BB 之外另一参与者，可能与
        // button 座位不同；SB 已因盲注 all-in 时顺延回 BB。
        bb_seat.and_then(|bb| find_next_active_seat(&table.seats, bb, n))
    } else if is_heads_up {
        // 单挑翻牌后 BB 先行动（button 职责=SB，最后行动）。dead button
        // 下 BB 座位可能与 button 座位不同，显式从 BB（轮转基准）开始：
        // BB 本身可行动则先行动，否则顺延到 BB 之后第一个可行动座位。
        let base = if table.last_bb_seat != NO_SEAT {
            table.last_bb_seat
        } else {
            table.button
        };
        let base_seat = &table.seats[usize::from(base)];
        let base_actionable = base_seat.is_occupied()
            && !base_seat.is_folded()
            && !base_seat.is_all_in()
            && !base_seat.is_waiting();
        if base_actionable {
            Some(base)
        } else {
            find_next_active_seat(&table.seats, base, n)
        }
    } else {
        // postflop 非 heads-up: button 之后第一个可行动座位（button 最后行动）。
        find_next_active_seat(&table.seats, table.button, n)
    };

    set_current_turn(table, start_seat, events)?;

    // All-in runout: with at most one stack still able to wager, no matched action remains.
    // canonical AdvanceRound 行不变量同 advance_turn：pre.turn 必须 NO_SEAT
    //（全员 all-in 的 C5 路径已为 None；唯一可行动者的路径在此清掉），
    // 收注 + 推街拆为独立 AdvanceBettingRound step（Reveal completion 行
    // 的 post 停在 Betting 状态，行链随后续 AdvanceRound 行咬合）。
    if no_further_betting_possible(table) {
        set_current_turn(table, None, events)?;
        if normalization_trace_armed() {
            let before = table.clone();
            // 边界锚：CompleteReveal 行的 post（新开下注轮，armed 语义由
            // 生产者修正），runout 以独立 AdvanceRound 行呈现。
            set_completion_boundary(&before);
            collect_bets_to_pot(table, events)?;
            advance_round(table, events)?;
            record_step_trace(NormalizationStep::AdvanceBettingRound, &before, table);
        } else {
            collect_bets_to_pot(table, events)?;
            advance_round(table, events)?;
        }
        return Ok(());
    }

    events::emit_event(
        events,
        TexasPokerEvent::BettingRoundStarted {
            table_id: table.id,
            round_state: table.round_state(),
            current_bet: table.betting_round().map_or(0, |b| b.current_bet),
            min_raise: bb,
            first_to_act: start_seat.unwrap_or(0),
            pot_before: table.pot,
        },
    );
    Ok(())
}

// ========== 行动轮换 ==========

/// 设置当前行动玩家。
fn set_current_turn(
    table: &mut TexasPokerTable,
    turn: Option<u8>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let old = table.current_turn_option();
    table.set_betting_turn(turn.unwrap_or(NO_SEAT))?;
    // 幂等：turn 未变时不发事件（normalize 拆步引入的重复清 turn 会产生
    // old == new == None 的噪音事件）。
    if old == turn {
        return Ok(());
    }
    events::emit_event(
        events,
        TexasPokerEvent::CurrentTurnChanged {
            table_id: table.id,
            old_turn: old,
            new_turn: turn,
            round_state: table.round_state(),
        },
    );
    Ok(())
}

/// 检查下注轮是否完成。
///
/// 所有可行动玩家（occupied && !folded && !all_in && !waiting）都已 acted 且 bet == current_bet。
fn is_betting_complete(table: &TexasPokerTable) -> bool {
    let cb = match table.betting_round() {
        Some(b) => b.current_bet,
        None => return true,
    };
    for (seat_index, s) in table.seats.iter().enumerate() {
        if s.is_occupied() && !s.is_folded() && !s.is_all_in() && !s.is_waiting() {
            if !table.seat_acted_this_round(seat_index as u8) || s.bet() != cb {
                return false;
            }
        }
    }
    true
}

/// 推进到下一行动玩家，若下注完成则 collect + advance_round。
fn advance_turn(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if is_betting_complete(table) {
        // canonical AdvanceRound 行不变量（控制逻辑入 AIR，Stage 2）：本
        // micro-step 的 pre 必须是"final actor 已离场"——turn 清到 NO_SEAT
        // （把 turn 留在最后行动者身上正是游戏层一直在 fight 的陈旧指针，
        // canonical AIR 据此证明"仅收注"关系）。收注 + 推街作为独立
        // AdvanceBettingRound step 进轨迹（armed 时），witness 生产者据此
        // 产出单街收注行。
        set_current_turn(table, None, events)?;
        if normalization_trace_armed() {
            let before = table.clone();
            collect_bets_to_pot(table, events)?;
            advance_round(table, events)?;
            record_step_trace(NormalizationStep::AdvanceBettingRound, &before, table);
        } else {
            collect_bets_to_pot(table, events)?;
            advance_round(table, events)?;
        }
        return Ok(());
    }
    let cur = table.current_turn_option().unwrap_or(0);
    let next = find_next_active_seat(&table.seats, cur, table.max_players);
    set_current_turn(table, next, events)?;
    Ok(())
}

/// 收集本轮 bet 到 pot。
fn collect_bets_to_pot(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // Preflight the complete collection so an overflow cannot leave an earlier
    // seat collected while a later seat still carries its bet.
    let total_to_collect = table.seats.iter().try_fold(0u64, |total, seat| {
        total.checked_add(seat.bet()).ok_or_else(|| {
            PokerL1Error::Serialization("collect_bets_to_pot: bet sum overflow".into())
        })
    })?;
    let post_pot = table.pot.checked_add(total_to_collect).ok_or_else(|| {
        PokerL1Error::Serialization("collect_bets_to_pot: pot += bets overflow".into())
    })?;

    let mut collected_mask: SeatMask = 0;
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.bet() > 0 {
            s.set_bet(0)?;
            seat_mask_insert(&mut collected_mask, i as u8)?;
        }
    }
    table.pot = post_pot;
    if collected_mask != 0 {
        events::emit_event(
            events,
            TexasPokerEvent::PotCollected {
                table_id: table.id,
                round_state: table.round_state(),
                pot_after: table.pot,
                collected_from_seats: collected_mask,
            },
        );
    }
    Ok(())
}

/// 推进到下一轮（preflop→flop→turn→river→showdown）。
///
/// 镜像 `table.move::advance_round`（line 2855-2886）。
fn advance_round(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // P1-8 修复：若只剩一名未 fold 玩家（其他人全 fold），无需继续发牌到 showdown，
    // 直接 end_without_showdown 结算。覆盖 advance_round 路径上的"剩一人"场景
    // （fold 路径已在 apply_fold_internal 处理，此处兜底 all-in/advance 后的情形）。
    if count_active_players(&table.seats) <= 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    maybe_trigger_run_it_twice(table, events)?;
    let from = table.round_state();
    let old_turn = table.current_turn_option();
    let to = match from {
        ROUND_PREFLOP => {
            start_community_reveal_phase(table, 3, ROUND_FLOP, events)?;
            ROUND_FLOP
        }
        ROUND_FLOP => {
            start_community_reveal_phase(table, 1, ROUND_TURN, events)?;
            ROUND_TURN
        }
        ROUND_TURN => {
            start_community_reveal_phase(table, 1, ROUND_RIVER, events)?;
            ROUND_RIVER
        }
        ROUND_RIVER => {
            start_showdown_reveal_phase(table, events)?;
            ROUND_SHOWDOWN
        }
        _ => return Ok(()), // 不该到达
    };

    events::emit_event(
        events,
        TexasPokerEvent::CurrentTurnChanged {
            table_id: table.id,
            old_turn,
            new_turn: None,
            round_state: to,
        },
    );

    events::emit_event(
        events,
        TexasPokerEvent::RoundAdvanced {
            table_id: table.id,
            from_round: from,
            to_round: to,
            pot: table.pot,
            community_cards_count: table.community_cards.len() as u64,
        },
    );
    Ok(())
}

// ========== 洗牌协议 ==========

/// 推进洗牌流程：选下一洗牌者，或完成洗牌进入下一阶段。
///
/// 镜像 `table.move::advance_shuffle`（line 2920-2970）。
fn advance_shuffle(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let phase = table.shuffle_phase();
    if phase != SHUFFLE_PHASE_RECONSTRUCT && phase != SHUFFLE_PHASE_BEFORE_PREFLOP {
        return Ok(());
    }

    if table.shuffle_state().pending_mask == 0 {
        // 洗牌完成
        let completed_count = u64::from(seat_mask_count(table.shuffle_state().completed_mask));
        let deck_size = table.deck_state.encrypted.len() as u64;
        events::emit_event(
            events,
            TexasPokerEvent::ShuffleComplete {
                table_id: table.id,
                phase,
                participant_count: completed_count,
                deck_size,
            },
        );
        match phase {
            SHUFFLE_PHASE_BEFORE_PREFLOP => {
                start_preflop_reveal_phase(table, events)?;
            }
            SHUFFLE_PHASE_RECONSTRUCT => {
                // reconstruct 后按当前 round_state 重启对应 reveal phase
                restart_reveal_after_reconstruct(table, events)?;
            }
            _ => {}
        }
        return Ok(());
    }

    // 选下一洗牌者
    let next = seat_mask_first(table.shuffle_state().pending_mask).ok_or_else(|| {
        PokerL1Error::Serialization("shuffle pending mask unexpectedly empty".into())
    })?;
    table.disarm_shuffle_deadline()?;
    events::emit_event(
        events,
        TexasPokerEvent::ShuffleTurn {
            table_id: table.id,
            seat_index: next,
            pending_count: u64::from(seat_mask_count(table.shuffle_state().pending_mask)),
            completed_count: u64::from(seat_mask_count(table.shuffle_state().completed_mask)),
        },
    );
    Ok(())
}

/// reconstruct 后根据当前 round_state 重启对应 reveal phase。
///
/// # 设计要点
///
/// reconstruct 在某轮 reveal 超时（玩家未提交 reveal token）后触发，由剩余玩家
/// 重新构建牌组（`rebuild_deck_from_reconstruct_deck` 生成全新加密 deck，`cards_dealt`
/// 重置为 0）让牌局继续。重启 reveal phase 的原则：
///
/// 1. **已解出的牌不动**：已写入 `community_cards` 的公共牌、已部分解密存于
///    固定 owner-readable ledger 的手牌，都不依赖新 deck 的 index，
///    原样保留。手牌的 partial 记录自包含 c2，showdown 时牌主公开 token 即可解开。
/// 2. **补发缺失的牌**：以 `community_cards.len()` 为基准补齐到当前轮次所需张数，
///    新发的牌从新 deck 的 index=0 开始顺序发出（`cards_dealt` 已被 rebuild 重置）。
///
/// # 各轮次处理
///
/// - PREFLOP：正常流程下 preflop 超时走 refund+reset（见 `on_reveal_timeout`），
///   不会进 reconstruct；此分支为防御性兜底。若走到这里，说明手牌从未成功发出，
///   需清空残留的旧 partial 手牌记录后从新 deck 重发。
/// - FLOP/TURN/RIVER：按 `community_cards.len()` 补发缺失的公共牌。
/// - SHOWDOWN：不补发新牌，直接让各牌主从固定 partial ledger 解手牌。
fn restart_reveal_after_reconstruct(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    validate_run_it_twice_progress(table)?;
    match table.round_state() {
        ROUND_PREFLOP => {
            // 防御性：清空残留的旧 partial 手牌记录，避免 showdown 时新旧记录并存。
            table.deck_state.owner_readable_hole_cards.clear();
            start_preflop_reveal_phase(table, events)?;
        }
        ROUND_FLOP => {
            let have = table.community_cards.len() as u8;
            if have < 3 {
                start_community_reveal_phase(table, 3 - have, ROUND_FLOP, events)?;
            }
        }
        ROUND_TURN => {
            let have = table.community_cards.len() as u8;
            if have < 4 {
                start_community_reveal_phase(table, 4 - have, ROUND_TURN, events)?;
            }
        }
        ROUND_RIVER => {
            let have = table.community_cards.len() as u8;
            if have < 5 {
                start_community_reveal_phase(table, 5 - have, ROUND_RIVER, events)?;
            }
        }
        ROUND_SHOWDOWN => start_showdown_reveal_phase(table, events)?,
        _ => {}
    }
    Ok(())
}

/// 超时后重建牌组并重启洗牌。
fn rebuild_deck_and_shuffle_on_timeout(
    table: &mut TexasPokerTable,
    phase: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    set_initial_encrypted_deck(table)?;
    let active = get_active_seat_mask(&table.seats);
    let state = super::types::ShuffleState {
        pending_mask: active,
        completed_mask: 0,
    };
    if phase == SHUFFLE_PHASE_RECONSTRUCT {
        let street = table.round_state();
        let suspended_reveal = table.take_reveal_payload()?;
        table.enter_reconstruct_shuffling(street, state, suspended_reveal, 0)?;
    } else {
        table.enter_initial_shuffling(state, 0)?;
    }
    events::emit_event(
        events,
        TexasPokerEvent::DeckRebuilt {
            table_id: table.id,
            reason: DECK_REBUILT_REASON_SHUFFLE_TIMEOUT,
            deck_size: table.deck_state.encrypted.len() as u64,
        },
    );
    Ok(())
}

// ========== Reveal 协议 ==========

/// 启动 preflop reveal phase：给每个活跃玩家发 2 张手牌。
///
/// 镜像 `table.move::start_preflop_reveal_phase`（line 2974-3017）。
fn start_preflop_reveal_phase(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let active_seats = get_active_seat_indices(&table.seats);
    let active_mask = get_active_seat_mask(&table.seats);
    let mut assignments = Vec::new();
    let mut card_idx = table.deck_state.cards_dealt;

    for &seat in &active_seats {
        for _slot in 0..CARDS_PER_PLAYER {
            // pending_players = 除牌主外的所有活跃玩家（牌主不为自己提交 reveal token）
            let pending_mask = active_mask & !(1u16 << seat);
            assignments.push(RevealAssignment {
                encrypted_card_index: card_idx,
                target: RevealTarget::Hole {
                    seat_index: seat,
                    card_slot: card_idx % CARDS_PER_PLAYER,
                },
                pending_mask,
                submitted_mask: 0,
                reveal_tokens: vec![],
            });
            card_idx += 1;
        }
    }

    table.deck_state.cards_dealt = card_idx;
    table.enter_revealing(
        ROUND_PREFLOP,
        super::types::RevealTokenState {
            purpose: RevealPurpose::DealHole,
            assignments,
        },
        0,
    )?;
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase: REVEAL_PHASE_PREFLOP,
        },
    );
    Ok(())
}

/// 启动公共牌 reveal phase（flop=3, turn=1, river=1）。
///
/// 镜像 `table.move::start_community_reveal_phase`（line 3019-3044）。
fn start_community_reveal_phase(
    table: &mut TexasPokerTable,
    count: u8,
    street: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !matches!(street, ROUND_FLOP | ROUND_TURN | ROUND_RIVER) {
        return Err(PokerL1Error::Serialization(format!(
            "community reveal cannot start on street {street}"
        )));
    }
    validate_run_it_twice_progress(table)?;
    let active_mask = get_active_seat_mask(&table.seats);
    let runout_count = if table.run_it_twice_state.is_active() {
        2
    } else {
        1
    };
    let mut assignments = Vec::new();
    let mut card_idx = table.deck_state.cards_dealt;

    for runout_index in 0..runout_count {
        let board_len = if runout_index == 0 {
            table.community_cards.len()
        } else {
            table.run_it_twice_state.second_board_len()
        };
        for offset in 0..count {
            // 所有活跃玩家都要为公共牌提交 token.
            let board_position = board_len
                .checked_add(usize::from(offset))
                .and_then(|position| u8::try_from(position).ok())
                .ok_or_else(|| {
                    PokerL1Error::Serialization("community reveal board position exceeds u8".into())
                })?;
            assignments.push(RevealAssignment {
                encrypted_card_index: card_idx,
                target: RevealTarget::Board {
                    runout_index,
                    board_position,
                },
                pending_mask: active_mask,
                submitted_mask: 0,
                reveal_tokens: vec![],
            });
            card_idx = card_idx.checked_add(1).ok_or_else(|| {
                PokerL1Error::Serialization("community reveal card index overflow".into())
            })?;
        }
    }

    table.deck_state.cards_dealt = card_idx;
    let phase = RevealPurpose::Board.legacy_phase(street);
    table.enter_revealing(
        street,
        super::types::RevealTokenState {
            purpose: RevealPurpose::Board,
            assignments,
        },
        0,
    )?;
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase,
        },
    );
    Ok(())
}

/// 启动 showdown reveal phase：每个未 fold 玩家提交自己手牌的 reveal token。
///
/// 镜像 `table.move::start_showdown_reveal_phase`（line 3046-3080）。
fn start_showdown_reveal_phase(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let mut assignments = Vec::new();
    let active_seats = get_active_seat_indices(&table.seats);

    for &seat in &active_seats {
        // Ledger position already defines canonical owner and dealing slot.
        let partial_cards = table
            .deck_state
            .owner_readable_hole_cards
            .iter_for_seat(seat)
            .collect::<Vec<_>>();
        let first_slot = table.seats[usize::from(seat)]
            .hand()
            .map_or(0, HoleCards::len);
        for (card_slot, card) in partial_cards {
            if usize::from(card_slot) < first_slot {
                return Err(PokerL1Error::Serialization(format!(
                    "showdown partial ledger overlaps materialized hand: seat={seat}, slot={card_slot}"
                )));
            }
            // pending = [seat]（只牌主自己提交）
            assignments.push(RevealAssignment {
                encrypted_card_index: card.encrypted_card_index,
                target: RevealTarget::Hole {
                    seat_index: seat,
                    card_slot,
                },
                pending_mask: 1u16 << seat,
                submitted_mask: 0,
                reveal_tokens: vec![],
            });
        }
    }

    table.enter_revealing(
        ROUND_SHOWDOWN,
        super::types::RevealTokenState {
            purpose: RevealPurpose::ShowdownOwner,
            assignments,
        },
        0,
    )?;
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhase {
            table_id: table.id,
            phase: REVEAL_PHASE_SHOWDOWN,
        },
    );
    Ok(())
}

/// 检查 reveal phase 是否完成，并推进状态。
///
/// 镜像 `table.move::check_reveal_phase_complete`（line 3106-3156）。
fn check_reveal_phase_complete(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // Every completed assignment is materialized and drained in the same dispatch. An empty
    // assignment list is therefore the only persisted phase-complete representation.
    let reveal = table.reveal_token_state().ok_or_else(|| {
        PokerL1Error::Serialization("reveal completion checked outside reveal state".into())
    })?;
    if !reveal.assignments.is_empty() {
        return Ok(());
    }

    let purpose = reveal.purpose;
    let phase = table.reveal_phase();
    events::emit_event(
        events,
        TexasPokerEvent::RevealPhaseComplete {
            table_id: table.id,
            phase,
        },
    );

    match purpose {
        RevealPurpose::DealHole => {
            // 投盲注并启动 preflop 下注轮
            let (_, bb_seat, _) = post_blinds(table, events)?;
            // 投 ante（若配置）— 在盲注之后、下注轮启动之前
            collect_ante(table, bb_seat, events)?;
            start_betting_round(table, true, Some(bb_seat), events)?;
        }
        RevealPurpose::RedealHole => {
            // 换牌窗口消化：原样恢复被挂起的下注轮（round/turn 逐位还原），
            // 行动截止期从当前时刻重新武装——换牌窗口消耗的时间不折损行动者。
            let HandPhase::Redealing {
                street,
                round,
                current_turn,
                ..
            } = table.hand_phase.clone()
            else {
                return Err(PokerL1Error::Serialization(
                    "redeal completion checked outside redeal phase".into(),
                ));
            };
            table.enter_betting(street, round, current_turn, now_ms)?;
        }
        RevealPurpose::Board => {
            start_betting_round(table, false, None, events)?;
        }
        RevealPurpose::ShowdownOwner => {
            table.enter_showdown_display(0);
        }
    }
    Ok(())
}

/// Match a decrypted plaintext point against the protocol's canonical 52-card domain.
fn card_from_plaintext(
    plaintext: &G1Projective,
    canonical_cards: &[G1Projective],
) -> PokerL1Result<(u8, Card)> {
    let card_id = canonical_cards
        .iter()
        .position(|candidate| g1_equal(candidate, plaintext))
        .ok_or_else(|| {
            PokerL1Error::Serialization(
                "decrypted plaintext is not a canonical Texas Poker card".into(),
            )
        })?;
    let card_id = u8::try_from(card_id)
        .map_err(|_| PokerL1Error::Serialization("canonical card id exceeds u8".into()))?;
    Ok((card_id, Card::from_index(card_id)))
}

/// Collect all already exposed card identities and reject corrupt duplicate state.
fn exposed_card_ids(table: &TexasPokerTable) -> PokerL1Result<std::collections::HashSet<u8>> {
    let mut seen = std::collections::HashSet::new();
    for card in table
        .community_cards
        .iter()
        .chain(table.run_it_twice_state.second_board_suffix().iter())
        .chain(
            table
                .seats
                .iter()
                .flat_map(|seat| seat.hand().into_iter().flat_map(|hand| hand.iter())),
        )
    {
        if !card.is_valid() {
            return Err(PokerL1Error::Serialization(format!(
                "table contains invalid exposed card suit={} rank={}",
                card.suit(),
                card.rank()
            )));
        }
        let card_id = card.to_index();
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "table contains duplicate exposed card id {card_id}"
            )));
        }
    }
    Ok(seen)
}

/// Validate the canonical in-progress shape of a two-runout board.
fn validate_run_it_twice_progress(table: &TexasPokerTable) -> PokerL1Result<()> {
    let state = &table.run_it_twice_state;
    state.validate_canonical(&table.community_cards)?;
    if !state.is_active() {
        return Ok(());
    }
    let shared = usize::from(state.shared_board_len());
    if shared > 4
        || table.community_cards.len() > 5
        || table.community_cards.len() < shared
        || state.second_board_len() > 5
    {
        return Err(PokerL1Error::Serialization(
            "run it twice board lengths are outside canonical bounds".into(),
        ));
    }
    if state.second_board_len() != table.community_cards.len() {
        return Err(PokerL1Error::Serialization(
            "run it twice boards have diverging lengths before reveal".into(),
        ));
    }
    exposed_card_ids(table)?;
    Ok(())
}

// ========== 部分解密 ==========

/// 部分解密 c2：`result = c2 - Σ token_point`。
///
/// typed 化后直接接收/返回 G1Projective，无需 bytes 转换。
fn partial_decrypt_c2(c2: &G1Projective, tokens: &[G1Projective]) -> G1Projective {
    let mut result = *c2;
    for t in tokens {
        result = g1_sub(&result, t);
    }
    result
}

// ========== Redeal 协议 ==========

/// 玩家换牌（redeal）：持有者报告自己的某张底牌解出非规范明文（死槽——例如
/// identity 点），用 deck 游标位（`cards_dealt`）的新牌替换，并开启
/// `RevealPurpose::RedealHole` 令牌窗口重新收集他人份额；下注轮被挂起
/// （`HandPhase::Redealing`），窗口消化后原样恢复 round/turn。
///
/// 信任模型：只有持有者本人能触发（caller == seat.player），且只有持有者的
/// 牌面受损——换掉一张好牌只伤害持有者自己，无需链上验证"牌确实坏了"
/// （链上不可解密，也无法验证）。deck 卡数天然约束换牌次数上限。
pub fn apply_redeal_hole_card(
    table: &mut TexasPokerTable,
    seat_index: u8,
    card_slot: u8,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let HandPhase::Betting {
        street,
        round,
        current_turn,
        ..
    } = table.hand_phase.clone()
    else {
        return Err(PokerL1Error::Serialization(
            "redeal is only allowed during an active betting round".into(),
        ));
    };
    if usize::from(card_slot) >= usize::from(CARDS_PER_PLAYER) {
        return Err(PokerL1Error::Serialization(format!(
            "redeal card slot {card_slot} is outside the hole-card width"
        )));
    }
    let seat = table
        .seats
        .get(usize::from(seat_index))
        .ok_or_else(|| PokerL1Error::Serialization("seat index out of range".into()))?;
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(
            "redeal seat is not occupied".into(),
        ));
    }
    // 旧账本条目必须存在：换的是本手已发且他人份额已收齐（DealHole 物化过）的牌。
    // 摊牌窗口/未发牌位无账本条目，直接拒绝。
    if table
        .deck_state
        .owner_readable_hole_cards
        .get(seat_index, card_slot)
        .is_none()
    {
        return Err(PokerL1Error::Serialization(format!(
            "redeal has no dealt partial to replace: seat={seat_index}, slot={card_slot}"
        )));
    }
    let new_card_index = table.deck_state.cards_dealt;
    if usize::from(new_card_index) >= table.deck_state.encrypted.len() {
        return Err(PokerL1Error::Serialization(
            "redeal exhausted the encrypted deck".into(),
        ));
    }
    let new_ct = table.deck_state.encrypted[usize::from(new_card_index)];

    // 账本换绑：移除旧 (seat, slot) partial（其 deck 索引随旧牌废弃），写入新牌的
    // 占位 partial（ciphertext 先等于完整密文，窗口物化时被真实部分解密覆盖）。
    table
        .deck_state
        .owner_readable_hole_cards
        .remove(seat_index, card_slot)?;
    table.deck_state.owner_readable_hole_cards.insert(
        seat_index,
        card_slot,
        PartialHoleCard::new(new_card_index, new_ct, new_ct),
    )?;
    table.deck_state.cards_dealt = new_card_index
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Serialization("cards_dealt overflow".into()))?;

    // 挂起下注轮 + 打开换牌令牌窗口：pending = 除持有者外的全部活跃座位
    //（对齐 DealHole 语义——他人剥层，持有者本地解密）。
    let active_mask = get_active_seat_mask(&table.seats);
    let pending_mask = active_mask & !(1u16 << seat_index);
    table.enter_redealing(
        street,
        round,
        current_turn,
        super::types::RevealTokenState {
            purpose: RevealPurpose::RedealHole,
            assignments: vec![RevealAssignment {
                encrypted_card_index: new_card_index,
                target: RevealTarget::Hole {
                    seat_index,
                    card_slot,
                },
                pending_mask,
                submitted_mask: 0,
                reveal_tokens: vec![],
            }],
        },
        now_ms,
    )?;

    events::emit_event(
        events,
        TexasPokerEvent::HoleCardRedealt {
            table_id: table.id,
            seat_index,
            card_slot,
            new_card_index,
            round_state: street,
        },
    );
    Ok(())
}

// ========== Reconstruct 协议 ==========

/// 启动 reconstruct 流程（玩家超时未提交 reveal token 时触发）。
///
/// 镜像 `table.move::start_reconstruct`（line 1357-1390）。
fn start_reconstruct(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    now_ms
        .checked_add(u64::from(table.timeout_config.reconstruct_timeout_ms))
        .ok_or_else(|| PokerL1Error::Serialization("reconstruct deadline overflows u64".into()))?;
    let active_mask = get_active_seat_mask(&table.seats);
    // Capture the outer street before `take_reveal_payload` temporarily puts
    // the hand phase into `Waiting`. Reading `table.round_state()` after the
    // take would pass `ROUND_WAITING` (0) to `enter_reconstructing`.
    let street = table.round_state();
    // 历史留档：reconstruct v1 曾在此派生 coefficient =
    // hash_to_scalar("reconstruct_coefficient/" || table_id_bytes || timestamp_ascii)。
    // reconstruction V3 不再持久化该系数，死计算已删除（其值从未被读取）。
    let suspended_reveal = table.take_reveal_payload()?;
    // 新一轮重构从 canonical base deck 开始：清空上一轮残留累加器
    // （累加器已迁 DeckState）。
    table.deck_state.reconstruct_accumulated = None;
    table.enter_reconstructing(
        street,
        super::types::ReconstructState {
            pending_mask: active_mask,
        },
        suspended_reveal,
        now_ms,
    )?;

    events::emit_event(
        events,
        TexasPokerEvent::ReconstructInitiated {
            table_id: table.id,
            expected_players: active_mask,
            round_state: table.round_state(),
        },
    );
    Ok(())
}

/// 所有玩家提交 reconstruct deck 完成后的处理。
///
/// 镜像 `table.move::on_complete_reconstruct`（line 1199-1211）。
fn on_complete_reconstruct(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    rebuild_deck_from_reconstruct_deck(table)?;
    events::emit_event(
        events,
        TexasPokerEvent::ReconstructComplete { table_id: table.id },
    );
    events::emit_event(
        events,
        TexasPokerEvent::DeckRebuilt {
            table_id: table.id,
            reason: DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE,
            deck_size: table.deck_state.encrypted.len() as u64,
        },
    );

    // 重新洗牌（RECONSTRUCT phase）
    let active = get_active_seat_mask(&table.seats);
    let street = table.round_state();
    let suspended_reveal = table.take_reveal_payload()?;
    table.enter_reconstruct_shuffling(
        street,
        super::types::ShuffleState {
            pending_mask: active,
            completed_mask: 0,
        },
        suspended_reveal,
        0,
    )?;
    advance_shuffle(table, events)?;
    Ok(())
}

/// reconstruct 超时处理：踢未提交者，按情况推进。
fn on_reconstruct_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let pending_mask = table.reconstruct_state().pending_mask;
    let pending = seat_mask_to_indices(pending_mask, table.max_players);
    events::emit_event(
        events,
        TexasPokerEvent::ReconstructTimeout {
            table_id: table.id,
            pending_players: pending_mask,
        },
    );

    for &seat in &pending {
        kick_player_internal(table, seat, KICK_REASON_RECONSTRUCT_TIMEOUT, events)?;
    }

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    if table.deck_state.reconstruct_accumulated.is_some() {
        on_complete_reconstruct(table, events)?;
    } else {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_RECONSTRUCT_FAIL,
                round_state: table.round_state(),
            },
        );
    }
    let _ = now_ms;
    Ok(())
}

// ========== 玩家入口动作 ==========

/// 后续玩家提交 shuffle（V2：链上注入 c2 += player_pk）。
///
/// 镜像 `table.move::submit_shuffle_v2`（line 1790-1845）。
pub fn apply_submit_shuffle_v2(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    shuffle_proof: ShuffleProof,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.shuffle_phase() == SHUFFLE_PHASE_NONE {
        return Err(PokerL1Error::Serialization("shuffle phase is NONE".into()));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }
    let current_shuffler = table.shuffle_state().derived_current_shuffler();
    if current_shuffler != seat_index {
        return Err(PokerL1Error::Serialization(format!(
            "not shuffler's turn: expected {:?}, got {seat_index}",
            current_shuffler
        )));
    }
    if seat_mask_contains(table.shuffle_state().completed_mask, seat_index) {
        return Err(PokerL1Error::Serialization(
            "already completed shuffle".into(),
        ));
    }

    // typed 化后无需反序列化
    let output_cts = output_cards;

    // input_cts = 当前 deck（已是 Vec<ElGamalCiphertext>）
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.to_vec();

    let agg_pk_pt: G1Projective = table
        .derived_aggregated_pk()?
        .map(|point| point.0)
        .unwrap_or(g1_identity());
    let _ = utils::verify_or_skip(utils::test_only_crypto_skip(), || {
        let mut t = utils::new_shuffle_transcript();
        shuffle_proof
            .verify(&input_cts, &output_cts, &agg_pk_pt, &mut t)
            .map_err(|e| PokerL1Error::Serialization(format!("shuffle proof: {e}")))?;
        Ok(true)
    })?;

    // 链上注入：new_cts[i] = add_pk_to_c2(output_cts[i], player_pk)
    // ECPoint → G1Projective（Seat.pk 字段为 ECPoint）
    // 注入语义按洗牌用途区分：
    // - Initial（逐层构建旧协议）：客户端输出不含自己的 pk 层，链上代注入
    //   `c2 += player_pk`（当前生产开局洗牌不经 dispatch——镜像在
    //   record_hand_start 注入终局 deck，此分支保留仅为语义完备）。
    // - Reconstruct（重构后重洗）：重建 deck（canonical base + Σcontributions）
    //   已含全员 pk 层，客户端纯 shuffle（share_pk = agg_total）的输出保持
    //   `c2 = m + r'·agg` 不变量——再注入会双重加层破坏可解性。
    let new_cts: Vec<ElGamalCiphertext> = if table.shuffle_phase() == SHUFFLE_PHASE_RECONSTRUCT {
        output_cts.clone()
    } else {
        let player_pk: G1Projective = table.seats[seat_index as usize]
            .pk()
            .ok_or_else(|| PokerL1Error::Serialization("shuffle seat has no live key".into()))?
            .0;
        output_cts
            .iter()
            .map(|ct| utils::add_pk_to_c2(ct, &player_pk))
            .collect()
    };
    table.deck_state.encrypted = CipherDeck::try_from(new_cts)?;

    let shuffle_state = table.active_shuffle_state_mut()?;
    shuffle_state.completed_mask |= 1u16 << seat_index;
    seat_mask_remove(&mut shuffle_state.pending_mask, seat_index);

    events::emit_event(
        events,
        TexasPokerEvent::ShuffleVerified {
            table_id: table.id,
            seat_index,
            player: table.seats[seat_index as usize].player(),
        },
    );

    advance_shuffle(table, events)?;
    Ok(())
}

/// 玩家提交 reveal token（批量）。
///
/// 镜像 `table.move::submit_player_reveal_tokens`（line 1900-2064）。
#[allow(clippy::too_many_arguments)]
pub fn apply_submit_player_reveal_tokens(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reveal_tokens: Vec<G1Projective>,
    proofs: Vec<RevealTokenProof<DefaultCurve>>,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.reveal_token_state().is_none() {
        // 专用变体（非 Serialization）：入口队列据此把"窗口未开的抢跑
        // reveal"分类为可重试暂存，其余 Serialization 失败一律门口拒绝。
        return Err(PokerL1Error::PhaseWindowClosed {
            detail: "reveal phase is NONE".into(),
        });
    }
    if reveal_tokens.len() != proofs.len() {
        return Err(PokerL1Error::Serialization(
            "reveal_tokens/proofs length mismatch".into(),
        ));
    }
    if reveal_tokens.is_empty() {
        return Err(PokerL1Error::Serialization(
            "reveal token submission must not be empty".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }

    let phase = table.reveal_phase();
    let assignment_indices = table
        .reveal_token_state()
        .expect("checked active reveal above")
        .assignments
        .iter()
        .enumerate()
        .filter_map(|(index, assignment)| {
            seat_mask_contains(assignment.pending_mask(), seat_index).then_some(index as u8)
        })
        .collect::<Vec<_>>();
    if assignment_indices.len() != reveal_tokens.len() {
        // 同上：canonical 数量不合是"抢跑下一街窗口"的典型形态（e2e 的
        // 提前 turn reveal 正走此处）——专用变体供队列暂存，窗口轮转后
        // 同一提交即对齐；真正的畸形载荷由队列 MAX_HOLDS 兜底死信。
        return Err(PokerL1Error::PhaseWindowClosed {
            detail: format!(
                "reveal submission must contain every pending assignment in canonical order: expected {} token/proof pairs, got {}",
                assignment_indices.len(),
                reveal_tokens.len()
            ),
        });
    }
    // ECPoint → G1Projective（Seat.pk 字段为 ECPoint）
    let expected_pk: G1Projective = table.seats[seat_index as usize]
        .pk()
        .ok_or_else(|| PokerL1Error::Serialization("reveal seat has no live key".into()))?
        .0;

    for k in 0..assignment_indices.len() {
        let ai = assignment_indices[k] as usize;
        if ai >= table.reveal_assignments().len() {
            return Err(PokerL1Error::Serialization(format!(
                "assignment_index {ai} out of range"
            )));
        }
        // 取 assignment 的可变引用前先检查
        {
            let reveal_state = table
                .reveal_token_state()
                .expect("checked active reveal above");
            let assignment = &reveal_state.assignments[ai];
            if assignment.is_ready() {
                return Err(PokerL1Error::Serialization(format!(
                    "assignment {ai} already resolved"
                )));
            }
            if !seat_mask_contains(assignment.pending_mask(), seat_index) {
                return Err(PokerL1Error::Serialization(format!(
                    "seat {seat_index} not in pending for assignment {ai}"
                )));
            }
        }

        let card_index = table.reveal_assignments()[ai].encrypted_card_index;

        // 取用于 proof 验证的密文。
        // - showdown：手牌已部分解密，密文存于固定 `(seat, slot)` ledger
        //   （自包含，与 deck_state.encrypted 解耦）。这点对 reconstruct 后的场景
        //   至关重要：rebuild 后 deck_state.encrypted 是全新 deck，旧 card_index 在
        //   其中指向不同密文，但 partial 记录自包含，proof 验证仍基于原 partial 密文。
        // - 其他阶段（preflop/公共牌）：直接用当前 deck 的密文。
        let encrypted_card = if phase == REVEAL_PHASE_SHOWDOWN {
            let RevealTarget::Hole {
                seat_index: owner_seat,
                card_slot,
            } = table.reveal_assignments()[ai].target
            else {
                return Err(PokerL1Error::Serialization(
                    "showdown reveal assignment must target a hole-card slot".into(),
                ));
            };
            if owner_seat != seat_index {
                return Err(PokerL1Error::Serialization(format!(
                    "showdown reveal submitter {seat_index} does not own target seat {owner_seat}"
                )));
            }
            let partial = table
                .deck_state
                .owner_readable_hole_cards
                .get(owner_seat, card_slot)
                .ok_or_else(|| {
                    PokerL1Error::Serialization(format!(
                        "showdown partial ciphertext is missing: seat={owner_seat}, slot={card_slot}"
                    ))
                })?;
            if partial.encrypted_card_index != card_index {
                return Err(PokerL1Error::Serialization(format!(
                    "showdown assignment/ledger lineage mismatch: assignment={card_index}, ledger={}",
                    partial.encrypted_card_index
                )));
            }
            // 客户端 reveal-token 证明绑定的是发牌时的完整密文（challenge 含
            // c2），而非剥层后的 partial 密文；验证必须用 ledger 保存的完整
            // 密文（自包含，reconstruct 重建 deck 后仍可验证）。
            partial.full_ciphertext
        } else {
            if card_index as usize >= table.deck_state.encrypted.len() {
                return Err(PokerL1Error::Serialization(format!(
                    "card_index {card_index} out of range"
                )));
            }
            table.deck_state.encrypted[card_index as usize]
        };
        let token = reveal_tokens[k];
        let proof = &proofs[k];

        let token_pt = token;
        let _ = utils::verify_or_skip(utils::test_only_crypto_skip(), || {
            RevealTokenProof::verify(
                proof,
                &encrypted_card,
                &token_pt,
                &expected_pk,
                &mut PoseidonFeltTranscript::new_domain(
                    poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
                ),
            )
            .map_err(|e| PokerL1Error::Serialization(format!("reveal token proof: {e:?}")))?;
            Ok(true)
        })?;

        // Add the token at the canonical position implied by the submitted-seat mask.
        {
            let assignment = &mut table.active_reveal_state_mut()?.assignments[ai];
            let insert_index = assignment.submitted_mask.count_ones() as usize;
            if insert_index != assignment.reveal_tokens.len() {
                return Err(PokerL1Error::Serialization(format!(
                    "assignment {ai} token vector is not canonical"
                )));
            }
            assignment
                .reveal_tokens
                .insert(insert_index, ECPoint(token));
            seat_mask_remove(&mut assignment.pending_mask, seat_index);
            assignment.submitted_mask |= 1u16 << seat_index;
        }

        events::emit_event(
            events,
            TexasPokerEvent::RevealTokenSubmitted {
                table_id: table.id,
                seat_index,
                card_index,
                phase,
            },
        );
    }

    materialize_completed_reveal_assignments(table, events)?;
    // 命令内联级联（reveal 完成检查 → post_blinds / 开下一窗口）：armed 时
    // 作为 CompleteReveal micro-step 进轨迹（有实际状态变更才记）。
    // runout 边界：start_betting_round 内的 all-in runout 已把
    // AdvanceBettingRound 记为独立 step（pre = 新开下注轮）——CompleteReveal
    // 行的 post 取边界锚（同一状态），行链逐行咬合。
    if normalization_trace_armed() {
        let before = table.clone();
        check_reveal_phase_complete(table, now_ms, events)?;
        let boundary = take_completion_boundary();
        match boundary {
            Some(fresh_betting) => {
                if fresh_betting != before {
                    record_step_trace(NormalizationStep::CompleteReveal, &before, &fresh_betting);
                }
            }
            None => {
                if *table != before {
                    record_step_trace(NormalizationStep::CompleteReveal, &before, table);
                }
            }
        }
    } else {
        check_reveal_phase_complete(table, now_ms, events)?;
    }
    Ok(())
}

fn completed_reveal_tokens(assignment: &RevealAssignment) -> PokerL1Result<Vec<G1Projective>> {
    if assignment.pending_mask != 0 {
        return Err(PokerL1Error::Serialization(
            "reveal assignment is not a freshly completed collection".into(),
        ));
    }
    if assignment.submitted_mask.count_ones() as usize != assignment.reveal_tokens.len() {
        Err(PokerL1Error::Serialization(
            "completed reveal assignment has a non-canonical token vector".into(),
        ))
    } else {
        Ok(assignment
            .reveal_tokens
            .iter()
            .map(|token| token.0)
            .collect())
    }
}

/// Materialize every freshly completed assignment before the dispatch may persist.
///
/// Preflop results become the one partial-ciphertext ledger needed for owner reveal. Public cards
/// and showdown cards are written directly to their final board/hand slots, so fresh execution
/// never creates `Ready*` progress or plaintext ledger records.
fn materialize_completed_reveal_assignments(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let reveal = table.reveal_token_state().ok_or_else(|| {
        PokerL1Error::Serialization("cannot materialize outside reveal state".into())
    })?;
    let purpose = reveal.purpose;
    let phase = table.reveal_phase();
    let completed = table
        .reveal_token_state()
        .expect("checked active reveal above")
        .assignments
        .iter()
        .enumerate()
        .filter(|(_, assignment)| assignment.pending_mask == 0)
        .map(|(index, assignment)| (index, assignment.clone()))
        .collect::<Vec<_>>();
    if completed.is_empty() {
        return Ok(());
    }

    let mut next = table.clone();
    let mut staged_events = Vec::new();
    match purpose {
        // DealHole 与 RedealHole 共用同一物化语义：把 (owner, slot) 的 partial
        // 账本条目更新为"剥掉全部他人层"的密文（redeal 时同时换绑到新牌的
        // deck 索引，替换换牌 dispatch 写入的占位条目）。
        RevealPurpose::DealHole | RevealPurpose::RedealHole => {
            for (_, assignment) in &completed {
                let RevealTarget::Hole {
                    seat_index,
                    card_slot,
                } = assignment.target
                else {
                    return Err(PokerL1Error::Serialization(
                        "preflop reveal completed a non-hole assignment".into(),
                    ));
                };
                let card_index = assignment.encrypted_card_index;
                let encrypted = next
                    .deck_state
                    .encrypted
                    .get(usize::from(card_index))
                    .ok_or_else(|| {
                        PokerL1Error::Serialization(format!(
                            "preflop reveal card index {card_index} is out of range"
                        ))
                    })?;
                let tokens = completed_reveal_tokens(assignment)?;
                // RedealHole：先移除换牌 dispatch 写入的同槽占位条目（其 deck
                // 索引就是本 assignment 的新牌索引），再写入真实部分解密。
                if purpose == RevealPurpose::RedealHole {
                    next.deck_state
                        .owner_readable_hole_cards
                        .remove(seat_index, card_slot)?;
                }
                next.deck_state.owner_readable_hole_cards.insert(
                    seat_index,
                    card_slot,
                    PartialHoleCard::new(
                        card_index,
                        ElGamalCiphertext {
                            c1: encrypted.c1,
                            c2: partial_decrypt_c2(&encrypted.c2, &tokens),
                        },
                        *encrypted,
                    ),
                )?;
            }
        }
        RevealPurpose::Board => {
            if completed.len() != next.reveal_assignments().len() {
                return Err(PokerL1Error::Serialization(
                    "community reveal assignments did not complete as one canonical batch".into(),
                ));
            }
            materialize_completed_community_assignments(
                &mut next,
                phase,
                &completed,
                &mut staged_events,
            )?;
        }
        RevealPurpose::ShowdownOwner => {
            materialize_completed_showdown_assignments(&mut next, &completed, &mut staged_events)?;
        }
    }

    for (assignment_index, _) in completed.iter().rev() {
        next.active_reveal_state_mut()?
            .assignments
            .remove(*assignment_index);
    }
    *table = next;
    events.extend(staged_events);
    Ok(())
}

fn materialize_completed_community_assignments(
    table: &mut TexasPokerTable,
    reveal_phase: u8,
    completed: &[(usize, RevealAssignment)],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let canonical_cards = generate_plaintext_cards();
    let mut seen = exposed_card_ids(table)?;
    let mut expected_positions = [
        table.community_cards.len(),
        table.run_it_twice_state.second_board_len(),
    ];
    let mut materialized = Vec::with_capacity(completed.len());
    for (_, assignment) in completed {
        let RevealTarget::Board {
            runout_index,
            board_position,
        } = assignment.target
        else {
            return Err(PokerL1Error::Serialization(
                "community reveal completed a hole assignment".into(),
            ));
        };
        let runout = usize::from(runout_index);
        let active_runouts = if table.run_it_twice_state.is_active() {
            2
        } else {
            1
        };
        if runout >= active_runouts || usize::from(board_position) != expected_positions[runout] {
            return Err(PokerL1Error::Serialization(format!(
                "community reveal target is not the canonical next position for runout {runout}"
            )));
        }
        let encrypted = table
            .deck_state
            .encrypted
            .get(usize::from(assignment.encrypted_card_index))
            .ok_or_else(|| {
                PokerL1Error::Serialization("community reveal card index is out of range".into())
            })?;
        let plaintext = partial_decrypt_c2(&encrypted.c2, &completed_reveal_tokens(assignment)?);
        let (card_id, card) = card_from_plaintext(&plaintext, &canonical_cards)?;
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "duplicate decrypted card id {card_id} while writing community cards"
            )));
        }
        expected_positions[runout] += 1;
        materialized.push((assignment.encrypted_card_index, runout, card));
    }

    let mut indices = [0u8; 6];
    let mut ranks = [0u8; 6];
    let mut suits = [0u8; 6];
    let mut card_count = 0usize;
    for (encrypted_card_index, runout, card) in materialized {
        if runout == 0 {
            table.community_cards.try_push(card).map_err(|error| {
                PokerL1Error::Serialization(format!("cannot append first-board card: {error}"))
            })?;
        } else {
            table
                .run_it_twice_state
                .second_board_suffix_mut()?
                .try_push(card)
                .map_err(|error| {
                    PokerL1Error::Serialization(format!(
                        "cannot append second-board suffix card: {error}"
                    ))
                })?;
        }
        indices[card_count] = encrypted_card_index;
        ranks[card_count] = card.rank();
        suits[card_count] = card.suit();
        card_count += 1;
    }
    events::emit_event(
        events,
        TexasPokerEvent::CommunityCardRevealed {
            table_id: table.id,
            phase: reveal_phase,
            card_indices: indices,
            card_ranks: ranks,
            card_suits: suits,
            card_count: card_count as u8,
        },
    );
    Ok(())
}

fn materialize_completed_showdown_assignments(
    table: &mut TexasPokerTable,
    completed: &[(usize, RevealAssignment)],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let canonical_cards = generate_plaintext_cards();
    let mut seen = exposed_card_ids(table)?;
    let mut materialized = Vec::with_capacity(completed.len());
    for (_, assignment) in completed {
        let RevealTarget::Hole {
            seat_index,
            card_slot,
        } = assignment.target
        else {
            return Err(PokerL1Error::Serialization(
                "showdown reveal completed a board assignment".into(),
            ));
        };
        let record = table
            .deck_state
            .owner_readable_hole_cards
            .get(seat_index, card_slot)
            .ok_or_else(|| {
                PokerL1Error::Serialization(format!(
                    "showdown partial ledger slot is missing: seat={seat_index}, slot={card_slot}"
                ))
            })?;
        if record.encrypted_card_index != assignment.encrypted_card_index {
            return Err(PokerL1Error::Serialization(format!(
                "showdown assignment/ledger lineage mismatch: assignment={}, ledger={}",
                assignment.encrypted_card_index, record.encrypted_card_index
            )));
        }
        let plaintext =
            partial_decrypt_c2(&record.ciphertext.c2, &completed_reveal_tokens(assignment)?);
        let (card_id, card) = card_from_plaintext(&plaintext, &canonical_cards)?;
        if !seen.insert(card_id) {
            return Err(PokerL1Error::Serialization(format!(
                "duplicate decrypted card id {card_id} while writing hole cards"
            )));
        }
        materialized.push((seat_index, card_slot, assignment.encrypted_card_index, card));
    }

    let mut next_slot = table
        .seats
        .iter()
        .map(|seat| seat.hand().map_or(0, HoleCards::len))
        .collect::<Vec<_>>();
    for (seat_index, card_slot, encrypted_card_index, card) in materialized {
        let seat = table
            .seats
            .get_mut(usize::from(seat_index))
            .ok_or_else(|| PokerL1Error::Serialization("showdown owner is out of range".into()))?;
        if !seat.is_occupied() || usize::from(card_slot) != next_slot[usize::from(seat_index)] {
            return Err(PokerL1Error::Serialization(format!(
                "showdown hole-card slot {card_slot} is not canonical for seat {seat_index}"
            )));
        }
        seat.hand_mut()?.try_push(card).map_err(|error| {
            PokerL1Error::Serialization(format!(
                "cannot append hole card for seat {seat_index}: {error}"
            ))
        })?;
        next_slot[usize::from(seat_index)] += 1;
        if !seat.is_folded() {
            events::emit_event(
                events,
                TexasPokerEvent::ShowdownHoleCardsRevealed {
                    table_id: table.id,
                    seat_index,
                    player: seat.player(),
                    card_indices: [encrypted_card_index, 0],
                    card_ranks: [card.rank(), 0],
                    card_suits: [card.suit(), 0],
                },
            );
        }
        table
            .deck_state
            .owner_readable_hole_cards
            .remove(seat_index, card_slot)?;
    }
    Ok(())
}

/// 玩家提交 reconstruct deck。
///
/// 镜像 `table.move::submit_reconstruct_deck`（line 2218-2275）。
#[allow(clippy::too_many_arguments)]
pub fn apply_submit_reconstruct_deck(
    table: &mut TexasPokerTable,
    seat_index: u8,
    statement: ReconstructionStatement<DefaultCurve>,
    proof: ReconstructProof<DefaultCurve>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.reconstruct_phase() != RECONSTRUCT_PHASE_COLLECTING {
        return Err(PokerL1Error::Serialization(
            "reconstruct not in COLLECTING phase".into(),
        ));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization("seat not occupied".into()));
    }
    if !seat_mask_contains(table.reconstruct_state().pending_mask, seat_index) {
        return Err(PokerL1Error::Serialization(
            "seat not in reconstruct pending".into(),
        ));
    }

    let aggregate_pk = table.derived_aggregated_pk()?.ok_or_else(|| {
        PokerL1Error::Serialization("reconstruction V3 requires aggregate public key".into())
    })?;
    let expected_owner_pk = table.seats[seat_index as usize]
        .pk()
        .ok_or_else(|| PokerL1Error::Serialization("reconstruct seat has no live key".into()))?
        .0;
    let expected_cards = generate_plaintext_cards();
    let expected_readable = utils::reconstruction_v3_residual_carriers(table, seat_index);
    let expected_context_digest = utils::reconstruction_v3_context_digest(table);
    let expected_prior_state_digest =
        utils::reconstruction_v3_prior_state_digest(table, seat_index)?;
    let expected_epoch = table.reconstruct_epoch_ms().ok_or_else(|| {
        PokerL1Error::Serialization("reconstruction epoch is unavailable outside phase".into())
    })?;
    if statement.aggregate_pk != aggregate_pk.0
        || statement.owner_pk != expected_owner_pk
        || statement.cards != expected_cards
        || statement.residual_carriers != expected_readable
        || statement.context_digest != expected_context_digest
        || statement.prior_state_digest != expected_prior_state_digest
        || statement.reconstruction_epoch != expected_epoch
    {
        return Err(PokerL1Error::Serialization(
            "reconstruction V3 statement does not match authenticated table state".into(),
        ));
    }
    let contributions = statement.contributions.clone();

    let _ = utils::verify_or_skip(utils::test_only_crypto_skip(), || {
        let mut transcript = utils::new_reconstruct_v3_transcript();
        proof.verify(&statement, &mut transcript).map_err(|error| {
            PokerL1Error::Serialization(format!("reconstruction V3 proof: {error}"))
        })?;
        Ok(true)
    })?;

    let prior_accumulator = if let Some(deck) = &table.deck_state.reconstruct_accumulated {
        deck.clone()
    } else {
        canonical_base_deck::<DefaultCurve>(&expected_cards, &aggregate_pk.0).map_err(|error| {
            PokerL1Error::Serialization(format!("reconstruction V3 base deck: {error}"))
        })?
    };
    let accumulated_deck =
        apply_reconstruction_contributions::<DefaultCurve>(&prior_accumulator, &contributions)
            .map_err(|error| {
                PokerL1Error::Serialization(format!(
                    "reconstruction V3 contribution for seat {seat_index}: {error}"
                ))
            })?;
    let reconstruct_state = table.active_reconstruct_state_mut()?;
    seat_mask_remove(&mut reconstruct_state.pending_mask, seat_index);
    table.deck_state.reconstruct_accumulated = Some(accumulated_deck);

    events::emit_event(
        events,
        TexasPokerEvent::ReconstructDeckSubmitted {
            table_id: table.id,
            seat_index,
        },
    );

    if table.reconstruct_state().pending_mask == 0 {
        on_complete_reconstruct(table, events)?;
    }
    Ok(())
}

/// 玩家 fold 并提交 fold proof（剥离自己的加密层 + 退出后续 reveal 协议）。
///
/// `fold_with_proof` 在下注轮完成局中弃牌与加密层移除。
///
/// 业务语义（结合 fold 与 leave）：
/// 1. 验证 DLEqProof<LeaveKind>（与 leave 同一 Poseidon epoch leave 生产域，
///    见 `poker_protocol::transcript_domains::LEAVE_POSEIDON_V2`）：
///    证明玩家剥离了自己对整个牌组的加密层（`output.c2 = input.c2 - c1*sk`）。
/// 2. 从 `aggregated_pk` 移除玩家 pk，把 `deck_state.encrypted` 替换为 output_cards。
///    c1 不变（DLEq verify 强制）→ 已收集的 reveal tokens 仍然有效。
/// 3. Scrub 玩家在所有协议 pending 列表中的痕迹（shuffle / reconstruct /
///    reveal assignments），让**后续解牌不需要该玩家参加**。
/// 4. 标记 `seat.folded = true`（保留 seat.pk / total_bet / bet，不设
///    left_during_hand）—— 玩家仍参与 side-pot 记账，只是已弃牌 + 退出协议。
///
/// # 与普通 fold 的区别
///
/// - 普通 `apply_fold`：仅置 `folded=true`，玩家 pk 仍在 aggregated_pk 中，
///   仍需为后续公共牌提交 reveal token（或被超时踢出）。
/// - `apply_fold_with_proof`：玩家立即从协议中「物理退出」，剥离加密层，
///   后续 reveal 不再需要他（也不会被超时罚）。
///
/// # Errors
///
/// - 非下注轮（WAITING / reveal phase / showdown）
/// - 非该玩家行动轮
/// - `seat_index` 越界 / 座位未占用 / 已 folded
/// - fold proof 验证失败（skip_remask=false 时）
pub fn apply_fold_with_proof(
    table: &mut TexasPokerTable,
    seat_index: u8,
    output_cards: Vec<ElGamalCiphertext>,
    fold_proof: DLEqProof<DefaultCurve, LeaveKind>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // 1. Guards（对齐 apply_fold_internal）
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization(
            "fold_with_proof: not in betting round".into(),
        ));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: not seat {seat_index}'s turn (current_turn={:?})",
            table.current_turn()
        )));
    }
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat {seat_index} not occupied"
        )));
    }
    if seat.is_folded() {
        return Err(PokerL1Error::Serialization(format!(
            "fold_with_proof: seat {seat_index} already folded"
        )));
    }

    // 2. 验证 DLEq layer-removal proof（排除集强校验，防亮牌）：
    //    剥层输出公开 input.c2 − output.c2 = sk·c1（= 该玩家对每张牌的
    //    reveal token）。弃牌者自己的手牌槽必须原样保留——否则其余玩家
    //    串谋（N−1 份 token + 公开的这份）即可解密其底牌，违反规则。
    //    排除集从 reveal assignments 推导（公开状态），不信任提交方。
    let output_cts = output_cards;
    let input_cts: Vec<ElGamalCiphertext> = table.deck_state.encrypted.to_vec();
    let player_pk = *table.seats[seat_index as usize]
        .pk()
        .ok_or_else(|| PokerL1Error::Serialization("fold seat has no live key".into()))?;

    let excluded: Vec<usize> = table
        .reveal_assignments()
        .iter()
        .filter_map(|a| match a.target {
            RevealTarget::Hole { seat_index: s, .. } if s == seat_index => {
                Some(usize::from(a.encrypted_card_index))
            }
            _ => None,
        })
        .collect();
    for &i in &excluded {
        if i >= output_cts.len() {
            return Err(PokerL1Error::Serialization(format!(
                "fold_with_proof: excluded slot {i} out of range"
            )));
        }
        if output_cts[i].c1 != input_cts[i].c1 || output_cts[i].c2 != input_cts[i].c2 {
            return Err(PokerL1Error::Serialization(format!(
                "fold_with_proof: own hole card slot {i} must stay unchanged (anti-reveal rule)"
            )));
        }
    }
    let sub_input: Vec<ElGamalCiphertext> = input_cts
        .iter()
        .enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, ct)| ct.clone())
        .collect();
    let sub_output: Vec<ElGamalCiphertext> = output_cts
        .iter()
        .enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, ct)| ct.clone())
        .collect();
    let _ = utils::verify_or_skip(utils::test_only_crypto_skip(), || {
        let mut t = utils::new_leave_transcript();
        let ok = DLEqProof::<DefaultCurve, LeaveKind>::verify(
            &fold_proof,
            &sub_input,
            &sub_output,
            &player_pk,
            &mut t,
        );
        if ok {
            Ok(true)
        } else {
            Err(PokerL1Error::Serialization(
                "fold_with_proof: proof verify failed".into(),
            ))
        }
    })?;

    // 3. 剥离 pk + 替换 deck；mask is the canonical lineage, aggregate is a cache.
    table.remove_deck_contributor(seat_index)?;
    table.deck_state.encrypted = CipherDeck::try_from(output_cts)?;

    // 4. 标记 fold（对齐 apply_fold_internal 1787-1788）。Betting is mutually exclusive
    // with shuffle/reveal/reconstruct, so there are no hidden protocol masks to scrub.
    //    保留 seat.pk / total_bet / bet / stack；不设 left_during_hand。
    let seat = &mut table.seats[seat_index as usize];
    seat.set_status(SeatStatus::Folded);
    table.set_seat_acted_this_round(seat_index, true);
    table.disarm_betting_deadline()?;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerFolded {
            table_id: table.id,
            seat_index,
            reason: FOLD_REASON_MANUAL,
            round_state: table.round_state(),
        },
    );

    // 5. 推进轮次（复制 apply_fold_internal 1800-1807）
    if count_active_players(&table.seats) <= 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    advance_turn(table, events)?;
    Ok(())
}

// ========== 下注动作 ==========

/// 玩家弃牌。
pub fn apply_fold(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    apply_fold_internal(table, seat_index, FOLD_REASON_MANUAL, events)
}

/// 内部 fold 实现（被 apply_fold / on_betting_timeout 共用）。
///
/// 暴露为 pub 供 dispatch.rs 的 auto_fold / force_fold 复用（带不同 reason）。
pub fn apply_fold_internal(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    apply_player_action(table, seat_index, PlayerAction::Fold { reason }, events)
}

/// Apply one canonical player action.
///
/// This is deliberately the only implementation of the ordinary betting
/// transition.  Compatibility selectors perform their legacy argument and
/// authorization checks, then lower to this function so a method batch has a
/// single transition shape for fold/match/raise.
pub fn apply_player_action(
    table: &mut TexasPokerTable,
    seat_index: u8,
    action: PlayerAction,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "player action seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization("not in betting round".into()));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("not player's turn".into()));
    }
    match action {
        PlayerAction::Fold { reason } => {
            if table.seats[seat_index as usize].is_folded() {
                return Err(PokerL1Error::Serialization("already folded".into()));
            }
            table.seats[seat_index as usize].set_status(SeatStatus::Folded);
            table.set_seat_acted_this_round(seat_index, true);
            table.disarm_betting_deadline()?;
            events::emit_event(
                events,
                TexasPokerEvent::PlayerFolded {
                    table_id: table.id,
                    seat_index,
                    reason,
                    round_state: table.round_state(),
                },
            );
        }
        PlayerAction::MatchBet => {
            let round = table.betting_round().expect("checked above");
            let current_bet = round.current_bet;
            let seat = &mut table.seats[seat_index as usize];
            if seat.is_folded() || seat.is_all_in() {
                return Err(PokerL1Error::Serialization("player inactive".into()));
            }
            if seat.bet() >= current_bet {
                table.set_seat_acted_this_round(seat_index, true);
                table.disarm_betting_deadline()?;
                events::emit_event(
                    events,
                    TexasPokerEvent::PlayerChecked {
                        table_id: table.id,
                        seat_index,
                        round_state: table.round_state(),
                    },
                );
            } else {
                let playing = seat.playing_mut()?;
                let call_amt = round.process_call(playing.bet, playing.occupied.stack);
                playing.occupied.stack = playing
                    .occupied
                    .stack
                    .checked_sub(call_amt)
                    .ok_or_else(|| PokerL1Error::Serialization("stack underflow on call".into()))?;
                playing.bet = playing
                    .bet
                    .checked_add(call_amt)
                    .ok_or_else(|| PokerL1Error::Serialization("bet overflow on call".into()))?;
                playing.total_bet = playing.total_bet.checked_add(call_amt).ok_or_else(|| {
                    PokerL1Error::Serialization("total_bet overflow on call".into())
                })?;
                let is_all_in = playing.occupied.stack == 0 && call_amt > 0;
                if is_all_in {
                    playing.status = PlayingSeatStatus::AllIn;
                }
                table.set_seat_acted_this_round(seat_index, true);
                table.disarm_betting_deadline()?;
                events::emit_event(
                    events,
                    TexasPokerEvent::PlayerCalled {
                        table_id: table.id,
                        seat_index,
                        call_delta: call_amt,
                        round_state: table.round_state(),
                    },
                );
                if is_all_in {
                    events::emit_event(
                        events,
                        TexasPokerEvent::PlayerAllIn {
                            table_id: table.id,
                            seat_index,
                            trigger_action: TRIGGER_ACTION_CALL_ALL_IN,
                            amount: call_amt,
                            round_state: table.round_state(),
                        },
                    );
                }
            }
        }
        PlayerAction::RaiseTo(total_bet) => {
            let seat_bet = table.seats[seat_index as usize].bet();
            let seat_stack = table.seats[seat_index as usize].stack();
            let (prev_current_bet, prev_min_raise) = {
                let round = table.active_betting_round_mut()?;
                (round.current_bet, round.min_raise)
            };
            // 短 all-in（raise_amount < min_raise）不重新打开行动权（TDA #41）：
            // 已行动过的玩家（acted 位仍置位，说明其后只发生过短 all-in）
            // 面对 current_bet 只能 call 或 fold，不得再加注；
            // 只有完整 raise 才会清除 acted 位并恢复加注权。
            if table.seat_acted_this_round(seat_index) {
                return Err(PokerL1Error::ContractExecutionFailed(
                    "betting error: action not reopened for acted seat (call or fold only)".into(),
                ));
            }
            let needed = table
                .active_betting_round_mut()?
                .process_raise(total_bet, seat_bet, seat_stack)?;
            let seat = table.seats[seat_index as usize].playing_mut()?;
            seat.occupied.stack =
                seat.occupied.stack.checked_sub(needed).ok_or_else(|| {
                    PokerL1Error::Serialization("stack underflow on raise".into())
                })?;
            seat.bet = total_bet;
            seat.total_bet = seat
                .total_bet
                .checked_add(needed)
                .ok_or_else(|| PokerL1Error::Serialization("total_bet overflow on raise".into()))?;
            let is_all_in = seat.occupied.stack == 0;
            if is_all_in {
                seat.status = PlayingSeatStatus::AllIn;
            }
            table.set_seat_acted_this_round(seat_index, true);
            table.disarm_betting_deadline()?;
            // 只有达到最小加注额的完整 raise 才重新打开其他玩家的行动权；
            // 短 all-in（raise_amount < min_raise）只抬高 current_bet，
            // 不清除已行动玩家的 acted 标记（call/fold 仍按新水位进行）。
            let reopens_action = total_bet - prev_current_bet >= prev_min_raise;
            if reopens_action {
                for (i, s) in table.seats.iter().enumerate() {
                    if i as u8 != seat_index
                        && s.is_occupied()
                        && !s.is_folded()
                        && !s.is_all_in()
                        && !s.is_waiting()
                    {
                        table.acted_mask &= !(1u16 << i);
                    }
                }
            }
            events::emit_event(
                events,
                TexasPokerEvent::PlayerRaised {
                    table_id: table.id,
                    seat_index,
                    raise_delta: needed,
                    total_bet,
                    round_state: table.round_state(),
                },
            );
            if is_all_in {
                events::emit_event(
                    events,
                    TexasPokerEvent::PlayerAllIn {
                        table_id: table.id,
                        seat_index,
                        trigger_action: TRIGGER_ACTION_RAISE_ALL_IN,
                        amount: needed,
                        round_state: table.round_state(),
                    },
                );
            }
        }
    }

    if matches!(action, PlayerAction::Fold { .. }) && count_active_players(&table.seats) <= 1 {
        // 命令内联级联（终局弃牌 → 派奖 + 复位）：作为 EndWithoutShowdown
        // micro-step 进轨迹（armed 时），与 normalize 级联同构呈现。
        if normalization_trace_armed() {
            let before = table.clone();
            end_without_showdown(table, events)?;
            record_step_trace(NormalizationStep::EndWithoutShowdown, &before, table);
        } else {
            end_without_showdown(table, events)?;
        }
        return Ok(());
    }
    advance_turn(table, events)?;
    Ok(())
}

/// 玩家过牌。
pub fn apply_check(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let current_bet = table
        .betting_round()
        .map(|round| round.current_bet)
        .ok_or_else(|| PokerL1Error::Serialization("not in betting round".into()))?;
    let seat_bet = table
        .seats
        .get(usize::from(seat_index))
        .ok_or_else(|| PokerL1Error::Serialization("seat index out of range".into()))?
        .bet();
    if seat_bet < current_bet {
        return Err(PokerL1Error::Serialization(
            "cannot check: bet < current_bet".into(),
        ));
    }
    apply_player_action(table, seat_index, PlayerAction::MatchBet, events)
}

/// 玩家跟注（与 check 共用 canonical `MatchBet` transition）。
pub fn apply_call(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let round_bet = table
        .betting_round()
        .map(|round| round.current_bet)
        .ok_or_else(|| PokerL1Error::Serialization("not in betting round".into()))?;
    let seat_bet = table
        .seats
        .get(usize::from(seat_index))
        .ok_or_else(|| PokerL1Error::Serialization("seat index out of range".into()))?
        .bet();
    if seat_bet >= round_bet {
        return Err(PokerL1Error::Serialization(
            "cannot call when no chips are owed; use check".into(),
        ));
    }
    apply_player_action(table, seat_index, PlayerAction::MatchBet, events)
}

/// 玩家加注到 total_bet。
pub fn apply_raise(
    table: &mut TexasPokerTable,
    seat_index: u8,
    total_bet: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    apply_player_action(table, seat_index, PlayerAction::RaiseTo(total_bet), events)
}

// ========== 开局 / 超时 / 结算 ==========

/// waiting-for-BB：把应在大盲位入局的 Waiting 座位提升为参与座位。
///
/// 提升规则（确定性，防"离桌—重入躲盲注"）：
/// - 桌上没有任何参与座位（全新桌）时，所有 Waiting 座位一起入局；
/// - 否则从 button 顺时针找到第一个参与座位（本手 SB），紧随其后的
///   occupied 座位若是 Waiting 则提升（正好以 BB 身份入局）；
/// - 提升后参与人数仍不足 `MIN_PLAYERS_TO_START` 时，按 button 之后的
///   顺序提升最早的 Waiting 座位补足（保证有人等待时牌桌可以开局）。
fn promote_waiting_for_big_blind(table: &mut TexasPokerTable) {
    let n = usize::from(table.max_players);
    let participating = |seats: &[Seat]| {
        seats
            .iter()
            .filter(|s| s.is_occupied() && !s.is_waiting())
            .count()
    };

    if participating(&table.seats) == 0 {
        // 全新桌：没有可参照的盲注轨道，所有等待座位同时入局。
        for seat in table.seats.iter_mut() {
            seat.promote_waiting();
        }
        return;
    }

    // dead button 盲注轨道：等待入局者在其"轮到大盲"的那一手入局——
    // 从上一手大盲（首手为 button）顺时针数，第一个被占用的座位若是
    // waiting 座位则以 BB 身份入局；若是参与座位，本手大盲已有归属。
    let rotation_base = if table.last_bb_seat != NO_SEAT {
        table.last_bb_seat
    } else {
        table.button
    };
    for offset in 1..=n {
        let idx = (usize::from(rotation_base) + offset) % n;
        if table.seats[idx].is_occupied() {
            if table.seats[idx].is_waiting() {
                table.seats[idx].promote_waiting();
            }
            break;
        }
    }

    // 补足开局人数下限。
    let mut count = participating(&table.seats);
    if count < usize::from(MIN_PLAYERS_TO_START) {
        for offset in 1..=n {
            let idx = (usize::from(table.button) + offset) % n;
            if table.seats[idx].is_waiting() {
                table.seats[idx].promote_waiting();
                count += 1;
                if count >= usize::from(MIN_PLAYERS_TO_START) {
                    break;
                }
            }
        }
    }
}

/// 开局：投盲注 + 进入 SHUFFLE_PHASE_BEFORE_PREFLOP + 设置 pending_players。
///
/// 镜像 `table.move::start_hand / do_start_hand`（line 1061-1100）。
pub fn start_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.round_state() != ROUND_WAITING {
        return Err(PokerL1Error::Serialization(format!(
            "not in WAITING state: round_state={}",
            table.round_state()
        )));
    }

    move_button(table);
    // waiting-for-BB：先按盲注位规则提升应入局的等待座位，再校验参与人数。
    promote_waiting_for_big_blind(table);
    if count_active_occupied(&table.seats) < MIN_PLAYERS_TO_START {
        return Err(PokerL1Error::Serialization(format!(
            "active players {} < MIN_PLAYERS_TO_START {}",
            count_active_occupied(&table.seats),
            MIN_PLAYERS_TO_START
        )));
    }
    set_initial_encrypted_deck(table)?;
    // `set_initial_encrypted_deck` replaces the prior deck with the canonical plaintext-base
    // ciphertexts. No per-hand shuffle layer has therefore been applied yet, even though
    // `contributor_mask` already identifies the long-lived aggregate-key members. Keep those
    // facts separate: contributor lineage derives the aggregate verification key, while this
    // phase-local mask records submissions for the freshly initialized hand.
    let completed_mask = 0;
    let pending_mask = get_pending_seat_mask(completed_mask, &table.seats);
    table.enter_initial_shuffling(
        super::types::ShuffleState {
            pending_mask,
            completed_mask,
        },
        0,
    )?;

    let mut active_mask: SeatMask = 0;
    for seat in get_active_seat_indices(&table.seats) {
        seat_mask_insert(&mut active_mask, seat)?;
    }
    events::emit_event(
        events,
        TexasPokerEvent::HandStarted {
            table_id: table.id,
            button: table.button,
            small_blind: table.small_blind,
            big_blind: table.big_blind,
            participants: active_mask,
        },
    );

    advance_shuffle(table, events)?;
    Ok(())
}

/// Deterministically advance the table until fresh external input is required.
///
/// This function never consumes timeouts and never invents a player/admin action. It only
/// performs transitions whose complete witness is already present in the authenticated table:
/// completed crypto collections, completed betting rounds, uncontested settlement, and
/// showdown settlement. The returned ordered steps are the source-level precursor of the
/// tagged-union Stage rows.
///
/// Every micro-transition is applied atomically. Exceeding [`MAX_NORMALIZATION_STEPS`] or
/// encountering a street with no live protocol/betting phase fails closed instead of invoking
/// a legacy refund-and-reset fallback.
pub fn normalize_until_blocked(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<NormalizationReport> {
    let mut candidate = table.clone();
    let mut staged_events = Vec::new();
    let report = normalize_until_blocked_in_place(&mut candidate, now_ms, &mut staged_events)?;
    *table = candidate;
    events.extend(staged_events);
    Ok(report)
}

fn normalize_until_blocked_in_place(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<NormalizationReport> {
    table.arm_active_deadline_if_needed(now_ms)?;
    table.validate_state_schema()?;
    let mut report = NormalizationReport::default();

    for _ in 0..MAX_NORMALIZATION_STEPS {
        let step = if table.reconstruct_phase() != RECONSTRUCT_PHASE_NONE {
            if table.reconstruct_state().pending_mask != 0 {
                None
            } else {
                if table.deck_state.reconstruct_accumulated.is_none() {
                    return Err(PokerL1Error::Serialization(
                        "normalize: completed reconstruct has no player contribution".into(),
                    ));
                }
                Some(NormalizationStep::CompleteReconstruct)
            }
        } else if matches!(
            table.shuffle_phase(),
            SHUFFLE_PHASE_RECONSTRUCT | SHUFFLE_PHASE_BEFORE_PREFLOP
        ) {
            if table.shuffle_state().pending_mask == 0 {
                Some(NormalizationStep::AdvanceShuffle)
            } else {
                None
            }
        } else if table.reveal_token_state().is_some() {
            let all_pending_empty = table
                .reveal_assignments()
                .iter()
                .all(|assignment| assignment.pending_mask() == 0);
            let all_ready = table
                .reveal_assignments()
                .iter()
                .all(RevealAssignment::is_ready);
            if all_pending_empty && !all_ready {
                return Err(PokerL1Error::Serialization(
                    "normalize: reveal assignment has no pending seat but is not resolved".into(),
                ));
            }
            all_ready.then_some(NormalizationStep::CompleteReveal)
        } else if is_betting_round(table) {
            if count_active_players(&table.seats) <= 1 {
                Some(NormalizationStep::EndWithoutShowdown)
            } else if table.current_turn() == NO_SEAT
                || is_betting_complete(table)
                || no_further_betting_possible(table)
            {
                Some(NormalizationStep::AdvanceBettingRound)
            } else {
                None
            }
        } else if table.round_state() == ROUND_SHOWDOWN {
            None
        } else if matches!(
            table.round_state(),
            ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
        ) {
            return Err(PokerL1Error::Serialization(format!(
                "normalize: round {} has no betting, reveal, shuffle, or reconstruct phase",
                table.round_state()
            )));
        } else {
            None
        };

        let Some(step) = step else {
            return Ok(report);
        };

        let before = table.clone();
        let event_len = events.len();
        let result = match step {
            NormalizationStep::CompleteReconstruct => on_complete_reconstruct(table, events),
            NormalizationStep::AdvanceShuffle => advance_shuffle(table, events),
            NormalizationStep::CompleteReveal => check_reveal_phase_complete(table, now_ms, events),
            NormalizationStep::EndWithoutShowdown => end_without_showdown(table, events),
            NormalizationStep::AdvanceBettingRound => {
                collect_bets_to_pot(table, events).and_then(|()| advance_round(table, events))
            }
        };
        if let Err(error) = result {
            *table = before;
            events.truncate(event_len);
            return Err(error);
        }
        if *table == before {
            events.truncate(event_len);
            return Err(PokerL1Error::Serialization(format!(
                "normalize: stage {step:?} made no progress"
            )));
        }
        // 控制逻辑入 AIR：轨迹捕获（未武装零开销）。pre 复用原子回滚的
        // before 克隆，post 为该步落地后的表。
        record_step_trace(step, &before, table);
        table.arm_active_deadline_if_needed(now_ms)?;
        table.validate_state_schema()?;
        let _ = table.canonical_hand_phase()?;
        report.steps.push(step);
    }

    Err(PokerL1Error::Serialization(format!(
        "normalize: exceeded {MAX_NORMALIZATION_STEPS} deterministic stages"
    )))
}

/// Consume the one canonical deadline currently exposed by the table.
///
/// 薄包装：仅返回 `AdvanceDeadlineOutcome`。生产 dispatch 层与 VM 执行走
/// [`advance_deadline_with_report`]（需要确定性阶段报告选择 native relation）；
/// 本包装保留给单元测试，以及 `src/airs/lifecycle/advance_deadline.rs` 的
/// canonical replay（该路径只消费 outcome）。
pub fn advance_deadline(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<AdvanceDeadlineOutcome> {
    advance_deadline_with_report(table, now_ms, events).map(|execution| execution.outcome)
}

/// Consume the current deadline and retain the exact deterministic stages
/// surrounding it for native relation selection.
pub fn advance_deadline_with_report(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<AdvanceDeadlineExecution> {
    let mut candidate = table.clone();
    let mut staged_events = Vec::new();
    let execution = advance_deadline_in_place(&mut candidate, now_ms, &mut staged_events)?;
    *table = candidate;
    events.extend(staged_events);
    Ok(execution)
}

fn advance_deadline_in_place(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<AdvanceDeadlineExecution> {
    // A persisted/current table must already expose an authenticated non-zero deadline. Only the
    // normalization suffix of the command that creates or rotates a phase may arm it.
    table.validate_state_schema()?;
    let pre_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;

    if table.reconstruct_phase() != RECONSTRUCT_PHASE_NONE {
        let deadline_ms = table.reconstruct_deadline_ms()?.ok_or_else(|| {
            PokerL1Error::Serialization("reconstruct phase has no deadline projection".into())
        })?;
        if now_ms < deadline_ms {
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::NotDue {
                    kind: DeadlineKind::Reconstruct,
                    subject: NO_SEAT,
                    deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        on_reconstruct_timeout(table, now_ms, events)?;
        let post_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;
        return Ok(AdvanceDeadlineExecution {
            pre_normalization,
            outcome: AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::Reconstruct,
                subject: NO_SEAT,
            },
            post_normalization,
        });
    }

    let sp = table.shuffle_phase();
    if sp == SHUFFLE_PHASE_RECONSTRUCT || sp == SHUFFLE_PHASE_BEFORE_PREFLOP {
        let subject = table.shuffle_state().derived_current_shuffler();
        let deadline_ms = table.shuffle_deadline_ms()?.ok_or_else(|| {
            PokerL1Error::Serialization("shuffle phase has no deadline projection".into())
        })?;
        if now_ms < deadline_ms {
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::NotDue {
                    kind: DeadlineKind::Shuffle,
                    subject,
                    deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        on_shuffle_timeout(table, now_ms, events)?;
        let post_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;
        return Ok(AdvanceDeadlineExecution {
            pre_normalization,
            outcome: AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::Shuffle,
                subject,
            },
            post_normalization,
        });
    }

    if table.reveal_token_state().is_some() {
        let pending_mask = table
            .reveal_assignments()
            .iter()
            .fold(0u16, |mask, assignment| mask | assignment.pending_mask());
        let subject = seat_mask_first(pending_mask).unwrap_or(NO_SEAT);
        let deadline_ms = table.reveal_deadline_ms()?.ok_or_else(|| {
            PokerL1Error::Serialization("reveal phase has no deadline projection".into())
        })?;
        if now_ms < deadline_ms {
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::NotDue {
                    kind: DeadlineKind::Reveal,
                    subject,
                    deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        on_reveal_timeout(table, now_ms, events)?;
        let post_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;
        return Ok(AdvanceDeadlineExecution {
            pre_normalization,
            outcome: AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::Reveal,
                subject,
            },
            post_normalization,
        });
    }

    if is_betting_round(table) {
        let subject = table.current_turn();
        if subject == NO_SEAT || usize::from(subject) >= usize::from(table.max_players) {
            return Err(PokerL1Error::Serialization(
                "advance_deadline: betting phase has no canonical current seat".into(),
            ));
        }
        let deadline_ms = table.betting_deadline_ms()?.ok_or_else(|| {
            PokerL1Error::Serialization("betting phase has no deadline projection".into())
        })?;
        if now_ms < deadline_ms {
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::NotDue {
                    kind: DeadlineKind::Betting,
                    subject,
                    deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        let time_bank = table.seats[usize::from(subject)].time_bank_ms();
        if time_bank > 0 {
            let consume = time_bank.min(table.timeout_config.betting_timeout_ms);
            consume_time_bank(table, subject, consume, events)?;
            let extended_deadline_ms = table.extend_betting_deadline(u64::from(consume))?;
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::TimeBankExtended {
                    seat_index: subject,
                    deadline_ms: extended_deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        on_betting_timeout(table, events)?;
        let post_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;
        return Ok(AdvanceDeadlineExecution {
            pre_normalization,
            outcome: AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::Betting,
                subject,
            },
            post_normalization,
        });
    }

    if table.round_state() == ROUND_SHOWDOWN {
        let deadline_ms = table.showdown_deadline_ms().ok_or_else(|| {
            PokerL1Error::Serialization("showdown phase has no deadline projection".into())
        })?;
        if now_ms < deadline_ms {
            return Ok(AdvanceDeadlineExecution {
                pre_normalization,
                outcome: AdvanceDeadlineOutcome::NotDue {
                    kind: DeadlineKind::ShowdownDisplay,
                    subject: NO_SEAT,
                    deadline_ms,
                },
                post_normalization: NormalizationReport::default(),
            });
        }
        settle_hand(table, events)?;
        let post_normalization = normalize_until_blocked_in_place(table, now_ms, events)?;
        return Ok(AdvanceDeadlineExecution {
            pre_normalization,
            outcome: AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::ShowdownDisplay,
                subject: NO_SEAT,
            },
            post_normalization,
        });
    }

    Ok(AdvanceDeadlineExecution {
        pre_normalization,
        outcome: AdvanceDeadlineOutcome::NoDeadline,
        post_normalization: NormalizationReport::default(),
    })
}

/// shuffle 超时处理。
fn on_shuffle_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let seat = table.shuffle_state().derived_current_shuffler();
    let phase = table.shuffle_phase();
    let deadline_ms = table.shuffle_deadline_ms()?.ok_or_else(|| {
        PokerL1Error::Serialization("shuffle timeout requires an active deadline".into())
    })?;
    let started_at = deadline_ms
        .checked_sub(u64::from(table.timeout_config.shuffle_timeout_ms))
        .ok_or_else(|| {
            PokerL1Error::Serialization(
                "shuffle deadline is earlier than its configured timeout".into(),
            )
        })?;
    events::emit_event(
        events,
        TexasPokerEvent::ShuffleTimeout {
            table_id: table.id,
            seat_index: seat,
            phase,
            started_at,
            timeout_ms: u64::from(table.timeout_config.shuffle_timeout_ms),
        },
    );

    kick_player_internal(table, seat, KICK_REASON_TIMEOUT, events)?;

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }
    if table.shuffle_phase() == SHUFFLE_PHASE_NONE {
        return Ok(());
    }

    rebuild_deck_and_shuffle_on_timeout(table, phase, events)?;
    advance_shuffle(table, events)?;
    let _ = now_ms;
    Ok(())
}

/// reveal 超时处理：移除超时玩家，按轮次选择 reset 或 reconstruct。
///
/// # 流程
/// 1. 收集所有未提交 reveal token 的 pending 玩家，逐个踢出（`kick_player_internal`）。
/// 2. 若踢出后无人活跃（active==0）→ refund + reset（异常收场）。
/// 3. 若仅剩 1 人 → `end_without_showdown`（该玩家独得 pot）。
/// 4. 否则按轮次分支：
///    - **preflop**：直接 reset。此时一张牌都未解出（preflop reveal 完成才会
///      post_blinds 进入下注），reset 后桌台回到 WAITING，等待显式 `start_hand`
///      （重新 shuffle + 发牌）。比 reconstruct（重建牌组）简单得多——
///      reconstruct 的语义是"已有牌解出、剩余牌无法继续解密时重建牌组继续"，
///      preflop 没有已解出的牌，无需重建。
///    - **其他轮次**（flop/turn/river/showdown）：已有牌解出，走 `start_reconstruct`
///      重建牌组让剩余玩家补发缺失的牌继续。
fn on_reveal_timeout(
    table: &mut TexasPokerTable,
    now_ms: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let phase = table.reveal_phase();
    let pending_mask = table
        .reveal_assignments()
        .iter()
        .fold(0, |mask, assignment| mask | assignment.pending_mask());
    let pending = seat_mask_to_indices(pending_mask, table.max_players);
    events::emit_event(
        events,
        TexasPokerEvent::RevealTimeout {
            table_id: table.id,
            phase,
            pending_players: pending_mask,
        },
    );

    for &seat in &pending {
        // Raw kick: the reveal-timeout endpoint (refund, sole-survivor award,
        // preflop reset, or reconstruct continuation) is decided once below,
        // after the complete pending union has been kicked.  Running the
        // generic low-player cascade mid-loop would reset and silently clear
        // the pot before the sole survivor can be awarded, and would then
        // kick seats that the reset already returned to waiting.
        kick_player_raw(table, seat, KICK_REASON_TIMEOUT, events)?;
    }

    let active = count_active_players(&table.seats);
    if active == 0 {
        refund_all_bets(table, events)?;
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_TIMEOUT,
                round_state: table.round_state(),
            },
        );
        return Ok(());
    }
    if active == 1 {
        end_without_showdown(table, events)?;
        return Ok(());
    }

    if phase == REVEAL_PHASE_PREFLOP && !matches!(table.hand_phase, HandPhase::Redealing { .. }) {
        // preflop 未解出任何牌，直接 reset 回 WAITING；
        // 后续必须由显式 start_hand 重新洗牌发牌；permissionless advance_deadline 不隐式开局。
        // 换牌窗口例外：preflop 下盲注后才可能换牌，reset 会吞掉已入池资金——
        // 走下方恢复下注轮的路径（持有者可再次 redeal 换取新牌）。
        reset_for_next_hand(table, events)?;
        events::emit_event(
            events,
            TexasPokerEvent::HandReset {
                table_id: table.id,
                reason: RESET_REASON_TIMEOUT,
                round_state: table.round_state(),
            },
        );
        return Ok(());
    }
    if let HandPhase::Redealing {
        street,
        round,
        current_turn,
        ..
    } = table.hand_phase.clone()
    {
        // 换牌窗口超时：踢掉未交份额的座位后，恢复被挂起的下注轮继续牌局。
        // 恢复而非 reconstruct：换牌窗口的死局只影响被换的那张牌（持有者可
        // 再次 redeal），deck 本身未被破坏，reconstruct 重建是过度反应。
        table.enter_betting(street, round, current_turn, now_ms)?;
        return Ok(());
    }

    // flop/turn/river/showdown：已有牌解出，走 reconstruct 重建牌组继续。
    start_reconstruct(table, now_ms, events)?;
    Ok(())
}

/// betting 超时处理：自动 fold。
fn on_betting_timeout(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let seat = table.current_turn();
    apply_fold_internal(table, seat, FOLD_REASON_AUTO_TIMEOUT, events)
}

/// 单人获胜（无摊牌）。
fn end_without_showdown(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // A fold can leave live bets in the current betting round. They are part of
    // the hand's funds and must enter the pot before rake and winner payout;
    // otherwise reset_for_next_hand would silently clear them.
    collect_bets_to_pot(table, events)?;

    let winner = table
        .seats
        .iter()
        .enumerate()
        .find(|(_, s)| s.is_occupied() && !s.is_folded() && !s.is_waiting())
        .map(|(i, _)| i as u8);

    if let Some(winner_seat) = winner {
        // 无竞争 pot（全员 fold，唯一幸存者直接获胜）不抽水，
        // 与 showdown 路径对 uncontested 层的处理保持一致
        // （SettlementPlan::validate: uncontested pot must not be raked）。
        let pot = table.pot;
        let post_stack = table.seats[winner_seat as usize]
            .stack()
            .checked_add(pot)
            .ok_or_else(|| {
                PokerL1Error::Serialization(
                    "end_without_showdown: winner stack += pot overflow".into(),
                )
            })?;
        table.seats[winner_seat as usize].set_stack(post_stack)?;
        table.pot = 0;

        events::emit_event(
            events,
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id: table.id,
                winner_seat,
                winner_player: table.seats[winner_seat as usize].player(),
                pot,
            },
        );
    }

    reset_for_next_hand(table, events)?;
    Ok(())
}

/// 摊牌结算。
///
/// 镜像 `table.move::settle_hand`（line 2440-2510）。
fn settle_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.round_state() != ROUND_SHOWDOWN {
        return Ok(());
    }
    if table.reveal_token_state().is_some() {
        return Ok(());
    }

    // Derive the complete plan before touching balances. Apply and reset on a scratch table so a
    // corrupt addon/leave ledger cannot leave a partially paid showdown when reset fails.
    let plan = if table.run_it_twice_state.is_active() {
        let RunItTwiceState::Twice { start, .. } = &table.run_it_twice_state else {
            unreachable!("is_active only matches the twice variant")
        };
        let second_board = table
            .run_it_twice_state
            .full_second_board(&table.community_cards)?;
        settlement::derive_settlement_plan_for_boards(
            table,
            &settlement::SettlementBoards::twice(
                *start,
                table.community_cards.to_vec(),
                second_board,
            ),
        )?
    } else {
        settlement::derive_settlement_plan(table)?
    };
    let mut next_table = table.clone();
    let mut staged_events = Vec::new();
    apply_settlement_plan(&mut next_table, &plan, &mut staged_events)?;
    reset_for_next_hand(&mut next_table, &mut staged_events)?;
    *table = next_table;
    events.extend(staged_events);
    Ok(())
}

/// Atomically applicable projection of a canonical [`SettlementPlan`].
///
/// This function never evaluates cards or reconstructs side pots. It only validates the plan's
/// internal conservation equations, preflights every balance update, and applies the explicit
/// per-seat awards. Callers must derive the plan from the same authenticated pre-state.
fn apply_settlement_plan(
    table: &mut TexasPokerTable,
    plan: &SettlementPlan,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    plan.validate(usize::from(table.max_players))?;
    if table.pot != plan.gross_pot {
        return Err(PokerL1Error::Serialization(format!(
            "settlement: plan gross pot {} does not match table pot {}",
            plan.gross_pot, table.pot
        )));
    }
    let post_chip_pool = table
        .chip_pool
        .checked_sub(plan.rake)
        .ok_or_else(|| PokerL1Error::Serialization("settlement: rake exceeds TableVault".into()))?;
    let mut post_stacks = Vec::with_capacity(usize::from(table.max_players));
    for (seat_index, seat) in table.seats.iter().enumerate() {
        post_stacks.push(
            seat.stack()
                .checked_add(plan.awards[seat_index])
                .ok_or_else(|| {
                    PokerL1Error::Serialization(format!(
                        "settlement: seat {seat_index} stack award overflow"
                    ))
                })?,
        );
    }
    let plan_digest = plan.digest()?;

    table.chip_pool = post_chip_pool;
    for (seat, post_stack) in table.seats.iter_mut().zip(post_stacks) {
        seat.set_stack(post_stack)?;
    }
    table.pot = 0;

    events::emit_event(
        events,
        TexasPokerEvent::SettlementPlanCommitted {
            table_id: table.id,
            plan_digest,
            runout_count: plan.schedule.count(),
            gross_pot: plan.gross_pot,
            rake: plan.rake,
            total_awards: plan.total_awards,
        },
    );
    if plan.rake > 0 {
        events::emit_event(
            events,
            TexasPokerEvent::RakeCollected {
                table_id: table.id,
                pot_before: plan.gross_pot,
                rake_amount: plan.rake,
                pot_after: plan.total_awards,
                rake_mode: table.rake_mode,
            },
        );
    }
    for pot in plan.active_pots() {
        let pot_type = if pot.pot_index == 0 {
            POT_TYPE_MAIN
        } else {
            POT_TYPE_SIDE
        };
        for runout in pot.runouts.iter().take(usize::from(plan.schedule.count())) {
            for seat_index in 0..usize::from(table.max_players) {
                let amount = runout.awards[seat_index];
                if amount == 0 {
                    continue;
                }
                events::emit_event(
                    events,
                    TexasPokerEvent::WinnerAwarded {
                        table_id: table.id,
                        seat_index: seat_index as u8,
                        player: table.seats[seat_index].player(),
                        amount,
                        pot_type,
                        hand_rank: runout.ranks[seat_index].map(|rank| rank.category),
                    },
                );
            }
        }
    }
    events::emit_event(
        events,
        TexasPokerEvent::HandSettled {
            table_id: table.id,
            pot: plan.gross_pot,
            winners: plan.winner_mask,
        },
    );
    Ok(())
}

/// 退还所有下注（异常路径）。
fn refund_all_bets(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.is_occupied() && !s.is_folded() && !s.has_left_hand() && s.total_bet() > 0 {
            let amount = s.total_bet();
            let post_stack = s.stack().checked_add(amount).ok_or_else(|| {
                PokerL1Error::Serialization("refund_all_bets: stack += total_bet overflow".into())
            })?;
            s.set_stack(post_stack)?;
            events::emit_event(
                events,
                TexasPokerEvent::PlayerRefund {
                    table_id: table.id,
                    seat_index: i as u8,
                    player: s.player(),
                    amount,
                    refund_type: REFUND_TYPE_BET_ONLY,
                },
            );
        }
        s.set_bet(0)?;
        s.set_total_bet(0)?;
    }
    table.pot = 0;
    Ok(())
}

/// 重置进入下一局。
///
/// 镜像 `table.move::reset_for_next_hand`（line 3550-3621）。
///
/// 暴露为 pub 供 dispatch 层 `reset_for_next_hand` selector 直接调用，
/// 用于管理员/测试场景下显式重置桌台到 WAITING 状态（正常对局流程中
/// 由 `settle_hand` / `end_without_showdown` / 超时路径内部调用）。
pub fn reset_for_next_hand(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // Preflight the complete addon merge before changing any seat or emitting events. This keeps
    // a corrupt pool/overflow failure atomic instead of crediting an earlier seat partially.
    let mut total_pending_addon = 0u64;
    let mut to_remove_leave: Vec<u8> = vec![];
    let mut total_leave_refund = 0u64;
    for (i, s) in table.seats.iter().enumerate() {
        if s.pending_addon() > 0 && s.is_occupied() {
            s.stack().checked_add(s.pending_addon()).ok_or_else(|| {
                PokerL1Error::Serialization(
                    "reset_for_next_hand: stack += pending_addon overflow".into(),
                )
            })?;
            total_pending_addon = total_pending_addon
                .checked_add(s.pending_addon())
                .ok_or_else(|| {
                    PokerL1Error::Serialization(
                        "reset_for_next_hand: total pending addon overflow".into(),
                    )
                })?;
        }
        if s.is_occupied() && table.seat_wants_leave(i as u8) {
            let refund = s.stack().checked_add(s.pending_addon()).ok_or_else(|| {
                PokerL1Error::Serialization("reset_for_next_hand: leave refund overflow".into())
            })?;
            total_leave_refund = total_leave_refund.checked_add(refund).ok_or_else(|| {
                PokerL1Error::Serialization(
                    "reset_for_next_hand: total leave refund overflow".into(),
                )
            })?;
            to_remove_leave.push(i as u8);
        }
    }
    let post_leave_chip_pool =
        table
            .chip_pool
            .checked_sub(total_leave_refund)
            .ok_or_else(|| {
                PokerL1Error::Serialization("reset_for_next_hand: leave chip_pool underflow".into())
            })?;

    // 第一阶段：合并 pending_addon 到 stack（在清理 stack==0 之前）
    //
    // 关键不变量：addon 在下一手生效，合并发生在任何清理之前，
    // 确保 addon 后玩家不会被误踢（即使上一手结束时 stack==0）。
    for (i, s) in table.seats.iter_mut().enumerate() {
        if s.pending_addon() > 0 && s.is_occupied() {
            let player = s.player();
            let amount = s.pending_addon();
            let post_stack = s.stack().checked_add(amount).ok_or_else(|| {
                PokerL1Error::Serialization(
                    "reset_for_next_hand: stack += pending_addon overflow".into(),
                )
            })?;
            s.set_stack(post_stack)?;
            s.set_pending_addon(0)?;
            events::emit_event(
                events,
                TexasPokerEvent::AddonCredited {
                    table_id: table.id,
                    seat_index: i as u8,
                    player,
                    amount,
                    stack_after: s.stack(),
                },
            );
        }
    }
    // P2-11 修复：每手开始时补充 Time Bank（按 TIME_BANK_REFILL_PER_HAND_MS，
    // 上限 DEFAULT_TIME_BANK_MS）。此前 constants 定义了 refill 常量但 reset
    // 未实现补充逻辑，导致 time_bank 仅会单调下降，无法跨手恢复。
    let refill = super::constants::TIME_BANK_REFILL_PER_HAND_MS;
    let cap = super::constants::DEFAULT_TIME_BANK_MS;
    for s in &mut table.seats {
        if s.is_occupied() {
            s.set_time_bank_ms(s.time_bank_ms().saturating_add(refill).min(cap));
        }
    }

    // 第二阶段：重置 seat 字段；新牌组从所有仍占座的有效公钥重建 contributor lineage。
    // `fold_with_proof` 只剥离当前牌组的加密层，玩家与资金仍留在桌上；若这里只恢复
    // waiting seat，该玩家下一手没有任何 occupied-seat 入口重新加入 aggregate key。
    table.acted_mask = 0;
    table.deck_state.contributor_mask = 0;
    for (seat_index, s) in table.seats.iter_mut().enumerate() {
        if s.pk().is_some_and(|pk| !g1_is_identity(&pk.0)) {
            table.deck_state.contributor_mask |= 1u16 << seat_index;
        }
        s.prepare_next_hand();
    }
    // 第二阶段（b）：强制踢出 `want_leave=true` 的 occupied seat。
    //
    // 这是 `set_leave_after_hand`（sit out next hand）的执行点：玩家在
    // 对局中预约离场后，下一手 reset 时强制踢出并退款。资金账对齐
    // `kick_player_internal` / `dispatch_leave_table`：
    // - 退 stack + pending_addon（refund_amt）
    // - 同步扣 chip_pool；pending addon 只由 seat ledger 派生
    // - 从 aggregated_pk 移除该 pk（若非 identity）
    // - 清空座位 + 发 PlayerRefund + PlayerLeft 事件
    //
    // 时机说明：必须在第二阶段（重置 seat 字段）之后、第三阶段（清理 stack==0）
    // 之前。理由：第二阶段已把 pending_addon 合并到 stack（退款金额正确），
    // 第三阶段的 stack==0 判定不会误清已退款的座位。
    for &i in &to_remove_leave {
        let stack_refund = table.seats[i as usize].stack();
        let pending_refund = table.seats[i as usize].pending_addon();
        let refund = stack_refund + pending_refund;
        let player = table.seats[i as usize].player();
        if refund > 0 {
            table.seats[i as usize].set_stack(0)?;
            table.seats[i as usize].set_pending_addon(0)?;
            events::emit_event(
                events,
                TexasPokerEvent::PlayerRefund {
                    table_id: table.id,
                    seat_index: i,
                    player,
                    amount: refund,
                    refund_type: REFUND_TYPE_STACK_ONLY,
                },
            );
        }
        seat_mask_remove(&mut table.deck_state.contributor_mask, i);
        table.seats[i as usize].vacate();
        table.set_seat_wants_leave(i, false);
        events::emit_event(
            events,
            TexasPokerEvent::PlayerLeft {
                table_id: table.id,
                seat_index: i,
                player,
            },
        );
    }
    table.chip_pool = post_leave_chip_pool;

    // 第三阶段：清理 stack==0 的 occupied seat
    let mut to_remove: Vec<u8> = vec![];
    for (i, s) in table.seats.iter().enumerate() {
        if s.has_left_hand() || (s.is_occupied() && s.stack() == 0) {
            to_remove.push(i as u8);
        }
    }
    for &i in &to_remove {
        let player = table.seats[i as usize].player();
        seat_mask_remove(&mut table.deck_state.contributor_mask, i);
        table.seats[i as usize].vacate();
        table.set_seat_wants_leave(i, false);
        events::emit_event(
            events,
            TexasPokerEvent::PlayerLeft {
                table_id: table.id,
                seat_index: i,
                player,
            },
        );
    }
    if count_active_occupied(&table.seats) == 0 {
        table.deck_state.contributor_mask = 0;
    }

    table.pot = 0;
    table.community_cards.clear();
    table.acted_mask = 0;
    table.leave_after_hand_mask = 0;
    table.deck_state.encrypted.clear();
    table.deck_state.cards_dealt = 0;
    table.deck_state.owner_readable_hole_cards.clear();
    table.run_it_twice_state = RunItTwiceState::default();
    table.enter_waiting();

    set_initial_encrypted_deck(table)?;
    Ok(())
}

/// 踢人内部实现（被 dispatch::kick_player / on_*_timeout 共用）。
///
/// 镜像 `table.move::kick_player_internal`（line 3625-3702）。
/// 暴露为 pub 供 dispatch.rs 直接调用。
pub fn kick_player_internal(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: super::events::KickCause,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // A kick can cascade into end_without_showdown/settlement and finally reset_for_next_hand.
    // Execute the whole cascade on a candidate table so a late reset failure cannot leave a
    // partially refunded seat or a partially collected pot in the caller's state.
    let mut candidate = table.clone();
    let mut candidate_events = Vec::new();
    kick_player_internal_in_place(&mut candidate, seat_index, reason, &mut candidate_events)?;
    *table = candidate;
    events.extend(candidate_events);
    Ok(())
}

/// Atomic raw kick without the generic post-kick cascades.
///
/// Mirrors the candidate-table atomicity of [`kick_player_internal`] so a late
/// failure cannot leave a partially refunded seat in the caller's state.
fn kick_player_raw(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: super::events::KickCause,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let mut candidate = table.clone();
    let mut candidate_events = Vec::new();
    kick_seat_in_place_raw(&mut candidate, seat_index, reason, &mut candidate_events)?;
    *table = candidate;
    events.extend(candidate_events);
    Ok(())
}

fn kick_player_internal_in_place(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: super::events::KickCause,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let was_current_shuffler = table.shuffle_state().derived_current_shuffler() == seat_index;
    let was_current_turn = table.current_turn() == seat_index && is_betting_round(table);
    kick_seat_in_place_raw(table, seat_index, reason, events)?;
    if was_current_shuffler && table.shuffle_phase() != SHUFFLE_PHASE_NONE {
        let mut tmp_events = Vec::new();
        advance_shuffle(table, &mut tmp_events)?;
        events.extend(tmp_events);
    }
    if was_current_turn && is_betting_round(table) {
        let active = count_active_players(&table.seats);
        if active <= 1 {
            end_without_showdown(table, events)?;
            // end_without_showdown already performs the complete award + reset cascade. Do not
            // fall through to the generic low-player reset below, which would reset and bump the
            // version a second time in the same kick dispatch.
            return Ok(());
        } else {
            advance_turn(table, events)?;
        }
    }

    let active = count_active_players(&table.seats);
    if active < MIN_PLAYERS_TO_START {
        if active == 1 && is_betting_round(table) {
            // Kicking a non-current heads-up player must award the complete pot to the survivor;
            // a bare reset here would silently clear the kicked bet, all remaining live bets and
            // the pre-existing pot without a winner event.
            end_without_showdown(table, events)?;
        } else {
            reset_for_next_hand(table, events)?;
        }
    }
    Ok(())
}

/// Kick one seat without running the generic shuffle/turn/low-player cascades.
///
/// `on_reveal_timeout` uses this so the reveal-timeout endpoint (refund/award/
/// preflop reset/reconstruct) is decided once, after the complete pending
/// union has been kicked.  Letting the low-player cascade run mid-loop would
/// reset and silently clear the pot before the sole survivor can be awarded,
/// and would then kick seats that the reset already returned to waiting.
fn kick_seat_in_place_raw(
    table: &mut TexasPokerTable,
    seat_index: u8,
    reason: super::events::KickCause,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    // P0-1 修复：seat_index 越界校验（原先直接索引会 panic）。
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "kick_player: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if !table.seats[seat_index as usize].is_occupied() {
        // 座位空闲视为无操作成功（幂等），但区分于越界错误。
        return Ok(());
    }
    let seat = &table.seats[seat_index as usize];
    let stack_refund = seat.stack();
    let pending_refund = seat.pending_addon();
    let refund_amt = stack_refund
        .checked_add(pending_refund)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: refund overflow".into()))?;
    let player = seat.player();

    // Preflight every fallible monetary transition before mutating the seat, pot or aggregate key.
    let post_pot = table
        .pot
        .checked_add(seat.bet())
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: pot overflow".into()))?;
    let post_chip_pool = table
        .chip_pool
        .checked_sub(refund_amt)
        .ok_or_else(|| PokerL1Error::Serialization("kick_player: chip_pool underflow".into()))?;
    // P1-2 语义说明：被踢玩家的 bet 立即并入 pot（区别于 fold/auto_fold/force_fold，
    // 后者保留 seat.bet()，等下注轮结束由 collect_bets_to_pot 统一收集）。
    // 这是 kick 的特殊路径：被踢玩家立即离开，其本轮已下注金额不参与后续轮次，
    // 故提前单独收集。资金账安全：collect_bets_to_pot 后续不会再收（seat.bet() 已为 0）；
    // side_pot 分层依据 total_bet（不受 bet 清零影响）。
    table.pot = post_pot;
    table.seats[seat_index as usize].depart_this_hand()?;
    table.set_seat_acted_this_round(seat_index, false);
    table.set_seat_wants_leave(seat_index, false);

    seat_mask_remove(&mut table.deck_state.contributor_mask, seat_index);
    if refund_amt > 0 {
        // chip_pool 是完整 TableVault 锁仓；pending addon 只保存在 seat ledger。
        table.chip_pool = post_chip_pool;
        events::emit_event(
            events,
            TexasPokerEvent::PlayerRefund {
                table_id: table.id,
                seat_index,
                player,
                amount: refund_amt,
                refund_type: REFUND_TYPE_STACK_ONLY,
            },
        );
    }

    table.remove_seat_from_active_phase(seat_index)?;

    events::emit_event(
        events,
        TexasPokerEvent::PlayerKicked {
            table_id: table.id,
            seat_index,
            player,
            reason,
        },
    );
    Ok(())
}

// ========== Addon / Rebuy ==========

/// `addon` — 玩家追加筹码，**下一手生效**。
///
/// 业务语义：玩家可在任意时刻（包括牌局进行中）追加筹码，但追加金额
/// **不影响当前手牌**，只累加 `seat.pending_addon()`，在下一手
/// [`reset_for_next_hand`] 第一阶段合并到 `seat.stack()`。
///
/// 这样设计的关键不变量：
/// - 不破坏当前 `side_pot` 分层（all-in 后的钱不能凭空增加）
/// - 不允许玩家利用 addon 在 all-in 后"加码"破坏结算
/// - addon 只影响 `stack`，不动 `bet/total_bet`
///
/// # 参数
/// - `table`: 桌台状态
/// - `seat_index`: 目标座位
/// - `amount`: 追加金额（必须 > 0）
/// - `events`: 事件日志
///
/// # Errors
///
/// - `seat_index` 越界
/// - 座位未被占用
/// - `amount == 0`
pub fn apply_addon(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    apply_fund_seat(table, seat_index, amount, FundTiming::NextHand, events)
}

/// Apply the canonical funding transition shared by addon and rebuy.
fn apply_fund_seat(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    timing: FundTiming,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let label = match timing {
        FundTiming::NextHand => "addon",
        FundTiming::Immediate => "rebuy",
    };
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    if amount == 0 {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: amount must > 0"
        )));
    }

    if !table.seats[seat_index as usize].is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: seat {seat_index} not occupied"
        )));
    }

    let total_chips = table
        .chip_pool
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization(format!("{label}: total chips overflow")))?;
    if total_chips > super::constants::MAX_TOTAL_BET {
        return Err(PokerL1Error::Serialization(format!(
            "{label}: total chips {total_chips} exceeds MAX_TOTAL_BET {}",
            super::constants::MAX_TOTAL_BET
        )));
    }

    let (player, pending_after, stack_after) = {
        let seat = &mut table.seats[seat_index as usize];
        match timing {
            FundTiming::NextHand => {
                let pending_after = seat.pending_addon().checked_add(amount).ok_or_else(|| {
                    PokerL1Error::Serialization("addon: pending_addon overflow".into())
                })?;
                let player = seat.player();
                seat.set_pending_addon(pending_after)?;
                (player, Some(pending_after), None)
            }
            FundTiming::Immediate => {
                let stack_after = seat
                    .stack()
                    .checked_add(amount)
                    .ok_or_else(|| PokerL1Error::Serialization("rebuy: stack overflow".into()))?;
                let player = seat.player();
                seat.set_stack(stack_after)?;
                (player, None, Some(stack_after))
            }
        }
    };
    table.chip_pool = total_chips;

    match timing {
        FundTiming::NextHand => events::emit_event(
            events,
            TexasPokerEvent::AddonRequested {
                table_id: table.id,
                seat_index,
                player,
                amount,
                pending_after: pending_after.expect("next-hand funding has pending balance"),
            },
        ),
        FundTiming::Immediate => events::emit_event(
            events,
            TexasPokerEvent::RebuyProcessed {
                table_id: table.id,
                seat_index,
                player,
                amount,
                stack_after: stack_after.expect("immediate funding has stack balance"),
            },
        ),
    }
    Ok(())
}

/// `rebuy` — 玩家重购，**立即生效**（仅 MTT 早期或特殊规则用）。
///
/// 与 `addon` 的关键区别：
/// - `addon` 下一手生效，只改 `pending_addon`，不影响当前 pot
/// - `rebuy` 立即生效，直接改 `stack`，可用于玩家筹码不足时继续游戏
///
/// 业务约束（调用方负责）：
/// - MTT 中通常要求 `seat.stack() < big_blind` 才允许 rebuy
/// - 现金桌通常不使用 rebuy，而用 addon
/// - 通常在 rebuy 期内（盲注升阶到某级别前）才允许
///
/// # 参数
/// - `table`: 桌台状态
/// - `seat_index`: 目标座位
/// - `amount`: 重购金额（必须 > 0）
/// - `events`: 事件日志
///
/// # Errors
///
/// - `seat_index` 越界
/// - 座位未被占用
/// - `amount == 0`
pub fn apply_rebuy(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    apply_fund_seat(table, seat_index, amount, FundTiming::Immediate, events)
}

// ========== Request Leave After Hand（sit out next hand） ==========

/// Set whether an occupied seat must leave after the current hand.
///
/// This is the canonical idempotent business transition intended for the tagged Seat command.
/// Repeating the same target bit is a no-op: it emits no duplicate event and does not bump the
/// table version.
///
/// # Errors
///
/// - `seat_index` is outside the configured table capacity
/// - the selected seat is vacant
pub fn apply_set_leave_after_hand(
    table: &mut TexasPokerTable,
    seat_index: u8,
    want_leave: bool,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<bool> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "set_leave_after_hand: seat_index {seat_index} out of range (max_players={})",
            table.max_players
        )));
    }
    let seat = &table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "set_leave_after_hand: seat {seat_index} not occupied"
        )));
    }
    if table.seat_wants_leave(seat_index) == want_leave {
        return Ok(false);
    }

    let player = seat.player();
    table.set_seat_wants_leave(seat_index, want_leave);
    events::emit_event(
        events,
        TexasPokerEvent::LeaveRequested {
            table_id: table.id,
            seat_index,
            player,
            want_leave,
        },
    );
    Ok(true)
}

// ========== Bet / Time Bank / Ante / Rake / Run It Twice ==========

/// `bet` — 玩家主动下注（postflop 第一个下注者）。
///
/// 与 `raise` 的区别：
/// - `raise` 用于已有下注时加注（preflop BB 已存在，或有人 bet 后）
/// - `bet` 用于 postflop 当前 pot 无下注时主动开注
///
/// 实现上 `bet` 等价于 `raise(total_bet = amount)`（因为 round 开注后 min_raise = amount）。
/// 分离为独立方法仅为语义清晰。
pub fn apply_bet(
    table: &mut TexasPokerTable,
    seat_index: u8,
    amount: u64,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !is_betting_round(table) {
        return Err(PokerL1Error::Serialization(
            "bet: not in betting round".into(),
        ));
    }
    if !is_player_turn(table, seat_index) {
        return Err(PokerL1Error::Serialization("bet: not player's turn".into()));
    }
    if amount == 0 {
        return Err(PokerL1Error::Serialization("bet: amount must > 0".into()));
    }
    // P2-5 修复：preflop 已有强制下注（盲注构成 current_bet），不应使用 bet
    // （开注动作应叫 raise）。bet 仅用于 postflop 当前轮无下注时主动开注。
    if table.round_state() == ROUND_PREFLOP {
        return Err(PokerL1Error::Serialization(
            "bet: not allowed in preflop, use raise instead".into(),
        ));
    }
    // 验证当前轮无已有下注（bet 只能在 current_bet == seat.bet() 时使用）
    let round = table.betting_round().expect("checked above");
    let current_bet = round.current_bet;
    let seat_bet = table.seats[seat_index as usize].bet();
    if current_bet > seat_bet {
        return Err(PokerL1Error::Serialization(format!(
            "bet: current_bet {current_bet} > seat_bet {seat_bet}, 应使用 call/raise"
        )));
    }

    // 复用 raise 逻辑（total_bet = seat_bet + amount）
    let total_bet = seat_bet
        .checked_add(amount)
        .ok_or_else(|| PokerL1Error::Serialization("bet: total_bet overflow".into()))?;
    apply_raise(table, seat_index, total_bet, events)?;
    // raise 已 emit PlayerRaised，额外 emit PlayerBet 以保留语义
    events::emit_event(
        events,
        TexasPokerEvent::PlayerBet {
            table_id: table.id,
            seat_index,
            amount,
            round_state: table.round_state(),
        },
    );
    Ok(())
}

/// `consume_time_bank` — 玩家 Time Bank 被消耗（超时续命）。
///
/// 通常由 `advance_deadline` 在玩家 betting 超时且 time_bank_ms > 0 时自动调用。
/// 消耗指定毫秒数，若剩余不足以覆盖则返回错误（调用方应改用 auto_fold）。
pub fn consume_time_bank(
    table: &mut TexasPokerTable,
    seat_index: u8,
    consumed_ms: u32,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if seat_index >= table.max_players {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: seat_index {seat_index} out of range"
        )));
    }
    let seat = &mut table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: seat {seat_index} not occupied"
        )));
    }
    if seat.time_bank_ms() < consumed_ms {
        return Err(PokerL1Error::Serialization(format!(
            "consume_time_bank: time_bank_ms {} < consumed_ms {}",
            seat.time_bank_ms(),
            consumed_ms
        )));
    }
    let remaining_ms = seat.time_bank_ms() - consumed_ms;
    seat.set_time_bank_ms(remaining_ms);
    events::emit_event(
        events,
        TexasPokerEvent::TimeBankConsumed {
            table_id: table.id,
            seat_index,
            consumed_ms: u64::from(consumed_ms),
            remaining_ms: u64::from(remaining_ms),
        },
    );
    Ok(())
}

/// `collect_ante` — 在 `start_hand` 中按 `ante_mode` 投 ante。
///
/// 此函数由 `start_hand` 内部调用，不作为独立 dispatch method。
/// 投注规则：
/// - `ANTE_MODE_NORMAL`：每个活跃玩家投 `ante_amount`
/// - `ANTE_MODE_BBA`：仅大盲位投 `ante_amount`
/// - `ANTE_MODE_NONE`：不做任何操作
///
/// 投注的 ante 直接加入 `table.pot`；本手总 ante 由逐 seat debit / pot delta 派生。
pub fn collect_ante(
    table: &mut TexasPokerTable,
    bb_seat: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.ante_mode == super::constants::ANTE_MODE_NONE || table.ante_amount == 0 {
        return Ok(());
    }
    let amount = table.ante_amount;
    let mode = table.ante_mode;

    let seats_to_ante: Vec<u8> = if mode == super::constants::ANTE_MODE_BBA {
        vec![bb_seat]
    } else {
        // NORMAL: 所有活跃玩家
        table
            .seats
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_occupied() && !s.is_waiting())
            .map(|(i, _)| i as u8)
            .collect()
    };

    let antes = seats_to_ante
        .iter()
        .map(|seat_idx| {
            (
                *seat_idx,
                amount.min(table.seats[*seat_idx as usize].stack()),
            )
        })
        .collect::<Vec<_>>();
    let total_ante = antes.iter().try_fold(0u64, |total, (_, actual)| {
        total
            .checked_add(*actual)
            .ok_or_else(|| PokerL1Error::Serialization("collect_ante: total overflow".into()))
    })?;
    table
        .pot
        .checked_add(total_ante)
        .ok_or_else(|| PokerL1Error::Serialization("collect_ante: pot overflow".into()))?;
    for (seat_idx, actual) in &antes {
        table.seats[*seat_idx as usize]
            .total_bet()
            .checked_add(*actual)
            .ok_or_else(|| {
                PokerL1Error::Serialization("collect_ante: total_bet overflow".into())
            })?;
    }

    table.pot += total_ante;
    for (seat_idx, actual) in antes {
        let seat = table.seats[seat_idx as usize].playing_mut()?;
        seat.occupied.stack -= actual;
        // An ante is dead money: it contributes to side-pot eligibility through total_bet and is
        // held directly by the pot, but it must not reduce the price of a call via seat.bet().
        seat.total_bet += actual;
        if seat.occupied.stack == 0 {
            seat.status = PlayingSeatStatus::AllIn;
        }
        events::emit_event(
            events,
            TexasPokerEvent::AntePosted {
                table_id: table.id,
                seat_index: seat_idx,
                amount: actual,
                ante_mode: mode,
            },
        );
    }
    Ok(())
}

/// Activate Run It Twice once no further contested betting is possible.
fn maybe_trigger_run_it_twice(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.rit_mode == RIT_MODE_DISABLED
        || table.run_it_twice_state.is_active()
        || table.community_cards.len() >= 5
        || !no_further_betting_possible(table)
    {
        return Ok(());
    }
    trigger_run_it_twice(table, events)
}

/// Activate the two-runout board schedule for the current all-in hand.
///
/// Already exposed community cards become a shared prefix. Every later community reveal creates
/// one assignment per runout, and settlement splits each post-rake pot before independently
/// selecting the winner of each board.
pub fn trigger_run_it_twice(
    table: &mut TexasPokerTable,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if table.rit_mode == super::constants::RIT_MODE_DISABLED {
        return Ok(());
    }
    if table.rit_mode != super::constants::RIT_MODE_TWICE {
        return Err(PokerL1Error::Serialization(format!(
            "trigger_run_it_twice: unsupported rit_mode {}",
            table.rit_mode
        )));
    }
    if table.run_it_twice_state.is_active() {
        return Ok(());
    }
    if !matches!(
        table.round_state(),
        ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER
    ) || !no_further_betting_possible(table)
    {
        return Err(PokerL1Error::Serialization(
            "trigger_run_it_twice requires an all-in betting state with no further contested action"
                .into(),
        ));
    }
    let shared_board_len = u8::try_from(table.community_cards.len()).map_err(|_| {
        PokerL1Error::Serialization("run it twice shared board length exceeds u8".into())
    })?;
    if shared_board_len >= 5 {
        return Err(PokerL1Error::Serialization(
            "trigger_run_it_twice requires at least one undealt community card".into(),
        ));
    }
    exposed_card_ids(table)?;
    table.run_it_twice_state = RunItTwiceState::Twice {
        start: RitStartStreet::from_shared_board_len(shared_board_len)?,
        second_board_suffix: Default::default(),
    };
    let remaining = 5 - shared_board_len;
    events::emit_event(
        events,
        TexasPokerEvent::RunItTwiceTriggered {
            table_id: table.id,
            board1_cards: remaining,
            board2_cards: remaining,
        },
    );
    Ok(())
}

// ========== 桌台生命周期转移（2026-09-09 自 runtime/dispatch 下沉）==========
//
// 这三个方法是"混合区"清理的最后一批：此前 create_table / join_table /
// leave_table 的完整状态转移内联在 runtime dispatch 包装里，核心状态机
// 存在缺口（合约移植 / 形式化 / 属性测试看不到它们）。下沉后 19 个 method
// 的全部转移语义都在本模块；runtime 包装只剩 decode + caller 认证 + 委托。

/// `create_table` 语义：参数校验 + 以调用方为 creator 重建全新桌台。
///
/// 权限（caller 身份）由 runtime dispatch 层保证；本函数只管状态语义。
///
/// `rit_mode` 是 Run It Twice 桌面策略：仅接受 [`RIT_MODE_DISABLED`] /
/// [`RIT_MODE_TWICE`]，其余值 fail-closed 拒绝（校验先于覆写，失败时桌台
/// 原样保留）。不开启是唯一缺省——调用方必须显式传 [`RIT_MODE_TWICE`] 才会
/// 在 contested all-in 时自动双跑（`MAX_RUNOUTS = 2`，协议不支持更多 runout）。
pub fn apply_create_table(
    table: &mut TexasPokerTable,
    creator: Address,
    max_players: u8,
    small_blind: u64,
    big_blind: u64,
    rit_mode: u8,
) -> PokerL1Result<()> {
    if !(2..=9).contains(&max_players) {
        return Err(PokerL1Error::Serialization(format!(
            "max_players {max_players} out of range [2, 9]"
        )));
    }
    if big_blind == 0 {
        return Err(PokerL1Error::Serialization("big_blind must > 0".into()));
    }
    if small_blind > big_blind {
        return Err(PokerL1Error::Serialization(
            "small_blind must <= big_blind".into(),
        ));
    }
    if !matches!(rit_mode, RIT_MODE_DISABLED | RIT_MODE_TWICE) {
        return Err(PokerL1Error::Serialization(format!(
            "create_table: rit_mode {rit_mode} is not canonical"
        )));
    }
    let id = table.id;
    // P0-2：记录 creator 为调用方，作为后续管理类方法的权限基准。
    *table = TexasPokerTable::new(id, creator, max_players, small_blind, big_blind);
    table.rules.rit_mode = rit_mode;
    Ok(())
}

/// `join_table` 语义：WAITING 校验 → pk 三重校验（非恒等元 / 所有权证明 /
/// 未注册）→ 会话交易公钥登记校验 → chip_pool 上限 → 占首个
/// 空座（Waiting，等大盲）→ 资金入池 → deck contributor 登记 → PlayerJoined
/// 事件。
///
/// 买入下限（buy_in >= big_blind）在游戏层买入入座接受点校验（SIT_DOWN_V2），
/// VM 层不设：镜像每手开局对本手参与者重放 join_table，其中含续座玩家——
/// split-pot 等场景留下的不足大盲筹码允许继续参与（真实规则），不得在此拦截。
///
/// `caller == player` 的认证检查在 runtime dispatch 层；`tx_pk` 与链上 vault
/// 登记（`set_session_tx_pk[_for]`）的一致性由游戏服务端在 join 接受点核验
/// （VM 无法查询链上账户状态）——入座后它就是本座 VM 层交易签名的唯一
/// 验证锚（P1-2 会话委托，2026-09-10）。
pub fn apply_join_table(
    table: &mut TexasPokerTable,
    player: Address,
    buy_in: u64,
    pk: G1Projective,
    tx_pk: crate::signature::TaggedPubkey,
    pk_ownership_proof: &[u8],
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !can_join_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot join_table".into(),
        ));
    }
    // ECPoint → G1Projective（is_pk_registered / Seat.pk 使用裸 G1Projective）
    if utils::g1_is_identity(&pk) {
        return Err(PokerL1Error::Serialization(
            "join_table public key cannot be identity".into(),
        ));
    }
    if !utils::verify_pk_ownership(&pk, pk_ownership_proof) {
        return Err(PokerL1Error::Serialization(
            "join_table PK ownership proof verification failed".into(),
        ));
    }
    if is_pk_registered(&table.seats, &pk) {
        return Err(PokerL1Error::Serialization(
            "pk already registered at this table".into(),
        ));
    }
    let post_chip_pool = table
        .chip_pool
        .checked_add(buy_in)
        .ok_or_else(|| PokerL1Error::Serialization("chip_pool overflow on join_table".into()))?;
    if post_chip_pool > MAX_TOTAL_BET {
        return Err(PokerL1Error::Serialization(format!(
            "join_table chip_pool {post_chip_pool} exceeds MAX_TOTAL_BET {MAX_TOTAL_BET}"
        )));
    }
    let seat_idx = table
        .find_empty_seat()
        .ok_or_else(|| PokerL1Error::Serialization("no empty seat available".into()))?;
    table.set_seat_acted_this_round(seat_idx, false);
    table.set_seat_wants_leave(seat_idx, false);
    table.seats[seat_idx as usize] =
        Seat::occupied(player, buy_in, ECPoint(pk), tx_pk, SeatStatus::Waiting)?;
    // waiting-for-BB：先入座等待，盲注位（大盲）到达时才参与发牌

    // P0 修复：与 apply_join_shuffle 保持一致的资金记账——buy_in 必须进入
    // chip_pool，否则离座退款时 chip_pool 会出现负差额（资金凭空多退）。
    table.chip_pool = post_chip_pool;
    table.add_deck_contributor(seat_idx)?;

    // 座位已设置完毕后再统计活跃人数（与 apply_join_shuffle 一致，不再 +1）。
    let active_count_after = count_active_occupied(&table.seats) as u64;
    events.push(TexasPokerEvent::PlayerJoined {
        table_id: table.id,
        seat_index: seat_idx,
        player,
        buy_in,
        is_waiting: true,
        active_count_after,
    });
    Ok(())
}

/// `leave_table` 语义：WAITING 校验 → 座位在座校验 → 退还 stack +
/// pending_addon → 腾座 → 移除 deck contributor → 退款/离桌事件。
///
/// caller 座位解析（认证）在 runtime dispatch 层。
pub fn apply_leave_table(
    table: &mut TexasPokerTable,
    seat_index: u8,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    if !can_leave_state(table) {
        return Err(PokerL1Error::Serialization(
            "not in WAITING state, cannot leave_table".into(),
        ));
    }
    let seat = &table.seats[seat_index as usize];
    if !seat.is_occupied() {
        return Err(PokerL1Error::Serialization(
            "seat not occupied, cannot leave".into(),
        ));
    }
    // 退还 stack + pending_addon（玩家离开时未入账的 addon 也必须退还）
    let refund_amt = seat
        .stack()
        .checked_add(seat.pending_addon())
        .ok_or_else(|| PokerL1Error::Serialization("leave_table refund overflow".into()))?;
    let post_chip_pool = table
        .chip_pool
        .checked_sub(refund_amt)
        .ok_or_else(|| PokerL1Error::Serialization("leave_table chip_pool underflow".into()))?;
    let player = seat.player();
    if refund_amt > 0 {
        // chip_pool 是总锁仓，必须扣除 stack + pending_addon 的完整退款。
        table.chip_pool = post_chip_pool;
    }
    table.seats[seat_index as usize].vacate();
    table.remove_deck_contributor(seat_index)?;

    if refund_amt > 0 {
        events.push(TexasPokerEvent::PlayerRefund {
            table_id: table.id,
            seat_index,
            player,
            amount: refund_amt,
            refund_type: REFUND_TYPE_STACK_ONLY,
        });
    }
    events.push(TexasPokerEvent::PlayerLeft {
        table_id: table.id,
        seat_index,
        player,
    });
    Ok(())
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::texas_poker::types::EMPTY_PLAYER;
    use crate::object_model::ObjectID;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn dummy_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    fn make_table() -> TexasPokerTable {
        TexasPokerTable::new(dummy_id(), EMPTY_PLAYER, 4, 50, 100)
    }

    #[test]
    fn apply_create_table_sets_rit_mode_and_rejects_unknown_values_atomically() {
        // TWICE：显式开启必须落到桌面规则。
        let mut table = make_table();
        apply_create_table(&mut table, [0xAA; 20], 6, 25, 50, RIT_MODE_TWICE).unwrap();
        assert_eq!(table.rules.rit_mode, RIT_MODE_TWICE);

        // DISABLED：默认不开启。
        apply_create_table(&mut table, [0xAA; 20], 6, 25, 50, RIT_MODE_DISABLED).unwrap();
        assert_eq!(table.rules.rit_mode, RIT_MODE_DISABLED);

        // 非协议值：fail-closed，且校验先于覆写——桌台原样保留。
        let pre_rit = table.rules.rit_mode;
        let error = apply_create_table(&mut table, [0xAA; 20], 6, 25, 50, 3).unwrap_err();
        assert!(error.to_string().contains("rit_mode"));
        assert_eq!(table.rules.rit_mode, pre_rit);
    }

    fn community_assignment(encrypted_card_index: u8, board_position: u8) -> RevealAssignment {
        RevealAssignment {
            encrypted_card_index,
            target: RevealTarget::Board {
                runout_index: 0,
                board_position,
            },
            pending_mask: 0,
            submitted_mask: 0,
            reveal_tokens: vec![],
        }
    }

    fn complete_public_reveal_with_card_ids(
        table: &mut TexasPokerTable,
        card_ids: &[u8],
        events: &mut Vec<TexasPokerEvent>,
    ) {
        assert_eq!(table.reveal_assignments().len(), card_ids.len());
        let plaintext_cards = generate_plaintext_cards();
        let card_indices = table
            .reveal_assignments()
            .iter()
            .map(|assignment| assignment.encrypted_card_index)
            .collect::<Vec<_>>();
        for (encrypted_card_index, card_id) in
            card_indices.into_iter().zip(card_ids.iter().copied())
        {
            let encrypted = table.deck_state.encrypted[usize::from(encrypted_card_index)];
            table.deck_state.encrypted[usize::from(encrypted_card_index)] = ElGamalCiphertext {
                c1: encrypted.c1,
                c2: plaintext_cards[usize::from(card_id)],
            };
        }
        for assignment in &mut table.active_reveal_state_mut().unwrap().assignments {
            assignment.pending_mask = 0;
            assignment.submitted_mask = 0;
            assignment.reveal_tokens.clear();
        }
        materialize_completed_reveal_assignments(table, events).unwrap();
        check_reveal_phase_complete(table, 1_000, events).unwrap();
    }

    #[test]
    fn test_can_join_state_initial() {
        let table = make_table();
        assert!(can_join_state(&table));
        assert!(can_leave_state(&table));
    }

    #[test]
    fn test_set_initial_encrypted_deck() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        assert_eq!(table.deck_state.encrypted.len(), 52);
        assert_eq!(generate_plaintext_cards().len(), 52);
        for ct in &table.deck_state.encrypted {
            // c1 = G（generator，非 identity）；c2 = plaintext_i（非 identity）。
            assert!(!g1_is_identity(&ct.c1));
            assert!(!g1_is_identity(&ct.c2));
        }
    }

    #[test]
    fn test_community_reveal_uses_plaintext_identity_not_encrypted_index() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        let plaintext_id = 3u8;
        let encrypted_card_index = 41u8;
        let plaintext_cards = generate_plaintext_cards();
        table.deck_state.encrypted[usize::from(encrypted_card_index)].c2 =
            plaintext_cards[usize::from(plaintext_id)];
        start_community_reveal_phase(&mut table, 1, REVEAL_PHASE_TURN, &mut vec![]).unwrap();
        table.active_reveal_state_mut().unwrap().assignments =
            vec![community_assignment(encrypted_card_index, 0)];
        let mut events = vec![];
        materialize_completed_reveal_assignments(&mut table, &mut events).unwrap();

        assert_eq!(table.community_cards, vec![Card::from_index(plaintext_id)]);
        assert_ne!(
            table.community_cards[0],
            Card::from_index(encrypted_card_index)
        );
        assert!(matches!(
            events.as_slice(),
            [TexasPokerEvent::CommunityCardRevealed { phase, card_indices, card_ranks, card_suits, card_count, .. }]
                if *phase == REVEAL_PHASE_TURN
                    && *card_count == 1
                    && card_indices[..1] == [encrypted_card_index]
                    && card_ranks[..1] == [Card::from_index(plaintext_id).rank()]
                    && card_suits[..1] == [Card::from_index(plaintext_id).suit()]
        ));
    }

    #[test]
    fn test_unknown_community_plaintext_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.encrypted[7].c2 = utils::hash_to_g1(b"not-a-canonical-card");
        start_community_reveal_phase(&mut table, 1, REVEAL_PHASE_FLOP, &mut vec![]).unwrap();
        table.active_reveal_state_mut().unwrap().assignments = vec![community_assignment(7, 0)];
        let before = table.clone();
        let mut events = vec![];
        let error = materialize_completed_reveal_assignments(&mut table, &mut events).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("not a canonical Texas Poker card")
        );
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_duplicate_community_plaintext_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        let plaintext = generate_plaintext_cards()[9];
        for encrypted_card_index in [2u8, 38u8] {
            table.deck_state.encrypted[usize::from(encrypted_card_index)].c2 = plaintext;
        }
        start_community_reveal_phase(&mut table, 2, REVEAL_PHASE_FLOP, &mut vec![]).unwrap();
        table.active_reveal_state_mut().unwrap().assignments =
            vec![community_assignment(2, 0), community_assignment(38, 1)];
        let before = table.clone();
        let mut events = vec![];
        let error = materialize_completed_reveal_assignments(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("duplicate decrypted card id 9"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_hole_card_duplicate_with_community_is_rejected_atomically() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.seats[0].fixture_set_player([1; 20]);
        let duplicate_id = 12u8;
        let plaintext_cards = generate_plaintext_cards();
        table
            .community_cards
            .try_push(Card::from_index(duplicate_id))
            .unwrap();
        table.deck_state.encrypted[44].c2 = plaintext_cards[usize::from(duplicate_id)];
        start_showdown_reveal_phase(&mut table, &mut vec![]).unwrap();
        table
            .deck_state
            .owner_readable_hole_cards
            .insert(
                0,
                0,
                PartialHoleCard::new(
                    44,
                    table.deck_state.encrypted[44],
                    table.deck_state.encrypted[44],
                ),
            )
            .unwrap();
        table.active_reveal_state_mut().unwrap().assignments = vec![RevealAssignment {
            encrypted_card_index: 44,
            target: RevealTarget::Hole {
                seat_index: 0,
                card_slot: 0,
            },
            pending_mask: 0,
            submitted_mask: 0,
            reveal_tokens: vec![],
        }];
        let before = table.clone();
        let mut events = vec![];
        let error = materialize_completed_reveal_assignments(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("duplicate decrypted card id 12"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_reconstruction_v3_two_players_rebuilds_canonical_deck() {
        let mut table = make_table();
        let generator = g1_generator();
        let owner_secrets = [scalar_from_u64(101), scalar_from_u64(202)];
        let owner_public_keys = [generator * owner_secrets[0], generator * owner_secrets[1]];
        let aggregate_pk = owner_public_keys[0] + owner_public_keys[1];

        for (seat_index, owner_pk) in owner_public_keys.iter().enumerate() {
            table.seats[seat_index].fixture_set_player([(seat_index as u8) + 1; 20]);
            table.seats[seat_index].set_stack(1_000).unwrap();
            table.seats[seat_index].fixture_set_pk(ECPoint(*owner_pk));
        }
        set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.contributor_mask = 0b11;
        assert_eq!(
            table.derived_aggregated_pk().unwrap(),
            Some(ECPoint(aggregate_pk))
        );
        table.hand_id = 7;
        table
            .enter_reconstructing(
                ROUND_FLOP,
                super::super::types::ReconstructState { pending_mask: 0b11 },
                super::super::types::RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                9_000,
            )
            .unwrap();

        // These ciphertexts model the authenticated, still-encrypted owner-readable
        // cards retained from the previous round. Their plaintexts are canonical
        // init-deck card points, but their readable-list order does not reveal the
        // hidden canonical slots used by the V3 Bayer--Groth witness.
        let readable_card_indices = [[17usize, 3usize], [41usize, 9usize]];
        let canonical_cards = generate_plaintext_cards();
        for (seat_index, indices) in readable_card_indices.iter().enumerate() {
            for (record_index, card_index) in indices.iter().enumerate() {
                let plaintext = canonical_cards[*card_index];
                let randomness =
                    scalar_from_u64(1_000 + (seat_index as u64) * 10 + record_index as u64);
                table
                    .deck_state
                    .owner_readable_hole_cards
                    .insert(
                        seat_index as u8,
                        record_index as u8,
                        PartialHoleCard::new(
                            (20 + seat_index * 2 + record_index) as u8,
                            ElGamalCiphertext::encrypt(
                                &plaintext,
                                &owner_public_keys[seat_index],
                                &randomness,
                            ),
                            ElGamalCiphertext::encrypt(
                                &plaintext,
                                &owner_public_keys[seat_index],
                                &randomness,
                            ),
                        ),
                    )
                    .unwrap();
            }
        }

        let preserved_readable_cards = table.deck_state.owner_readable_hole_cards.clone();
        let mut expected_deck =
            canonical_base_deck::<DefaultCurve>(&canonical_cards, &aggregate_pk)
                .expect("canonical aggregate-key base deck");
        let mut events = vec![];

        for seat_index in 0..2usize {
            let context_digest = utils::reconstruction_v3_context_digest(&table);
            let prior_state_digest =
                utils::reconstruction_v3_prior_state_digest(&table, seat_index as u8).unwrap();
            let readable_cards =
                utils::reconstruction_v3_residual_carriers(&table, seat_index as u8);
            let mut transcript = utils::new_reconstruct_v3_transcript();
            let mut rng = StdRng::seed_from_u64(0xC0DE_0000 + seat_index as u64);
            let (statement, proof) = ReconstructProof::prove(
                context_digest,
                table.reconstruct_epoch_ms().unwrap(),
                prior_state_digest,
                canonical_cards.clone(),
                readable_cards,
                &owner_secrets[seat_index],
                &owner_public_keys[seat_index],
                &aggregate_pk,
                &mut rng,
                &mut transcript,
            )
            .expect("honest reconstruction V3 proof");

            expected_deck = apply_reconstruction_contributions::<DefaultCurve>(
                &expected_deck,
                &statement.contributions,
            )
            .expect("apply verified contribution vector");
            apply_submit_reconstruct_deck(
                &mut table,
                seat_index as u8,
                statement,
                proof,
                &mut events,
            )
            .expect("state machine accepts honest reconstruction V3 submission");
        }

        assert_eq!(table.deck_state.encrypted.to_vec(), expected_deck);
        assert_eq!(table.deck_state.cards_dealt, 0);
        assert_eq!(
            table.deck_state.owner_readable_hole_cards,
            preserved_readable_cards
        );
        assert_eq!(
            table.reconstruct_state().as_ref(),
            &super::super::types::ReconstructState::default()
        );
        assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_RECONSTRUCT);
        assert_eq!(table.round_state(), ROUND_FLOP);
        assert_eq!(table.reveal_phase(), REVEAL_PHASE_FLOP);
        assert_eq!(table.shuffle_state().derived_current_shuffler(), 0);
        assert_eq!(table.shuffle_state().pending_mask, 0b11);
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::ReconstructComplete { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::DeckRebuilt { .. }))
        );
    }

    #[test]
    fn reconstruct_shuffle_timeout_preserves_resume_street_and_reveal() {
        let mut table = make_table();
        for seat_index in 0..3usize {
            table.seats[seat_index].fixture_set_player([(seat_index as u8) + 1; 20]);
            table.seats[seat_index].set_stack(100).unwrap();
            table.seats[seat_index].set_status(SeatStatus::Active);
        }
        table.chip_pool = 300;
        table.hand_id = 9;
        set_initial_encrypted_deck(&mut table).unwrap();

        let suspended_reveal = super::super::types::RevealTokenState {
            purpose: RevealPurpose::Board,
            assignments: vec![],
        };
        table
            .enter_reconstruct_shuffling(
                ROUND_TURN,
                super::super::types::ShuffleState {
                    pending_mask: 0b111,
                    completed_mask: 0,
                },
                suspended_reveal.clone(),
                1_000,
            )
            .unwrap();

        let deadline_ms = table.shuffle_deadline_ms().unwrap().unwrap();
        let mut events = vec![];
        let outcome = advance_deadline(&mut table, deadline_ms, &mut events).unwrap();

        assert!(matches!(
            outcome,
            AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::Shuffle,
                subject: 0,
            }
        ));
        assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_RECONSTRUCT);
        assert_eq!(table.round_state(), ROUND_TURN);
        assert_eq!(table.reveal_token_state(), Some(&suspended_reveal));
        assert_eq!(table.shuffle_state().pending_mask, 0b110);
        assert_eq!(table.shuffle_state().derived_current_shuffler(), 1);
        assert_eq!(
            table.shuffle_deadline_ms().unwrap(),
            Some(deadline_ms + u64::from(table.timeout_config.shuffle_timeout_ms))
        );
        assert!(
            events.iter().any(|event| matches!(
                event,
                TexasPokerEvent::ShuffleTimeout { seat_index: 0, .. }
            ))
        );
    }

    #[test]
    fn test_is_pk_registered() {
        let mut table = make_table();
        let g = g1_generator();
        let pk = g * scalar_from_u64(0xAB);
        assert!(!is_pk_registered(&table.seats, &pk));
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].fixture_set_pk(ECPoint(pk));
        assert!(is_pk_registered(&table.seats, &pk));
        let other_pk = g * scalar_from_u64(0xCD);
        assert!(!is_pk_registered(&table.seats, &other_pk));
    }

    #[test]
    fn test_count_active_players() {
        let mut table = make_table();
        assert_eq!(count_active_players(&table.seats), 0);

        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[1].fixture_set_player([0x02; 20]);
        assert_eq!(count_active_players(&table.seats), 2);

        table.seats[0].set_status(SeatStatus::Folded);
        assert_eq!(count_active_players(&table.seats), 1);

        table.seats[1].set_status(SeatStatus::Waiting);
        assert_eq!(count_active_players(&table.seats), 0);
    }

    #[test]
    fn test_get_active_seat_indices() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[2].fixture_set_player([0x03; 20]);
        let active = get_active_seat_indices(&table.seats);
        assert_eq!(active, vec![0, 2]);
    }

    #[test]
    fn test_find_next_active_seat() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_status(SeatStatus::Folded);
        table.seats[2].fixture_set_player([0x03; 20]);
        let next = find_next_active_seat(&table.seats, 0, 4);
        assert_eq!(next, Some(2));
    }

    #[test]
    fn test_remove_from_pending_mask() {
        let mut mask = 0b1010_1010;
        seat_mask_remove(&mut mask, 3);
        assert_eq!(mask, 0b1010_0010);
        seat_mask_remove(&mut mask, 99);
        assert_eq!(mask, 0b1010_0010);
    }

    #[test]
    fn test_add_remove_pk_aggregated() {
        let g = g1_generator();
        let pk1 = g * scalar_from_u64(111);
        let pk2 = g * scalar_from_u64(222);

        // typed 化后 add/remove_pk_to/from_aggregated 接受 Option<&G1Projective>，
        // 返回 Option<G1Projective>（None = 空/单位元）。
        let agg1 = add_pk_to_aggregated(None, &pk1);
        assert_eq!(agg1, Some(pk1));

        let agg2 = add_pk_to_aggregated(agg1.as_ref(), &pk2);
        let expected = g1_add(&pk1, &pk2);
        assert_eq!(agg2, Some(expected));

        let agg3 = remove_pk_from_aggregated(agg2.as_ref(), &pk1);
        assert_eq!(agg3, Some(pk2));

        let agg4 = remove_pk_from_aggregated(agg3.as_ref(), &pk2);
        assert_eq!(agg4, None);
    }

    #[test]
    fn test_start_hand_requires_min_players() {
        let mut table = make_table();
        let mut events = vec![];
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_err());

        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_err());

        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        let result = start_hand(&mut table, &mut events);
        assert!(result.is_ok());
        assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_BEFORE_PREFLOP);
        assert_ne!(table.shuffle_state().pending_mask, 0);
    }

    #[test]
    fn test_start_hand_initializes_deck() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        let mut events = vec![];
        start_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.deck_state.encrypted.len(), 52);
        assert_eq!(generate_plaintext_cards().len(), 52);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::HandStarted { .. }))
        );
    }

    #[test]
    fn test_tick_only_consumes_deadline_after_explicit_start() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        let mut events = vec![];
        // WAITING has no deadline: advance_deadline must not start a hand implicitly.
        advance_deadline(&mut table, 1000, &mut events).unwrap();
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_NONE);

        start_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_BEFORE_PREFLOP);
        assert_ne!(table.shuffle_state().derived_current_shuffler(), NO_SEAT);
        assert_eq!(table.shuffle_deadline_ms().unwrap(), Some(0));
        // The start-hand command's own normalization suffix arms the active shuffle deadline.
        normalize_until_blocked(&mut table, 1000, &mut events).unwrap();
        assert_eq!(
            table.shuffle_deadline_ms().unwrap(),
            Some(1000 + u64::from(table.timeout_config.shuffle_timeout_ms))
        );
        let before_tick = table.clone();
        advance_deadline(&mut table, 1000, &mut events).unwrap();
        assert_eq!(
            table, before_tick,
            "advance_deadline must not be used only to arm a timer"
        );
    }

    #[test]
    fn shuffle_actor_is_derived_without_normalization_step() {
        let mut table = make_table();
        for (seat_index, player) in [(0usize, [0x01; 20]), (2usize, [0x03; 20])] {
            table.seats[seat_index].fixture_set_player(player);
            table.seats[seat_index].set_stack(1_000).unwrap();
            table.seats[seat_index].set_status(SeatStatus::Active);
        }
        table
            .enter_initial_shuffling(
                super::super::types::ShuffleState {
                    pending_mask: 0b0101,
                    completed_mask: 0,
                },
                0,
            )
            .unwrap();

        let mut events = vec![];
        let report = normalize_until_blocked(&mut table, 1_000, &mut events).unwrap();

        assert!(report.steps.is_empty());
        assert_eq!(table.shuffle_state().derived_current_shuffler(), 0);
        assert!(events.is_empty());
    }

    #[test]
    fn normalize_completes_ready_reveal_phase() {
        let mut table = make_table();
        table
            .enter_revealing(
                ROUND_SHOWDOWN,
                super::super::types::RevealTokenState {
                    purpose: RevealPurpose::ShowdownOwner,
                    assignments: vec![],
                },
                0,
            )
            .unwrap();

        let mut events = vec![];
        let report = normalize_until_blocked(&mut table, 1_000, &mut events).unwrap();

        assert_eq!(report.steps, vec![NormalizationStep::CompleteReveal]);
        assert!(table.reveal_token_state().is_none());
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::RevealPhaseComplete {
                phase: REVEAL_PHASE_SHOWDOWN,
                ..
            }
        )));
    }

    #[test]
    fn normalize_rejects_unmaterialized_reveal_atomically() {
        let mut table = make_table();
        table
            .enter_revealing(
                ROUND_FLOP,
                super::super::types::RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Board {
                            runout_index: 0,
                            board_position: 0,
                        },
                        pending_mask: 0,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                0,
            )
            .unwrap();
        let before = table.clone();
        let mut events = vec![];

        let error = normalize_until_blocked(&mut table, 1_000, &mut events).unwrap_err();

        assert!(!error.to_string().is_empty());
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn normalize_rejects_betting_payload_on_showdown_atomically() {
        let mut table = make_table();
        table.hand_phase = super::super::types::HandPhase::Betting {
            street: ROUND_SHOWDOWN,
            round: BettingRound::new(100, 100),
            current_turn: NO_SEAT,
            deadline_ms: 0,
        };
        let before = table.clone();
        let mut events = vec![];

        let error = normalize_until_blocked(&mut table, 1_000, &mut events).unwrap_err();

        assert!(!error.to_string().is_empty());
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    #[test]
    fn advance_betting_deadline_normalizes_then_reports_not_due_and_extends_time_bank() {
        let mut table = make_table();
        for (seat_index, player) in [(0usize, [0x01; 20]), (1usize, [0x02; 20])] {
            table.seats[seat_index].fixture_set_player(player);
            table.seats[seat_index].set_stack(1_000).unwrap();
            table.seats[seat_index].set_status(SeatStatus::Active);
        }
        table.timeout_config.betting_timeout_ms = 100;
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 1_000)
            .unwrap();
        table.seats[0].set_time_bank_ms(40);
        let mut events = vec![];

        assert_eq!(
            advance_deadline(&mut table, 1_099, &mut events).unwrap(),
            AdvanceDeadlineOutcome::NotDue {
                kind: DeadlineKind::Betting,
                subject: 0,
                deadline_ms: 1_100,
            }
        );
        assert_eq!(
            advance_deadline(&mut table, 1_100, &mut events).unwrap(),
            AdvanceDeadlineOutcome::TimeBankExtended {
                seat_index: 0,
                deadline_ms: 1_140,
            }
        );
        assert_eq!(table.seats[0].time_bank_ms(), 0);
        assert_eq!(
            table.betting_deadline_ms().unwrap().unwrap()
                - u64::from(table.timeout_config.betting_timeout_ms),
            1_040
        );
    }

    #[test]
    fn test_post_blinds_heads_up() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.button = 0;
        let mut events = vec![];
        let (sb, bb, first) = post_blinds(&mut table, &mut events).unwrap();
        assert_eq!(sb, 0);
        assert_eq!(bb, 1);
        assert_eq!(first, 1);
        assert_eq!(table.seats[0].bet(), 50);
        assert_eq!(table.seats[1].bet(), 100);
        assert_eq!(table.seats[0].stack(), 950);
        assert_eq!(table.seats[1].stack(), 900);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::BlindsPosted { .. }))
        );
    }

    #[test]
    fn test_post_blinds_dead_button_rotation() {
        // Dead button（Robert's Rules §4.2b）：大盲按轮转归属——上一手大盲
        // 座位之后第一个参与座位；上一手大盲座位本身（仍参与时）交小盲。
        let mut table = make_table();
        // 4 桌：座 3 已离场；上一手 BB=座 2，上一手按钮=座 3（空）。
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[2].fixture_set_player([0x03; 20]);
        table.seats[2].set_stack(1000).unwrap();
        table.last_bb_seat = 2;
        let mut events = vec![];
        let (sb, bb, _) = post_blinds(&mut table, &mut events).unwrap();
        // 轮转：BB = 上一手 BB（座 2）之后第一个参与座位 = 座 0；
        // SB = 上一手 BB 座位本身（座 2，仍参与）。
        assert_eq!(bb, 0);
        assert_eq!(sb, 2);
        assert_eq!(table.last_bb_seat, 0, "track advances to this hand's BB");
        assert_eq!(table.seats[2].bet(), 50);
        assert_eq!(table.seats[0].bet(), 100);
    }

    #[test]
    fn test_post_blinds_dead_small_blind() {
        // 上一手大盲座位已离场 → 本手无小盲（dead small blind），只有大盲。
        // 注意：需要 ≥3 名参与者——单挑时小盲恒为另一参与者，无 dead SB。
        let mut table = make_table();
        table.seats[1].fixture_set_player([0x01; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[2].fixture_set_player([0x02; 20]);
        table.seats[2].set_stack(1000).unwrap();
        table.seats[3].fixture_set_player([0x03; 20]);
        table.seats[3].set_stack(1000).unwrap();
        table.last_bb_seat = 0; // 上一手大盲（座 0）已离场
        let mut events = vec![];
        let (sb, bb, _) = post_blinds(&mut table, &mut events).unwrap();
        assert_eq!(sb, NO_SEAT, "previous BB seat is vacant → dead small blind");
        assert_eq!(bb, 1, "BB = first participating after the vacant seat");
        assert_eq!(table.last_bb_seat, 1);
        assert_eq!(table.seats[1].bet(), 100);
        assert_eq!(table.seats[2].bet(), 0, "no small blind posted");
        let posted = events.iter().any(|e| {
            matches!(
                e,
                TexasPokerEvent::BlindsPosted {
                    sb_seat: NO_SEAT,
                    sb_amount: 0,
                    ..
                }
            )
        });
        assert!(posted, "BlindsPosted carries the dead SB shape");
    }

    #[test]
    fn test_post_blinds_hu_dead_button_button_seat_differs() {
        // 单挑 + 死按钮：按钮落在空座位，SB（轮转）≠ button 座位。
        let mut table = make_table();
        table.seats[1].fixture_set_player([0x01; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[3].fixture_set_player([0x03; 20]);
        table.seats[3].set_stack(1000).unwrap();
        table.button = 0; // 死按钮落在空座位
        table.last_bb_seat = 1; // 上一手大盲 = 座 1
        let mut events = vec![];
        let (sb, bb, _) = post_blinds(&mut table, &mut events).unwrap();
        // BB 按轮转 = 上一手 BB 之后第一个参与 = 座 3；SB = 另一人 = 座 1。
        assert_eq!(bb, 3);
        assert_eq!(sb, 1);
        assert_ne!(
            sb, table.button,
            "dead button: SB seat differs from the button seat"
        );
        assert_eq!(table.last_bb_seat, 3);
    }

    #[test]
    fn test_apply_fold_ends_without_showdown() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        table.pot = 200;
        table.seats[0].fixture_set_bet(25);
        table.seats[0].fixture_set_total_bet(25);
        table.seats[1].fixture_set_bet(75);
        table.seats[1].fixture_set_total_bet(75);
        let mut events = vec![];

        apply_fold(&mut table, 0, &mut events).unwrap();
        // fold 后只剩 1 名活跃玩家 → end_without_showdown → reset_for_next_hand
        // 会清掉 folded 标记，故此处仅断言事件与筹码分配。
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerFolded { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::HandEndedWithoutShowdown { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, TexasPokerEvent::PotCollected { pot_after: 300, .. }))
        );
        assert_eq!(table.seats[1].stack(), 1300);
    }

    #[test]
    fn test_collect_bets_to_pot_overflow_is_atomic() {
        let mut pot_overflow = make_table();
        pot_overflow.pot = u64::MAX;
        pot_overflow.seats[0].fixture_set_player([0x01; 20]);
        pot_overflow.seats[0].fixture_set_bet(1);
        let before = pot_overflow.clone();
        let mut events = vec![];
        assert!(collect_bets_to_pot(&mut pot_overflow, &mut events).is_err());
        assert_eq!(pot_overflow, before);
        assert!(events.is_empty());

        let mut sum_overflow = make_table();
        sum_overflow.seats[0].fixture_set_player([0x01; 20]);
        sum_overflow.seats[1].fixture_set_player([0x02; 20]);
        sum_overflow.seats[0].fixture_set_bet(u64::MAX);
        sum_overflow.seats[1].fixture_set_bet(1);
        let before = sum_overflow.clone();
        assert!(collect_bets_to_pot(&mut sum_overflow, &mut events).is_err());
        assert_eq!(sum_overflow, before);
        assert!(events.is_empty());
    }

    #[test]
    fn test_apply_call_deducts_stack() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_bet(0);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_bet(100);
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_call(&mut table, 0, &mut events).unwrap();
        assert_eq!(table.seats[0].stack(), 900);
        assert_eq!(table.seats[0].bet(), 100);
        assert!(table.seat_acted_this_round(0));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerCalled { .. }))
        );
    }

    #[test]
    fn test_apply_raise_resets_others_acted() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_bet(100);
        table.set_seat_acted_this_round(1, true);
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_raise(&mut table, 0, 300, &mut events).unwrap();
        assert_eq!(table.seats[0].bet(), 300);
        assert_eq!(table.seats[0].stack(), 700);
        assert!(!table.seat_acted_this_round(1));
    }

    #[test]
    fn test_short_all_in_raise_does_not_reopen_action() {
        // current_bet=100, min_raise=100；seat0 短 all-in 加到 150
        // （raise_amount=50 < min_raise），不应清除 seat1 的 acted 标记。
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(150).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_bet(100);
        table.set_seat_acted_this_round(1, true);
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_raise(&mut table, 0, 150, &mut events).unwrap();
        assert_eq!(table.seats[0].bet(), 150);
        assert_eq!(table.seats[0].stack(), 0);
        assert!(table.seats[0].is_all_in());
        // 短 all-in 不重新打开 seat1 的行动权。
        assert!(table.seat_acted_this_round(1));
        // current_bet 被抬高，但 min_raise 保持不变。
        let round = table.betting_round().unwrap();
        assert_eq!(round.current_bet, 150);
        assert_eq!(round.min_raise, 100);
    }

    #[test]
    fn test_acted_player_cannot_raise_after_short_all_in() {
        // seat0 短 all-in 后，已行动的 seat1 只能 call 或 fold，不得再加注（TDA #41）。
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(150).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_bet(100);
        table.set_seat_acted_this_round(1, true);
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_raise(&mut table, 0, 150, &mut events).unwrap();
        assert!(is_player_turn(&table, 1));
        // seat1 加注被拒绝：短 all-in 没有重新打开其行动权。
        assert!(apply_raise(&mut table, 1, 400, &mut events).is_err());
        // call 到新水位仍然允许。
        apply_call(&mut table, 1, &mut events).unwrap();
        // 双方水位一致后本轮结束，bet 被收入 pot。
        assert_eq!(table.seats[1].stack(), 950);
        assert_eq!(table.pot, 300);
    }

    #[test]
    fn test_end_without_showdown_does_not_rake_uncontested_pot() {
        // 全员 fold、唯一幸存者直接获胜：无竞争 pot 不抽水，
        // 赢家拿回全部底池（含自己未被跟注的部分）。
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].set_status(SeatStatus::Folded);
        table.pot = 300;
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 1_000;
        table.rake_cap = u64::MAX;
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        end_without_showdown(&mut table, &mut events).unwrap();
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::RakeCollected { .. }))
        );
        assert_eq!(table.seats[0].stack(), 1300);
        assert_eq!(table.pot, 0);
    }

    #[test]
    fn test_reset_for_next_hand_clears_state() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_bet(100);
        table.seats[0].fixture_set_total_bet(250);
        table.seats[0].set_status(SeatStatus::Folded);
        table.pot = 500;
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 0), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        reset_for_next_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert_eq!(table.pot, 0);
        assert_eq!(table.seats[0].bet(), 0);
        assert_eq!(table.seats[0].total_bet(), 0);
        assert!(!table.seats[0].is_folded());
        assert!(table.community_cards.is_empty());
        assert_eq!(table.deck_state.encrypted.len(), 52);
    }

    #[test]
    fn test_kick_player_internal_removes_pk() {
        let mut table = make_table();
        let g = g1_generator();
        // 3 个玩家，pk = sk_i * G；aggregated_pk = pk0 + pk1 + pk2。
        let pk0 = g * scalar_from_u64(42);
        let pk1 = g * scalar_from_u64(43);
        let pk2 = g * scalar_from_u64(44);
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();
        table.seats[0].fixture_set_pk(ECPoint(pk0));
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(500).unwrap();
        table.seats[1].fixture_set_pk(ECPoint(pk1));
        table.seats[2].fixture_set_player([0x03; 20]);
        table.seats[2].set_stack(500).unwrap();
        table.chip_pool = 1_500;
        table.seats[2].fixture_set_pk(ECPoint(pk2));
        table.deck_state.contributor_mask = 0b111;
        // 用一个非 NONE 的 round_state，使 reset_for_next_hand 不会被触发
        // （count_active_players 在 kick 后仍 >= MIN_PLAYERS_TO_START）。
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 0), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events).unwrap();
        // kick 后 active=2（seat1+seat2），不会触发 reset_for_next_hand。
        assert!(table.seats[0].has_left_hand());
        assert_eq!(table.seats[0].status(), SeatStatus::Out);
        assert_eq!(table.seats[0].stack(), 0);
        // Departed seat no longer carries a live Mental Poker key.
        assert!(table.seats[0].pk().is_none());
        // aggregated_pk 应 = pk1 + pk2（移除 pk0）。
        let new_agg = table.derived_aggregated_pk().unwrap().unwrap().0;
        let expected = pk1 + pk2;
        assert!(g1_equal(&new_agg, &expected));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerKicked { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerRefund { .. }))
        );
    }

    #[test]
    fn test_kick_player_pool_underflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(10).unwrap();
        table.chip_pool = 9;
        let before = table.clone();
        let mut events = vec![];

        let error =
            kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events).unwrap_err();

        assert!(error.to_string().contains("chip_pool underflow"));
        assert_eq!(table, before, "failed kick refund must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_kick_player_nested_reset_failure_is_atomic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(10).unwrap();
        // A waiting seat is not counted as active, so kicking seat 0 triggers reset. Make the
        // pending-addon merge overflow so reset fails after the kick candidate mutates.
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_status(SeatStatus::Waiting);
        table.seats[1].set_stack(u64::MAX).unwrap();
        table.seats[1].set_pending_addon(1).unwrap();
        table.chip_pool = 10;
        let before = table.clone();
        let mut events = vec![];

        let error = kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events)
            .expect_err("nested reset failure must propagate");

        assert!(
            error
                .to_string()
                .contains("stack += pending_addon overflow")
        );
        assert_eq!(
            table, before,
            "nested reset failure must not commit the kick"
        );
        assert!(
            events.is_empty(),
            "failed kick must not emit partial events"
        );
    }

    #[test]
    fn test_active_kick_settlement_resets_once() {
        let mut table = make_table();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([u8::try_from(seat_index + 1).unwrap(); 20]);
            table.seats[seat_index].set_stack(900).unwrap();
            table.seats[seat_index].fixture_set_bet(100);
            table.seats[seat_index].fixture_set_total_bet(100);
        }
        table.chip_pool = 2_000;
        let pre_call_seq = table.call_seq;
        let mut events = vec![];

        kick_player_internal(&mut table, 0, KICK_REASON_ADMIN, &mut events).unwrap();

        assert_eq!(table.call_seq, pre_call_seq);
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert_eq!(table.pot, 0);
        assert_eq!(table.seats[1].stack(), 1_100);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, TexasPokerEvent::HandEndedWithoutShowdown { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn test_non_current_active_kick_awards_survivor_before_reset() {
        let mut table = make_table();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([u8::try_from(seat_index + 1).unwrap(); 20]);
            table.seats[seat_index].set_stack(900).unwrap();
            table.seats[seat_index].fixture_set_bet(100);
            table.seats[seat_index].fixture_set_total_bet(100);
        }
        table.chip_pool = 2_000;
        let pre_call_seq = table.call_seq;
        let mut events = vec![];

        kick_player_internal(&mut table, 1, KICK_REASON_ADMIN, &mut events).unwrap();

        assert_eq!(table.call_seq, pre_call_seq);
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert_eq!(table.pot, 0);
        assert_eq!(table.seats[0].stack(), 1_100);
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::HandEndedWithoutShowdown { winner_seat: 0, .. }
        )));
    }

    #[test]
    fn test_partial_decrypt_c2_subtracts_tokens() {
        let g = g1_generator();
        let sk = scalar_from_u64(42);
        let pk = g * sk;
        let plaintext = utils::hash_to_g1(b"test_card");
        let r = scalar_from_u64(7);
        let ct = ElGamalCiphertext::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);

        // typed 化后 partial_decrypt_c2 直接接受 G1Projective，返回 G1Projective。
        let result = partial_decrypt_c2(&ct.c2, &[token]);
        assert!(g1_equal(&result, &plaintext));
    }

    #[test]
    fn test_is_betting_complete() {
        let mut table = make_table();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_bet(100);
        table.set_seat_acted_this_round(0, true);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table.seats[1].fixture_set_bet(100);
        table.set_seat_acted_this_round(1, true);
        assert!(is_betting_complete(&table));

        table.set_seat_acted_this_round(1, false);
        assert!(!is_betting_complete(&table));
    }

    // ========== Addon / Rebuy 单元测试 ==========

    #[test]
    fn test_apply_addon_basic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();
        let mut events = vec![];

        apply_addon(&mut table, 0, 200, &mut events).unwrap();
        // 关键不变量：stack 不变（不影响当前手牌）
        assert_eq!(table.seats[0].stack(), 500);
        assert_eq!(table.seats[0].pending_addon(), 200);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            200
        );
        assert_eq!(
            table.call_seq, 0,
            "business helper does not commit a command"
        );
        // 事件
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::AddonRequested { amount: 200, .. }))
        );
    }

    #[test]
    fn test_apply_addon_accumulates() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(500).unwrap();

        apply_addon(&mut table, 0, 100, &mut vec![]).unwrap();
        apply_addon(&mut table, 0, 50, &mut vec![]).unwrap();
        assert_eq!(table.seats[0].pending_addon(), 150);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            150
        );
        assert_eq!(table.seats[0].stack(), 500); // 仍不变
    }

    #[test]
    fn test_apply_addon_invalid_seat() {
        let mut table = make_table();
        // 越界
        let err = apply_addon(&mut table, 99, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat_index 99 out of range"));
        // amount == 0
        table.seats[0].fixture_set_player([0x01; 20]);
        let err = apply_addon(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
        // 未占用座位
        let err = apply_addon(&mut table, 1, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat 1 not occupied"));
    }

    #[test]
    fn test_set_leave_after_hand_is_idempotent() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_status(SeatStatus::Waiting);
        let mut events = vec![];

        assert!(apply_set_leave_after_hand(&mut table, 0, true, &mut events).unwrap());
        assert!(table.seat_wants_leave(0));
        assert_eq!(table.call_seq, 0);
        assert_eq!(events.len(), 1);

        assert!(!apply_set_leave_after_hand(&mut table, 0, true, &mut events).unwrap());
        assert!(table.seat_wants_leave(0));
        assert_eq!(
            table.call_seq, 0,
            "idempotent retry must not commit a command"
        );
        assert_eq!(
            events.len(),
            1,
            "idempotent retry must not duplicate events"
        );

        assert!(apply_set_leave_after_hand(&mut table, 0, false, &mut events).unwrap());
        assert!(!table.seat_wants_leave(0));
        assert_eq!(table.call_seq, 0);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_reset_for_next_hand_merges_addon() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(0).unwrap(); // stack==0 触发清理
        table.seats[0].set_pending_addon(500).unwrap(); // 但有 addon
        table.chip_pool = 500;

        let mut events = vec![];
        reset_for_next_hand(&mut table, &mut events).unwrap();

        // addon 合并后 stack > 0，玩家不应被踢
        assert_eq!(table.seats[0].stack(), 500);
        assert_eq!(table.seats[0].pending_addon(), 0);
        assert_eq!(table.seats[0].player(), [0x01; 20]);
        // AddonCredited 事件应触发
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::AddonCredited {
                amount: 500,
                stack_after: 500,
                ..
            }
        )));
    }

    #[test]
    fn test_reset_for_next_hand_pending_sum_overflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_pending_addon(u64::MAX).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_pending_addon(1).unwrap();
        table.chip_pool = u64::MAX;
        let before = table.clone();
        let mut events = vec![];

        let error = reset_for_next_hand(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("total pending addon overflow"));
        assert_eq!(table, before, "failed addon merge must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_reset_for_next_hand_leave_underflow_is_atomic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(10).unwrap();
        table.set_seat_wants_leave(0, true);
        table.chip_pool = 9;
        let before = table.clone();
        let mut events = vec![];

        let error = reset_for_next_hand(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("leave chip_pool underflow"));
        assert_eq!(table, before, "failed leave refund must be atomic");
        assert!(events.is_empty());
    }

    #[test]
    fn test_reset_for_next_hand_addon_then_cleanup() {
        // addon=0 且 stack=0 的玩家应被清理（不能误保留）
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(0).unwrap();
        table.seats[0].set_pending_addon(0).unwrap();

        let mut events = vec![];
        reset_for_next_hand(&mut table, &mut events).unwrap();
        assert_eq!(table.seats[0].player(), [0u8; 20]); // EMPTY_PLAYER
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerLeft { seat_index: 0, .. }))
        );
    }

    #[test]
    fn test_apply_rebuy_immediate() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(100).unwrap();
        table.chip_pool = 100;

        let mut events = vec![];
        apply_rebuy(&mut table, 0, 500, &mut events).unwrap();
        // 立即生效
        assert_eq!(table.seats[0].stack(), 600);
        assert_eq!(table.chip_pool, 600);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            0
        );
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::RebuyProcessed {
                amount: 500,
                stack_after: 600,
                ..
            }
        )));
    }

    #[test]
    fn test_apply_rebuy_invalid() {
        let mut table = make_table();
        // amount == 0
        table.seats[0].fixture_set_player([0x01; 20]);
        let err = apply_rebuy(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
        // 未占用
        let err = apply_rebuy(&mut table, 1, 100, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("seat 1 not occupied"));
    }

    // ========== Bet 动作测试 ==========

    #[test]
    fn test_apply_bet_postflop() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_bet(0); // postflop bet=0
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_bet(&mut table, 0, 200, &mut events).unwrap();
        assert_eq!(table.seats[0].bet(), 200);
        assert_eq!(table.seats[0].stack(), 800);
        assert!(table.seat_acted_this_round(0));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::PlayerBet { amount: 200, .. }))
        );
    }

    #[test]
    fn test_apply_bet_rejects_when_current_bet_exists() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[0].fixture_set_bet(50);
        // 模拟已有下注：current_bet = 100 > seat.bet = 50
        let mut round = BettingRound::new(100, 0);
        round.current_bet = 100;
        table.enter_betting(ROUND_FLOP, round, 0, 0).unwrap();

        let err = apply_bet(&mut table, 0, 200, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("current_bet 100 > seat_bet 50"));
    }

    #[test]
    fn test_apply_bet_rejects_zero_amount() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 0), 0, 0)
            .unwrap();

        let err = apply_bet(&mut table, 0, 0, &mut vec![]).unwrap_err();
        assert!(err.to_string().contains("amount must > 0"));
    }

    // ========== Time Bank 测试 ==========

    #[test]
    fn test_consume_time_bank_basic() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_time_bank_ms(30_000);
        let mut events = vec![];

        consume_time_bank(&mut table, 0, 10_000, &mut events).unwrap();
        assert_eq!(table.seats[0].time_bank_ms(), 20_000);
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::TimeBankConsumed {
                consumed_ms: 10_000,
                remaining_ms: 20_000,
                ..
            }
        )));
    }

    #[test]
    fn test_consume_time_bank_insufficient() {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_time_bank_ms(5_000);
        let err = consume_time_bank(&mut table, 0, 10_000, &mut vec![]).unwrap_err();
        assert!(
            err.to_string()
                .contains("time_bank_ms 5000 < consumed_ms 10000")
        );
    }

    // ========== Ante 测试 ==========

    #[test]
    fn test_collect_ante_normal_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NORMAL;
        table.ante_amount = 10;
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        let mut events = vec![];

        collect_ante(&mut table, 1, &mut events).unwrap();
        assert_eq!(table.pot, 20);
        assert_eq!(table.seats[0].stack(), 990);
        assert_eq!(table.seats[1].stack(), 990);
        assert_eq!(table.seats[0].bet(), 0);
        assert_eq!(table.seats[1].bet(), 0);
        assert_eq!(table.seats[0].total_bet(), 10);
        assert_eq!(table.seats[1].total_bet(), 10);
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TexasPokerEvent::AntePosted { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn test_ante_does_not_buy_down_call_and_table_vault_reconciles() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NORMAL;
        table.ante_amount = 10;
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1_000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1_000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        table.chip_pool = 2_000;
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        let (_, bb_seat, _) = post_blinds(&mut table, &mut events).unwrap();
        collect_ante(&mut table, bb_seat, &mut events).unwrap();
        start_betting_round(&mut table, true, Some(bb_seat), &mut events).unwrap();
        table.arm_betting_deadline(1).unwrap();

        assert_eq!(table.betting_round().unwrap().current_bet, table.big_blind);
        assert_eq!(table.pot, 20);
        assert_eq!(table.seats.iter().map(|seat| seat.bet()).sum::<u64>(), 150);
        assert_eq!(reconcile_table_vault(&table).unwrap(), 2_000);
    }

    #[test]
    fn test_collect_ante_bba_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_BBA;
        table.ante_amount = 20;
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1000).unwrap();
        let mut events = vec![];

        // BBA 模式：仅 bb_seat=1 投 ante
        collect_ante(&mut table, 1, &mut events).unwrap();
        assert_eq!(table.pot, 20);
        assert_eq!(table.seats[0].stack(), 1000); // SB 不投 ante
        assert_eq!(table.seats[1].stack(), 980); // BB 投 ante
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, TexasPokerEvent::AntePosted { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn test_collect_ante_none_mode() {
        let mut table = make_table();
        table.ante_mode = ANTE_MODE_NONE;
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1000).unwrap();
        let mut events = vec![];

        collect_ante(&mut table, 0, &mut events).unwrap();
        assert_eq!(table.pot, 0);
        assert!(events.is_empty());
    }

    // Rake 金额计算的唯一权威实现是 `settlement::compute_rake`，
    // 其公式、封顶与守恒行为由 settlement.rs / settlement_fixture.rs 的测试覆盖。

    // ========== Run It Twice 测试 ==========

    #[test]
    fn test_trigger_run_it_twice_enabled() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_TWICE;
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([seat_index as u8 + 1; 20]);
            table.seats[seat_index].set_status(SeatStatus::AllIn);
        }
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        trigger_run_it_twice(&mut table, &mut events).unwrap();
        assert!(table.run_it_twice_state.is_active());
        assert_eq!(table.run_it_twice_state.shared_board_len(), 0);
        assert!(events.iter().any(|e| matches!(
            e,
            TexasPokerEvent::RunItTwiceTriggered {
                board1_cards: 5,
                board2_cards: 5,
                ..
            }
        )));
    }

    #[test]
    fn test_trigger_run_it_twice_disabled() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_DISABLED;
        let mut events = vec![];

        trigger_run_it_twice(&mut table, &mut events).unwrap();
        // DISABLED 模式下不 emit 事件
        assert!(events.is_empty());
    }

    #[test]
    fn run_it_twice_turn_reveal_schedules_one_card_per_board() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_TWICE;
        table.community_cards = vec![Card::new(0, 2), Card::new(1, 3), Card::new(2, 4)]
            .try_into()
            .unwrap();
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([seat_index as u8 + 1; 20]);
            table.seats[seat_index].set_status(SeatStatus::AllIn);
        }
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];
        trigger_run_it_twice(&mut table, &mut events).unwrap();
        start_community_reveal_phase(&mut table, 1, ROUND_TURN, &mut events).unwrap();

        assert_eq!(table.run_it_twice_state.shared_board_len(), 3);
        assert!(table.run_it_twice_state.second_board_suffix().is_empty());
        assert_eq!(
            table
                .run_it_twice_state
                .full_second_board(&table.community_cards)
                .unwrap(),
            table.community_cards.to_vec()
        );
        assert_eq!(table.reveal_assignments().len(), 2);
        assert_eq!(
            table.reveal_assignments()[0].target,
            RevealTarget::Board {
                runout_index: 0,
                board_position: 3
            }
        );
        assert_eq!(
            table.reveal_assignments()[1].target,
            RevealTarget::Board {
                runout_index: 1,
                board_position: 3
            }
        );
        assert_ne!(
            table.reveal_assignments()[0].encrypted_card_index,
            table.reveal_assignments()[1].encrypted_card_index
        );
    }

    #[test]
    fn run_it_twice_triggers_from_each_incomplete_street() {
        for (round_state, shared_cards) in [
            (ROUND_PREFLOP, vec![]),
            (
                ROUND_FLOP,
                vec![
                    Card::from_index(0),
                    Card::from_index(1),
                    Card::from_index(2),
                ],
            ),
            (
                ROUND_TURN,
                vec![
                    Card::from_index(0),
                    Card::from_index(1),
                    Card::from_index(2),
                    Card::from_index(3),
                ],
            ),
        ] {
            let mut table = make_table();
            table.rit_mode = RIT_MODE_TWICE;
            table.community_cards = BoardCards::try_from(shared_cards.clone()).unwrap();
            for seat_index in 0..2 {
                table.seats[seat_index].fixture_set_player([seat_index as u8 + 1; 20]);
                table.seats[seat_index].set_status(SeatStatus::AllIn);
            }
            table
                .enter_betting(round_state, BettingRound::new(100, 100), NO_SEAT, 0)
                .unwrap();
            let mut events = vec![];

            maybe_trigger_run_it_twice(&mut table, &mut events).unwrap();

            assert!(table.run_it_twice_state.is_active());
            assert_eq!(
                usize::from(table.run_it_twice_state.shared_board_len()),
                shared_cards.len()
            );
            assert!(table.run_it_twice_state.second_board_suffix().is_empty());
        }
    }

    #[test]
    fn run_it_twice_does_not_trigger_after_river_is_complete() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_TWICE;
        table.community_cards =
            BoardCards::try_from((0..5).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([seat_index as u8 + 1; 20]);
            table.seats[seat_index].set_status(SeatStatus::AllIn);
        }
        table
            .enter_betting(ROUND_RIVER, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        maybe_trigger_run_it_twice(&mut table, &mut events).unwrap();

        assert!(!table.run_it_twice_state.is_active());
        assert!(events.is_empty());
    }

    #[test]
    fn run_it_twice_plaintexts_route_through_turn_river_and_settlement() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.rit_mode = RIT_MODE_TWICE;
        table.community_cards =
            BoardCards::try_from((0..3).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        table.deck_state.cards_dealt = 7;
        table.pot = 200;
        table.chip_pool = 2_000;
        table.seats[0].fixture_set_player([1; 20]);
        table.seats[0].set_stack(900).unwrap();
        table.seats[0].fixture_set_total_bet(100);
        table.seats[0].set_status(SeatStatus::AllIn);
        table.seats[0].fixture_set_hand([Card::from_index(20), Card::from_index(21)].into());
        table.seats[1].fixture_set_player([2; 20]);
        table.seats[1].set_stack(900).unwrap();
        table.seats[1].fixture_set_total_bet(100);
        table.seats[1].set_status(SeatStatus::AllIn);
        table.seats[1].fixture_set_hand([Card::from_index(30), Card::from_index(31)].into());
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];

        trigger_run_it_twice(&mut table, &mut events).unwrap();
        start_community_reveal_phase(&mut table, 1, ROUND_TURN, &mut events).unwrap();
        assert_eq!(
            table
                .reveal_assignments()
                .iter()
                .map(|assignment| assignment.encrypted_card_index)
                .collect::<Vec<_>>(),
            vec![7, 8]
        );

        complete_public_reveal_with_card_ids(&mut table, &[3, 4], &mut events);
        assert_eq!(table.round_state(), ROUND_RIVER);
        assert_eq!(
            table.community_cards,
            (0..=3).map(Card::from_index).collect::<Vec<_>>()
        );
        assert_eq!(
            table.run_it_twice_state.second_board_suffix(),
            &[Card::from_index(4)]
        );
        assert_eq!(
            table
                .reveal_assignments()
                .iter()
                .map(|assignment| assignment.encrypted_card_index)
                .collect::<Vec<_>>(),
            vec![9, 10]
        );

        complete_public_reveal_with_card_ids(&mut table, &[5, 6], &mut events);
        assert_eq!(table.round_state(), ROUND_SHOWDOWN);
        assert_eq!(
            table.community_cards,
            vec![
                Card::from_index(0),
                Card::from_index(1),
                Card::from_index(2),
                Card::from_index(3),
                Card::from_index(5),
            ]
        );
        assert_eq!(
            table.run_it_twice_state.second_board_suffix(),
            &[Card::from_index(4), Card::from_index(6)]
        );

        // The test preloads authenticated hole cards, so showdown has no remaining owner-token
        // assignments. Completion now stops at the canonical showdown-display deadline.
        assert!(table.reveal_assignments().is_empty());
        check_reveal_phase_complete(&mut table, 1_000, &mut events).unwrap();
        assert_eq!(table.round_state(), ROUND_SHOWDOWN);
        normalize_until_blocked(&mut table, 1_000, &mut events).unwrap();
        let deadline = 1_000 + u64::from(table.timeout_config.showdown_display_ms);
        let advanced = advance_deadline(&mut table, deadline, &mut events).unwrap();
        assert!(matches!(
            advanced,
            AdvanceDeadlineOutcome::Advanced {
                kind: DeadlineKind::ShowdownDisplay,
                ..
            }
        ));
        assert_eq!(table.round_state(), ROUND_WAITING);
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::SettlementPlanCommitted {
                runout_count: 2,
                gross_pot: 200,
                ..
            }
        )));
    }

    #[test]
    fn rit_reconstruct_restart_uses_fresh_indices_and_preserves_both_boards() {
        let mut table = make_table();
        set_initial_encrypted_deck(&mut table).unwrap();
        table.rit_mode = RIT_MODE_TWICE;
        table.community_cards =
            BoardCards::try_from((0..3).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        for seat_index in 0..2 {
            table.seats[seat_index].fixture_set_player([seat_index as u8 + 1; 20]);
            table.seats[seat_index].set_status(SeatStatus::AllIn);
        }
        table
            .enter_betting(ROUND_FLOP, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        let mut events = vec![];
        trigger_run_it_twice(&mut table, &mut events).unwrap();
        table.community_cards.try_push(Card::from_index(3)).unwrap();
        table
            .run_it_twice_state
            .second_board_suffix_mut()
            .unwrap()
            .try_push(Card::from_index(4))
            .unwrap();
        table
            .enter_betting(ROUND_RIVER, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();

        // `rebuild_deck_from_reconstruct_deck` resets only the new deck's index space.
        table.deck_state.cards_dealt = 0;
        restart_reveal_after_reconstruct(&mut table, &mut events).unwrap();

        assert_eq!(table.community_cards.len(), 4);
        assert_eq!(table.run_it_twice_state.second_board_len(), 4);
        assert_eq!(table.reveal_phase(), REVEAL_PHASE_RIVER);
        assert_eq!(table.reveal_assignments().len(), 2);
        assert_eq!(table.reveal_assignments()[0].encrypted_card_index, 0);
        assert_eq!(
            table.reveal_assignments()[0].target,
            RevealTarget::Board {
                runout_index: 0,
                board_position: 4
            }
        );
        assert_eq!(table.reveal_assignments()[1].encrypted_card_index, 1);
        assert_eq!(
            table.reveal_assignments()[1].target,
            RevealTarget::Board {
                runout_index: 1,
                board_position: 4
            }
        );
    }

    #[test]
    fn rit_reconstruct_restart_rejects_diverged_boards_atomically() {
        let mut table = make_table();
        table.rit_mode = RIT_MODE_TWICE;
        table
            .enter_betting(ROUND_RIVER, BettingRound::new(100, 100), NO_SEAT, 0)
            .unwrap();
        table.community_cards =
            BoardCards::try_from((0..4).map(Card::from_index).collect::<Vec<_>>()).unwrap();
        table.run_it_twice_state = RunItTwiceState::Twice {
            start: RitStartStreet::Flop,
            second_board_suffix: BoardCards::empty(),
        };
        let before = table.clone();
        let mut events = vec![];

        let error = restart_reveal_after_reconstruct(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("diverging lengths"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    fn complete_rit_showdown_table() -> TexasPokerTable {
        let mut table = make_table();
        table.enter_showdown_display(0);
        table.rit_mode = RIT_MODE_TWICE;
        table.run_it_twice_state = RunItTwiceState::Twice {
            start: RitStartStreet::Preflop,
            second_board_suffix: vec![
                Card::new(2, 13),
                Card::new(3, 13),
                Card::new(2, 3),
                Card::new(3, 5),
                Card::new(2, 7),
            ]
            .try_into()
            .unwrap(),
        };
        table.community_cards = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(3, 8),
            Card::new(2, 10),
        ]
        .try_into()
        .unwrap();
        table.pot = 200;
        table.chip_pool = 2_000;
        table.seats[0].fixture_set_player([1; 20]);
        table.seats[0].set_stack(900).unwrap();
        table.seats[0].fixture_set_total_bet(100);
        table.seats[0].set_status(SeatStatus::AllIn);
        table.seats[0].fixture_set_hand([Card::new(0, 14), Card::new(1, 14)].into());
        table.seats[1].fixture_set_player([2; 20]);
        table.seats[1].set_stack(900).unwrap();
        table.seats[1].fixture_set_total_bet(100);
        table.seats[1].set_status(SeatStatus::AllIn);
        table.seats[1].fixture_set_hand([Card::new(0, 13), Card::new(1, 13)].into());
        table
    }

    #[test]
    fn settle_hand_applies_two_runouts_and_resets_atomically() {
        let mut table = complete_rit_showdown_table();
        let mut events = vec![];

        settle_hand(&mut table, &mut events).unwrap();

        assert_eq!(table.round_state(), ROUND_WAITING);
        assert!(!table.run_it_twice_state.is_active());
        assert_eq!(table.seats[0].stack(), 1_000);
        assert_eq!(table.seats[1].stack(), 1_000);
        assert!(events.iter().any(|event| matches!(
            event,
            TexasPokerEvent::SettlementPlanCommitted {
                runout_count: 2,
                gross_pot: 200,
                rake: 0,
                total_awards: 200,
                ..
            }
        )));
    }

    #[test]
    fn settlement_reset_failure_leaves_table_and_events_unchanged() {
        let mut table = complete_rit_showdown_table();
        table.seats[0].set_pending_addon(u64::MAX).unwrap();
        table.seats[1].set_pending_addon(1).unwrap();
        let before = table.clone();
        let mut events = vec![];

        let error = settle_hand(&mut table, &mut events).unwrap_err();

        assert!(error.to_string().contains("pending_addon overflow"));
        assert_eq!(table, before);
        assert!(events.is_empty());
    }

    // ========== Redeal 协议 ==========

    /// 构造 preflop 下注轮 fixture：2 名活跃玩家、52 张加密牌组、cards_dealt=4、
    /// 两个账本条目（p0: deck[0]/deck[1]，p1: deck[2]/deck[3]）。
    fn preflop_betting_table_with_dealt_hands() -> TexasPokerTable {
        let mut table = make_table();
        table.seats[0].fixture_set_player([0x01; 20]);
        table.seats[0].set_stack(1_000).unwrap();
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([0x02; 20]);
        table.seats[1].set_stack(1_000).unwrap();
        table.seats[1].set_status(SeatStatus::Active);
        table.chip_pool = 2_000;
        set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.cards_dealt = 4;
        for (seat, slot, index) in [(0u8, 0u8, 0u8), (0, 1, 1), (1, 0, 2), (1, 1, 3)] {
            let ct = table.deck_state.encrypted[usize::from(index)];
            table
                .deck_state
                .owner_readable_hole_cards
                .insert(seat, slot, PartialHoleCard::new(index, ct, ct))
                .unwrap();
        }
        table
    }

    #[test]
    fn apply_redeal_hole_card_suspends_betting_restores_after_window() {
        let mut table = preflop_betting_table_with_dealt_hands();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];

        apply_redeal_hole_card(&mut table, 0, 0, 1_000, &mut events).unwrap();

        // 下注轮挂起进 Redealing，窗口恰好一个 assignment：pending = 活跃 & !牌主。
        let HandPhase::Redealing { street, .. } = &table.hand_phase else {
            panic!("hand phase must be Redealing after redeal");
        };
        assert_eq!(*street, ROUND_PREFLOP);
        let assignments = &table.reveal_token_state().unwrap().assignments;
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].encrypted_card_index, 4, "新牌取 deck 游标位");
        assert_eq!(assignments[0].pending_mask, 0b0010, "除牌主外全部活跃座位");
        assert_eq!(table.deck_state.cards_dealt, 5);
        // 账本换绑：新牌占位条目已写入（物化时被真实部分解密覆盖）。
        assert_eq!(
            table
                .deck_state
                .owner_readable_hole_cards
                .get(0, 0)
                .unwrap()
                .encrypted_card_index,
            4
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, TexasPokerEvent::HoleCardRedealt { .. }))
        );

        // p1 提交份额（测试态跳过证明验证）→ 窗口消化 → 下注轮原样恢复。
        let token = g1_generator();
        use poker_protocol::crypto::curve::CurveScalar as _;
        let sk = <poker_protocol::crypto::DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar::from_u64(1);
        let pk = g1_generator();
        let ct = table.deck_state.encrypted[4];
        let mut rng = StdRng::from_seed([7u8; 32]);
        let proof = RevealTokenProof::prove(
            &sk,
            &pk,
            &ct,
            &token,
            &mut rng,
            &mut PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
            ),
        );
        apply_submit_player_reveal_tokens(
            &mut table,
            1,
            vec![token],
            vec![proof],
            2_000,
            &mut events,
        )
        .unwrap();

        let HandPhase::Betting {
            street: restored_street,
            current_turn: restored_turn,
            ..
        } = &table.hand_phase
        else {
            panic!("hand phase must restore to Betting after the redeal window");
        };
        assert_eq!(*restored_street, ROUND_PREFLOP);
        assert_eq!(*restored_turn, 0, "挂起的行动者原样恢复");
        // 物化：partial = c2 − token（唯一他人份额）。
        let partial = table
            .deck_state
            .owner_readable_hole_cards
            .get(0, 0)
            .unwrap();
        assert_eq!(partial.encrypted_card_index, 4);
        assert_eq!(partial.ciphertext.c2, ct.c2 - token);
    }

    #[test]
    fn apply_redeal_hole_card_rejects_invalid_requests() {
        let mut events = vec![];

        // 非下注相位拒绝。
        let mut table = preflop_betting_table_with_dealt_hands();
        let error = apply_redeal_hole_card(&mut table, 0, 0, 1_000, &mut events).unwrap_err();
        assert!(error.to_string().contains("betting"));

        // 槽位越界拒绝。
        let mut table = preflop_betting_table_with_dealt_hands();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let error = apply_redeal_hole_card(&mut table, 0, 2, 1_000, &mut events).unwrap_err();
        assert!(error.to_string().contains("slot"));

        // 未发牌位（无账本条目）拒绝：p1 的槽 0 已有账本，换牌后槽位保留，
        // 这里用不存在的 deck 索引位：先清空一个槽再试。
        let mut table = preflop_betting_table_with_dealt_hands();
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        table
            .deck_state
            .owner_readable_hole_cards
            .remove(1, 1)
            .unwrap();
        let error = apply_redeal_hole_card(&mut table, 1, 1, 1_000, &mut events).unwrap_err();
        assert!(error.to_string().contains("no dealt partial"));
    }

    #[test]
    fn redeal_window_timeout_restores_betting() {
        let mut table = preflop_betting_table_with_dealt_hands();
        table.seats[2].fixture_set_player([0x03; 20]);
        table.seats[2].set_stack(1_000).unwrap();
        table.seats[2].set_status(SeatStatus::Active);
        table.chip_pool += 1_000;
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(100, 100), 0, 0)
            .unwrap();
        let mut events = vec![];
        apply_redeal_hole_card(&mut table, 0, 0, 1_000, &mut events).unwrap();
        let deadline = match &table.hand_phase {
            HandPhase::Redealing { deadline_ms, .. } => *deadline_ms,
            other => panic!("expected Redealing, got {other:?}"),
        };
        assert!(deadline > 1_000);

        // p1 已交份额，p2 超时：踢 p2 后恢复下注轮继续（而非 refund/reconstruct）。
        let token = g1_generator();
        use poker_protocol::crypto::curve::CurveScalar as _;
        let sk = <poker_protocol::crypto::DefaultCurve as poker_protocol::crypto::curve::Curve>::Scalar::from_u64(1);
        let pk = g1_generator();
        let ct = table.deck_state.encrypted[4];
        let mut rng = StdRng::from_seed([7u8; 32]);
        let proof = RevealTokenProof::prove(
            &sk,
            &pk,
            &ct,
            &token,
            &mut rng,
            &mut PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
            ),
        );
        apply_submit_player_reveal_tokens(
            &mut table,
            1,
            vec![token],
            vec![proof],
            deadline - 1,
            &mut events,
        )
        .unwrap();

        advance_deadline(&mut table, deadline + 1, &mut events).unwrap();
        assert!(matches!(table.hand_phase, HandPhase::Betting { .. }));
        assert!(
            !table.seats[2].is_occupied(),
            "timed-out pending seat is kicked"
        );
        assert!(table.seats[0].is_occupied() && table.seats[1].is_occupied());
    }
}
