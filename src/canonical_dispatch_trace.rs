//! 控制逻辑入 AIR（Stage 2）：dispatch 控制轨迹 → canonical witness 行链。
//!
//! [`crate::texas_canonical_air`] 的 canonical AIR 是 preimage→postimage 行
//! 约束——它逐行验证状态迁移关系，但要求**单街**粒度的行序列（一次收注
//! 一行、一次推街一行）。宿主 VM 的单次 dispatch 可能在 normalize 级联内
//! 连跳多条街（all-in runout），折叠成一对 pre/post 会违反单街收注投影
//! （PotCollected 分歧的根因）。本模块把 `texas/src/starknet/vm_session.rs`
//! 捕获的 [`DispatchRecord`]（命令 pre/post + 逐步 normalize pre/post）展开
//! 为 call_seq 连续、逐行咬合的 canonical 行链：
//!
//! - 命令行（Fold/Check/Call/Raise/Bet/SubmitReveal…）：pre = 命令应用前，
//!   post = 第一个**独立行** micro-step 的 pre（或 dispatch 终态）；
//! - 命令内联的协议完成级联（CompleteReveal——最终 reveal 提交触发的
//!   post_blinds + 开轮）并入 SubmitReveal 命令行，携带
//!   [`CanonicalProtocolCompletionKind::Reveal`] opening + 盲注 opening；
//! - `AdvanceBettingRound` micro-step → 独立 [`CanonicalTransitionKind::
//!   AdvanceRound`] 行（单街收注 + 推街 + board reveal 开窗 opening）；
//! - `EndWithoutShowdown` micro-step → 独立 EndWithoutShowdown 行。
//!
//! 状态镜像投影（[`project_state_image`]）是确定性的：协议承诺（deck/
//! rules）用 stage-0 权威推导（`canonical_shuffle_chain` /
//! `canonical_rake_opening`），其余承诺/根为域分隔摘要（AIR 绑定端点一致
//! 性而不重算，字节锚定由伴随 hash STARK 承担）。
//!
//! 密码学方程（BG shuffle / DLEQ / reveal token）维持 Plan D 边界——native
//! 验证，不入 AIR（`docs/STATUS.md`）。

use crate::canonical_rake_opening::CanonicalBlindOpening;
use crate::error::TexasAirResult;
use crate::texas_canonical::{
    CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment, CanonicalPhase,
    CanonicalProtocolCompletionKind, CanonicalProtocolCompletionOpening,
    CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use borsh::BorshDeserialize;
use poker_l1::contracts::texas_poker::state_machine::NormalizationStep;
use poker_l1::contracts::texas_poker::types::{
    HandPhase, RevealPurpose, RevealTarget, Seat, TexasPokerTable,
};

/// 一次 dispatch 的控制轨迹（texas `DispatchTrace` 的根 crate 镜像——
/// 避免根 crate 反向依赖 texas）。
pub struct DispatchRecord<'a> {
    /// dispatch 的方法 selector。
    pub selector: &'a [u8; 32],
    /// canonical Borsh 命令载荷（typed 解码 seat/amount/tokens）。
    pub args: &'a [u8],
    /// 认证时间戳（completion opening 依据）。
    pub timestamp_ms: u64,
    /// 命令应用前的表。
    pub pre: &'a TexasPokerTable,
    /// 命令 + 全部 normalize 之后的表。
    pub post: &'a TexasPokerTable,
    /// normalize 级联逐步轨迹。
    pub steps: Vec<StepRecord<'a>>,
}

/// 一个 normalize micro-step 的执行轨迹。
pub struct StepRecord<'a> {
    /// micro-step 种类。
    pub step: NormalizationStep,
    /// 该步应用前的表。
    pub pre: &'a TexasPokerTable,
    /// 该步应用后的表。
    pub post: &'a TexasPokerTable,
}

/// 摘要域分隔前缀（确定性承诺推导；AIR 绑定端点一致性，字节锚定由
/// 伴随 hash STARK 承担——stage-0 语义）。
const DOMAIN: &[u8] = b"zchain.texas.canonical-dispatch.v1";

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut preimage = DOMAIN.to_vec();
    for part in parts {
        preimage.extend_from_slice(&(part.len() as u64).to_be_bytes());
        preimage.extend_from_slice(part);
    }
    crate::blake3_flock::blake3_chain_digest(&preimage)
}

fn u64_bytes(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// 把 scope 分段拼接为单字节串（digest 的扁平输入）。
fn scope_concat(scope: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in scope {
        out.extend_from_slice(part);
    }
    out
}

/// selector → canonical kind（仅本生产者支持的行族；其余 fail-closed）。
fn kind_of_selector(selector: &[u8; 32]) -> Option<CanonicalTransitionKind> {
    use poker_l1::contracts::texas_poker::runtime::dispatch::selectors;
    if selector == &selectors::fold() {
        Some(CanonicalTransitionKind::Fold)
    } else if selector == &selectors::check() {
        Some(CanonicalTransitionKind::Check)
    } else if selector == &selectors::call() {
        Some(CanonicalTransitionKind::Call)
    } else if selector == &selectors::raise() {
        Some(CanonicalTransitionKind::Raise)
    } else if selector == &selectors::bet() {
        Some(CanonicalTransitionKind::Bet)
    } else if selector == &selectors::submit_player_reveal_tokens() {
        Some(CanonicalTransitionKind::SubmitReveal)
    } else {
        None
    }
}

/// VM 座位 → canonical 座位投影。
fn project_seat(seat: &Seat, acted: bool) -> CanonicalSeat {
    use poker_l1::contracts::texas_poker::types::PlayingSeatStatus;
    let (status, stack, bet, total_bet, pending_addon, time_bank_ms, player, hole): (
        CanonicalSeatStatus,
        u64,
        u64,
        u64,
        u64,
        u64,
        Option<&[u8; 20]>,
        Option<Vec<u8>>,
    ) = match seat {
        Seat::Vacant { time_bank_ms } => {
            return CanonicalSeat {
                status: CanonicalSeatStatus::Empty,
                acted: false,
                stack: 0,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: *time_bank_ms,
                identity_commitment: [0; 32],
                key_commitment: [0; 32],
                hole_cards_commitment: [0; 32],
            };
        }
        Seat::Waiting { occupied } => (
            CanonicalSeatStatus::Waiting,
            occupied.stack,
            0,
            0,
            occupied.pending_addon,
            u64::from(occupied.time_bank_ms),
            Some(&occupied.player),
            None,
        ),
        Seat::DepartedThisHand {
            player,
            total_bet,
            time_bank_ms,
        } => (
            CanonicalSeatStatus::Out,
            0,
            0,
            *total_bet,
            0,
            u64::from(*time_bank_ms),
            Some(player),
            None,
        ),
        Seat::Playing { playing } => {
            let status = match playing.status {
                PlayingSeatStatus::Active => CanonicalSeatStatus::Active,
                PlayingSeatStatus::Folded => CanonicalSeatStatus::Folded,
                PlayingSeatStatus::AllIn => CanonicalSeatStatus::AllIn,
            };
            (
                status,
                playing.occupied.stack,
                playing.bet,
                playing.total_bet,
                playing.occupied.pending_addon,
                u64::from(playing.occupied.time_bank_ms),
                Some(&playing.occupied.player),
                borsh::to_vec(&playing.hand).ok(),
            )
        }
    };
    let player_bytes: [u8; 20] = player.copied().unwrap_or([0; 20]);
    let identity = digest(&[b"identity", &player_bytes]);
    let hole_bytes: Vec<u8> = hole.unwrap_or_default();
    CanonicalSeat {
        status,
        acted,
        stack,
        bet,
        total_bet,
        pending_addon,
        time_bank_ms: u32::try_from(time_bank_ms).unwrap_or(u32::MAX),
        identity_commitment: identity,
        key_commitment: digest(&[b"key", &player_bytes]),
        hole_cards_commitment: if hole_bytes.is_empty() {
            [0; 32]
        } else {
            digest(&[b"hole", &hole_bytes])
        },
    }
}

/// 当前活动协议窗口的 pending 座位集（shuffle / reveal / redeal / reconstruct）。
fn protocol_pending_mask(table: &TexasPokerTable) -> u16 {
    match &table.hand_phase {
        HandPhase::Shuffling { phase } => match phase {
            poker_l1::contracts::texas_poker::types::ShufflingPhase::Initial { state, .. } => {
                state.pending_mask
            }
            poker_l1::contracts::texas_poker::types::ShufflingPhase::Reconstruct {
                state, ..
            } => state.pending_mask,
        },
        HandPhase::Revealing { state, .. } => state
            .assignments
            .iter()
            .fold(0u16, |acc, a| acc | a.pending_mask()),
        HandPhase::Redealing { state, .. } => state
            .assignments
            .iter()
            .fold(0u16, |acc, a| acc | a.pending_mask()),
        HandPhase::Reconstructing { state, .. } => state.pending_mask,
        _ => 0,
    }
}

/// VM 相位 → canonical (phase, subtag, street, current_turn, deadline)。
#[allow(clippy::type_complexity)]
fn project_phase(table: &TexasPokerTable) -> (CanonicalPhase, u8, u8, u8, u64) {
    use poker_l1::contracts::texas_poker::types::ShufflingPhase;
    match &table.hand_phase {
        HandPhase::Waiting => (CanonicalPhase::Waiting, 0, 0, NO_CANONICAL_SEAT, 0),
        HandPhase::Shuffling { phase } => match phase {
            ShufflingPhase::Initial { deadline_ms, .. } => (
                CanonicalPhase::Shuffling,
                1,
                0,
                NO_CANONICAL_SEAT,
                *deadline_ms,
            ),
            ShufflingPhase::Reconstruct {
                street,
                deadline_ms,
                ..
            } => (
                CanonicalPhase::Shuffling,
                2,
                street.saturating_sub(1),
                NO_CANONICAL_SEAT,
                *deadline_ms,
            ),
        },
        HandPhase::Revealing {
            street,
            state,
            deadline_ms,
        } => (
            CanonicalPhase::Revealing,
            // canonical subtag = reveal purpose 序数（DealHole=1/Board=2/
            // ShowdownOwner=3，对齐 AIR advance_round fixture）。
            state.purpose as u8,
            street.saturating_sub(1),
            NO_CANONICAL_SEAT,
            *deadline_ms,
        ),
        HandPhase::Redealing {
            street,
            state,
            deadline_ms,
            ..
        } => (
            CanonicalPhase::Redealing,
            // canonical subtag = reveal purpose 序数（RedealHole=4）。
            state.purpose as u8,
            street.saturating_sub(1),
            NO_CANONICAL_SEAT,
            *deadline_ms,
        ),
        HandPhase::Reconstructing {
            street,
            deadline_ms,
            ..
        } => (
            CanonicalPhase::Reconstructing,
            1,
            street.saturating_sub(1),
            NO_CANONICAL_SEAT,
            *deadline_ms,
        ),
        HandPhase::Betting {
            street,
            current_turn,
            deadline_ms,
            ..
        } => (
            CanonicalPhase::Betting,
            1,
            street.saturating_sub(1),
            *current_turn,
            *deadline_ms,
        ),
        HandPhase::ShowdownDisplay { deadline_ms } => (
            CanonicalPhase::ShowdownDisplay,
            1,
            // 摊牌窗口（canonical street 5）完成后的展示期，street 保持 5。
            5,
            NO_CANONICAL_SEAT,
            *deadline_ms,
        ),
    }
}

/// VM 表 → canonical 状态镜像（确定性投影）。
///
/// # Errors
/// deck 承诺推导失败（非法牌组形状）时返回错误。
pub fn project_state_image(
    table: &TexasPokerTable,
    table_id: u64,
) -> TexasAirResult<CanonicalStateImage> {
    let (phase, subtag, street, current_turn, deadline_ms) = project_phase(table);
    let tc = &table.rules.timeout_config;
    let seats: [CanonicalSeat; MAX_CANONICAL_SEATS] = core::array::from_fn(|index| {
        table
            .seats
            .get(index)
            .map(|s| project_seat(s, table.acted_mask & (1u16 << index) != 0))
            .unwrap_or(CanonicalSeat::EMPTY)
    });
    let hand_id_bytes = u64_bytes(u64::from(table.hand_id));
    let deck_commitment = match &table.deck_state.encrypted {
        poker_l1::contracts::texas_poker::types::CipherDeck::Active(cards) => {
            crate::canonical_shuffle_chain::canonical_deck_commitment(cards.as_slice())?
        }
        _ => [0; 32],
    };
    let board_bytes: Vec<u8> = borsh::to_vec(&table.community_cards).unwrap_or_default();
    let call_seq_bytes = u64_bytes(u64::from(table.call_seq));
    // 行级 scope（随 call_seq 演化）与手级 scope（批内不变——governance/
    // settlement/custody 是跨行 immutable 承诺族，AIR 禁止其跨行变化）。
    let scope_hand = [&u64_bytes(table_id)[..], &hand_id_bytes[..]];
    let scope_hand_flat = scope_concat(&scope_hand);
    let _ = call_seq_bytes;
    Ok(CanonicalStateImage {
        abi_version: CANONICAL_ABI_VERSION,
        table_id,
        hand_id: table.hand_id,
        call_seq: table.call_seq,
        phase,
        phase_subtag: subtag,
        street,
        current_turn,
        deadline_ms,
        shuffle_timeout_ms: tc.shuffle_timeout_ms,
        reveal_timeout_ms: tc.reveal_timeout_ms,
        betting_timeout_ms: tc.betting_timeout_ms,
        reconstruct_timeout_ms: tc.reconstruct_timeout_ms,
        showdown_display_ms: tc.showdown_display_ms,
        // 下注价仅在 Betting 相位携带；其它相位（Revealing 等）投影为零
        //（canonical AdvanceRound 行要求 post 清空已完成轮的下注价）。
        current_bet: table
            .betting_round()
            .map(|round| round.current_bet)
            .unwrap_or(0),
        min_raise: table
            .betting_round()
            .map(|round| round.min_raise)
            .unwrap_or(0),
        chip_pool: table.chip_pool,
        pot: table.pot,
        button: table.button,
        last_bb_seat: table.last_bb_seat,
        max_players: table.rules.max_players,
        acted_mask: table.acted_mask,
        leave_after_hand_mask: table.leave_after_hand_mask,
        protocol_pending_mask: protocol_pending_mask(table),
        board_cards_commitment: digest(&[b"board", &board_bytes]),
        deck_commitment,
        // reveal 承诺在非最终提交行必须不变（crypto 行白名单不含它）——
        // 投影绑定手级 + 已物化公共牌；完成行的承诺轮转（防重放）由
        // 后续 postflop-completion 扩写接管（docs/STATUS.md Stage 2）。
        reveal_commitment: digest(&[b"reveal", scope_hand_flat.as_slice(), &board_bytes]),
        reconstruction_commitment: digest(&[b"reconstruct", scope_hand_flat.as_slice()]),
        run_it_twice_commitment: digest(&[b"rit", scope_hand_flat.as_slice()]),
        rules_commitment: crate::canonical_rake_opening::canonical_rules_commitment(&table.rules)?,
        governance_commitment: digest(&[b"governance", scope_hand_flat.as_slice()]),
        settlement_commitment: digest(&[b"settlement", scope_hand_flat.as_slice()]),
        custody_commitment: digest(&[
            b"custody",
            scope_hand_flat.as_slice(),
            &u64_bytes(table.chip_pool),
        ]),
        lifecycle_root: digest(&[b"lifecycle", scope_hand_flat.as_slice()]),
        overlay_root: digest(&[b"overlay", scope_hand_flat.as_slice()]),
        state_root: digest(&[b"state-root", scope_hand_flat.as_slice()]),
        seats,
    })
}

/// 行端点 deadline 修复：VM 在 dispatch 级 disarm/re-arm deadline，
/// micro-step 快照（命令 post / 完成边界 / advance 端点）常携带 0——
/// canonical 镜像恒要求 active phase 携带绝对 deadline。回填来源由
/// 调用方按链上连续性选择：上一 canonical 行的 post（链上权威）、
/// dispatch 终态（re-arm 后）或 canonical 公式值（完成行）。
fn repair_deadline(image: &mut CanonicalStateImage, fallback_deadline_ms: u64) {
    if image.phase != CanonicalPhase::Waiting && image.deadline_ms == 0 {
        image.deadline_ms = fallback_deadline_ms;
    }
}

/// seat 参与集合（Playing 且非 Waiting；镜像 canonical 的参与语义）。
fn participating_seats(table: &TexasPokerTable) -> Vec<u8> {
    table
        .seats
        .iter()
        .enumerate()
        .filter(|(index, seat)| {
            matches!(seat, Seat::Playing { .. }) && usize::from(table.rules.max_players) > *index
        })
        .map(|(index, _)| index as u8)
        .collect()
}

/// dead button 盲注定位（镜像 validator / VM post_blinds §4.2b）。
fn blind_seats(pre: &TexasPokerTable) -> (bool, u8, u8) {
    let participants = participating_seats(pre);
    let heads_up = participants.len() == 2;
    if participants.is_empty() {
        return (heads_up, NO_CANONICAL_SEAT, NO_CANONICAL_SEAT);
    }
    let rotation_base = if pre.last_bb_seat != NO_SEAT_RAW {
        pre.last_bb_seat
    } else {
        pre.button
    };
    let max = pre.rules.max_players;
    let next_participating = |from: u8| -> Option<u8> {
        (1..=usize::from(max))
            .map(|offset| (usize::from(from) + offset) % usize::from(max))
            .find(|index| participants.contains(&(*index as u8)))
            .map(|index| index as u8)
    };
    let bb = next_participating(rotation_base).unwrap_or(rotation_base);
    let sb = if heads_up {
        next_participating(bb).unwrap_or(bb)
    } else {
        let base_participating = participants.contains(&rotation_base);
        if rotation_base != bb && base_participating {
            rotation_base
        } else {
            NO_CANONICAL_SEAT
        }
    };
    (heads_up, sb, bb)
}

const NO_SEAT_RAW: u8 = NO_CANONICAL_SEAT;

/// Reveal 完成级联的 canonical opening（并入最终 SubmitReveal 命令行）。
/// kind 由 pre 窗口语义决定（镜像 validator 的三个开局面关系）：
/// DealHole → [`CanonicalProtocolCompletionKind::Reveal`]（preflop 盲注
/// 开局）；Board(street≥2) → `RevealStreet`（同街下注开局，BB 通道 =
/// opening.bb_amount）；ShowdownOwner → `Showdown`（摊牌展示期）。
#[allow(clippy::too_many_arguments)]
fn reveal_completion_opening(
    pre_image: &CanonicalStateImage,
    post_image: &CanonicalStateImage,
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
    timestamp_ms: u64,
) -> CanonicalProtocolCompletionOpening {
    let _ = post;
    let mut opening = CanonicalProtocolCompletionOpening {
        kind: CanonicalProtocolCompletionKind::Reveal,
        completion_timestamp_ms: timestamp_ms,
        pre_cards_dealt: 0,
        post_cards_dealt: 0,
        post_shuffle_pending_mask: 0,
        post_shuffle_completed_mask: 0,
        suspended_reveal_commitment: [0; 32],
        post_current_turn: post_image.current_turn,
        sb_seat: NO_SEAT_RAW,
        bb_seat: NO_SEAT_RAW,
        sb_amount: 0,
        bb_amount: 0,
        is_heads_up: false,
        pre_reveal_commitment: pre_image.reveal_commitment,
        post_reveal_commitment: post_image.reveal_commitment,
        pre_deck_commitment: pre_image.deck_commitment,
        post_deck_commitment: post_image.deck_commitment,
        pre_reconstruction_commitment: pre_image.reconstruction_commitment,
        post_reconstruction_commitment: post_image.reconstruction_commitment,
    };
    // 窗口语义按 purpose 分类（VM street 编号含翻前 HandReveal 窗口，
    // 与 canonical street 错位一位——purpose 才是窗口类型的权威）。
    let window_purpose = match &pre.hand_phase {
        HandPhase::Revealing { state, .. } => Some(state.purpose),
        _ => None,
    };
    match window_purpose {
        Some(RevealPurpose::Board) => {
            // 同街下注开局：min_raise = BB，经 opening.bb_amount 通道
            // 与公开 blind scope（companion rules proof）锚定。
            opening.kind = CanonicalProtocolCompletionKind::RevealStreet;
            opening.bb_amount = post_image.min_raise;
            return opening;
        }
        Some(RevealPurpose::ShowdownOwner) => {
            opening.kind = CanonicalProtocolCompletionKind::Showdown;
            return opening;
        }
        _ => {}
    }
    let (is_heads_up, sb_seat, bb_seat) = blind_seats(pre);
    let seat_amount = |seat: u8| -> u64 {
        if seat == NO_SEAT_RAW {
            0
        } else {
            post.seats[usize::from(seat)].bet()
        }
    };
    opening.sb_seat = sb_seat;
    opening.bb_seat = bb_seat;
    opening.sb_amount = seat_amount(sb_seat);
    opening.bb_amount = seat_amount(bb_seat);
    opening.is_heads_up = is_heads_up;
    opening
}

/// AdvanceRound 行的 board-reveal 开窗 opening（单街收注 → 开下一窗口）。
fn round_advance_opening(
    pre: &TexasPokerTable,
    post: &TexasPokerTable,
) -> CanonicalRoundAdvanceOpening {
    let mut opening = CanonicalRoundAdvanceOpening {
        pre_cards_dealt: pre.deck_state.cards_dealt,
        post_cards_dealt: post.deck_state.cards_dealt,
        pre_board_len: pre.community_cards.len() as u8,
        post_board_len: post.community_cards.len() as u8,
        pre_second_board_len: 0,
        post_second_board_len: 0,
        run_it_twice: false,
        reveal_purpose: 0,
        assignment_count: 0,
        assignments: [CanonicalBoardRevealAssignment::EMPTY;
            MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS],
    };
    if let HandPhase::Revealing { state, .. } = &post.hand_phase {
        match state.purpose {
            RevealPurpose::Board => {
                opening.reveal_purpose = 2;
                for (slot, assignment) in state.assignments.iter().enumerate() {
                    if slot >= MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS {
                        break;
                    }
                    let RevealTarget::Board { board_position, .. } = assignment.target else {
                        continue;
                    };
                    opening.assignments[slot] = CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: assignment.encrypted_card_index,
                        runout_index: 0,
                        board_position,
                        pending_mask: assignment.pending_mask(),
                        submitted_mask: assignment.submitted_mask,
                    };
                    opening.assignment_count += 1;
                }
            }
            // 摊牌窗口：openings 不携带 hole 槽位（AIR 摊牌 profile 钉
            // count=0，窗口逐座 token 的 pending 演化由状态镜像掩码承担）。
            RevealPurpose::ShowdownOwner => {
                opening.reveal_purpose = 3;
            }
            _ => {}
        }
    }
    opening
}

/// 控制轨迹 → canonical witness 行链（call_seq 连续、逐行咬合）。
///
/// # Errors
/// 不支持的 selector（密码学提交行族由 stage-0 链另行生产）或行链不咬合
/// 时返回错误（fail-closed）。
pub fn witnesses_from_dispatch_records(
    records: &[DispatchRecord<'_>],
    table_id: u64,
) -> TexasAirResult<Vec<CanonicalTransitionWitness>> {
    let mut witnesses = Vec::new();
    let mut call_seq: u32 = records
        .first()
        .map(|record| record.pre.call_seq)
        .unwrap_or(0);
    // 上一 canonical 行 post 的 deadline（disarm/re-arm 修复的链上权威源）。
    let mut last_post_deadline: Option<u64> = None;
    for record in records {
        let kind = kind_of_selector(record.selector).ok_or_else(|| {
            crate::error::TexasAirError::SpecViolation(
                "dispatch trace contains a selector outside the supported row families \
                 (crypto submissions are produced by the stage-0 chain)"
                    .into(),
            )
        })?;
        let mut steps = record.steps.iter().peekable();
        // 命令内联协议完成级联（CompleteReveal 并入 SubmitReveal 命令行）。
        // 完成级联内的即时 all-in runout 会把 AdvanceBettingRound 记录在
        // CompleteReveal **之前**（边界快照先于 start_betting_round 打好，
        // 收注/推街在开轮内即时执行）：此时完成行的真实 post = 该 advance
        // step 的 pre（边界下注轮），advance step 本身仍作为独立行跟随。
        // 不存在该模式时完成行 post = dispatch 终态（deadline re-arm 后的
        // 开轮/展示期）。trace 最后一步的 post 已被 patch 成 dispatch 终态，
        // 因此完成行 post 必须取自 advance.pre 而非 step.post。
        let completion_idx = if kind == CanonicalTransitionKind::SubmitReveal {
            let found = record
                .steps
                .iter()
                .position(|step| step.step == NormalizationStep::CompleteReveal);
            match found {
                None | Some(0) => found,
                Some(1) if record.steps[0].step == NormalizationStep::AdvanceBettingRound => found,
                Some(other) => {
                    return Err(crate::error::TexasAirError::SpecViolation(format!(
                        "unsupported completion cascade shape (CompleteReveal at step {other})"
                    )));
                }
            }
        } else {
            None
        };
        let mut completion: Option<CanonicalProtocolCompletionOpening> = None;
        let mut consumed_completion_step = false;
        let mut completion_post: Option<&TexasPokerTable> = None;
        if let Some(k) = completion_idx {
            completion_post = if k == 1 {
                Some(record.steps[0].pre)
            } else {
                None
            };
            let pre_image = project_state_image(record.pre, table_id)?;
            let post_table = completion_post.unwrap_or(record.post);
            let post_image = project_state_image(post_table, table_id)?;
            completion = Some(reveal_completion_opening(
                &pre_image,
                &post_image,
                record.pre,
                post_table,
                record.timestamp_ms,
            ));
            consumed_completion_step = true;
        }
        // 命令行 post：完成行 = 完成真实 post；无完成 = 第一个独立行 step
        // 的 pre（或 dispatch 终态）。
        let cmd_post: &TexasPokerTable = {
            if let Some(post) = completion_post {
                post
            } else if consumed_completion_step {
                record.post
            } else {
                steps.peek().map(|s| s.pre).unwrap_or(record.post)
            }
        };
        let armed_deadline = project_state_image(record.pre, table_id)?.deadline_ms;
        let dispatch_end_deadline = project_state_image(record.post, table_id)?.deadline_ms;
        let mut pre_image = project_state_image(record.pre, table_id)?;
        let mut post_image = project_state_image(cmd_post, table_id)?;
        repair_deadline(&mut pre_image, last_post_deadline.unwrap_or(armed_deadline));
        if let Some(opening) = completion.as_ref() {
            // 完成行 post deadline = canonical 公式值（validator 同式：
            // ts + betting_timeout / showdown_display_ms）。
            let timeout = match opening.kind {
                CanonicalProtocolCompletionKind::Showdown => {
                    u64::from(pre_image.showdown_display_ms)
                }
                _ => u64::from(pre_image.betting_timeout_ms),
            };
            post_image.deadline_ms = opening.completion_timestamp_ms.saturating_add(timeout);
        } else {
            repair_deadline(&mut post_image, dispatch_end_deadline);
        }
        // 行链权威重编：VM 快照的 call_seq 是 dispatch 级别（micro-step 不
        // 占外部调用序号），canonical 行的 call_seq 按行序连续递增。
        pre_image.call_seq = call_seq;
        post_image.call_seq = call_seq.wrapping_add(1);
        if let Some(completion) = completion.as_mut() {
            completion.post_reveal_commitment = post_image.reveal_commitment;
            completion.post_deck_commitment = post_image.deck_commitment;
            completion.post_reconstruction_commitment = post_image.reconstruction_commitment;
        }
        let actor = actor_bytes(record, kind);
        let mut witness = CanonicalTransitionWitness {
            pre: pre_image,
            post: post_image,
            kind,
            actor,
            action: command_action(record, kind)?,
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: completion.unwrap_or_default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            blind_opening: if consumed_completion_step {
                crate::canonical_rake_opening::blind_opening_of(&record.pre.rules)
            } else {
                CanonicalBlindOpening::ZERO
            },
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        last_post_deadline = Some(witness.post.deadline_ms);
        witnesses.push(witness);
        call_seq += 1;
        // 独立行 micro-steps（跳过已内联的 CompleteReveal；完成级联内的
        // runout advance step 的 pre 与命令行 post 咬合）。
        for (idx, step) in record.steps.iter().enumerate() {
            if Some(idx) == completion_idx {
                continue;
            }
            let (kind, opening) = match step.step {
                NormalizationStep::AdvanceBettingRound => (
                    CanonicalTransitionKind::AdvanceRound,
                    round_advance_opening(step.pre, step.post),
                ),
                NormalizationStep::EndWithoutShowdown => (
                    CanonicalTransitionKind::EndWithoutShowdown,
                    Default::default(),
                ),
                other => {
                    return Err(crate::error::TexasAirError::SpecViolation(format!(
                        "unmodeled normalization step {other:?} after the command row \
                             (protocol completions must be inlined into the command row)"
                    )));
                }
            };
            let mut pre_image = project_state_image(step.pre, table_id)?;
            let mut post_image = project_state_image(step.post, table_id)?;
            repair_deadline(&mut pre_image, last_post_deadline.unwrap_or(armed_deadline));
            repair_deadline(&mut post_image, dispatch_end_deadline);
            pre_image.call_seq = call_seq;
            post_image.call_seq = call_seq.wrapping_add(1);
            let mut witness = CanonicalTransitionWitness {
                pre: pre_image,
                post: post_image,
                kind,
                actor: [0; 32], // permissionless
                action: CanonicalActionPayload {
                    // seatless 行的 canonical 哨兵（validator 强制 NO_SEAT）。
                    seat: NO_CANONICAL_SEAT,
                    amount: 0,
                    auxiliary: 0,
                    flag: false,
                    proof_commitment: [0; 32],
                },
                round_advance: opening,
                protocol_completion: CanonicalProtocolCompletionOpening::default(),
                rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
                blind_opening: CanonicalBlindOpening::ZERO,
                transition_commitment: [0; 32],
                nullifier: [0; 32],
                deadline_height: 0,
            };
            witness.seal();
            last_post_deadline = Some(witness.post.deadline_ms);
            witnesses.push(witness);
            call_seq += 1;
        }
    }
    Ok(witnesses)
}

/// 命令行 actor（32B：座位地址右对齐；permissionless 行为零）。
fn actor_bytes(record: &DispatchRecord<'_>, kind: CanonicalTransitionKind) -> [u8; 32] {
    if kind.permissionless() {
        return [0; 32];
    }
    let seat = command_seat(record, kind);
    let player = record
        .pre
        .seats
        .get(usize::from(seat))
        .map(poker_l1::contracts::texas_poker::types::Seat::player);
    // Seat::player 返回 Address（Vacant 时 EMPTY_PLAYER 哨兵）。
    if let Some(player) = player {
        if player != poker_l1::contracts::texas_poker::types::EMPTY_PLAYER {
            let mut actor = [0u8; 32];
            actor[12..].copy_from_slice(&player);
            return actor;
        }
    }
    [0; 32]
}

/// 命令的目标座位（selector 语义：SeatIndexArgs / RaiseArgs 的 seat_index）。
fn command_seat(record: &DispatchRecord<'_>, kind: CanonicalTransitionKind) -> u8 {
    use poker_l1::contracts::texas_poker::dispatch::{
        RaiseArgs, SeatIndexArgs, SubmitRevealTokensArgs,
    };
    if let Ok(args) = <SeatIndexArgs as BorshDeserialize>::try_from_slice(record.args) {
        return args.seat_index;
    }
    if let Ok(args) = <RaiseArgs as BorshDeserialize>::try_from_slice(record.args) {
        return args.seat_index;
    }
    if let Ok(args) = <SubmitRevealTokensArgs as BorshDeserialize>::try_from_slice(record.args) {
        return args.seat_index;
    }
    let _ = kind;
    0
}

/// 命令行 action 载荷（seat + 经济数量 + 密码承诺锚）。
fn command_action(
    record: &DispatchRecord<'_>,
    kind: CanonicalTransitionKind,
) -> TexasAirResult<CanonicalActionPayload> {
    use poker_l1::contracts::texas_poker::dispatch::{RaiseArgs, SubmitRevealTokensArgs};
    let seat = command_seat(record, kind);
    let amount = match kind {
        CanonicalTransitionKind::Raise => {
            <RaiseArgs as BorshDeserialize>::try_from_slice(record.args)
                .ok()
                .map(|args| args.total_bet)
                .unwrap_or(0)
        }
        CanonicalTransitionKind::Call => {
            // canonical Call 语义：amount = 跟注增量 = min(owed, stack)
            //（validator 的逐分资金关系要求精确增量）。
            let round = record.pre.betting_round();
            let playing = match record.pre.seats.get(usize::from(seat)) {
                Some(Seat::Playing { playing }) => Some(playing),
                _ => None,
            };
            match (round, playing) {
                (Some(round), Some(playing)) => round
                    .current_bet
                    .saturating_sub(playing.bet)
                    .min(playing.occupied.stack),
                _ => 0,
            }
        }
        _ => 0,
    };
    let proof_commitment = match kind {
        CanonicalTransitionKind::SubmitReveal => {
            // 密码承诺锚：reveal token 集合摘要（native 通道的公开绑定）。
            match <SubmitRevealTokensArgs as BorshDeserialize>::try_from_slice(record.args) {
                Ok(args) => {
                    let material = borsh::to_vec(&args.reveal_tokens).unwrap_or_default();
                    digest(&[b"proof", &material])
                }
                Err(_) => [0; 32],
            }
        }
        kind if kind.carries_crypto_proof() => digest(&[b"args", record.args]),
        _ => [0; 32],
    };
    Ok(CanonicalActionPayload {
        seat,
        amount,
        auxiliary: 0,
        flag: false,
        proof_commitment,
    })
}
