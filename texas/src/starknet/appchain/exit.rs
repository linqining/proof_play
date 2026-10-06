//! B6：结算出口——`SettlementExit::{Starknet, Appchain}` 路由与 Appchain
//! 出口的完整落地（镜像 → SettlementPlan/SettlementRecord → 嵌入式
//! sequencer → ProofPipeline → 批次/水位）。
//!
//! ## 路由（配置 `STARKNET_SETTLEMENT_EXIT`，默认 `appchain` 供 dev）
//!
//! - [`SettlementExit::Appchain`]（默认）：hooks 终局对账通过后进入
//!   [`settle_from_mirror`]；任何一步失败（手型不支持/REAL 无归档/账本
//!   不齐/出证超时）→ Err，由 hooks 回退 **Starknet 遗留路径**（保留可配，
//!   结算绝不因出口改造丢失）。
//! - [`SettlementExit::Starknet`]：hooks 原路径（submit.rs calldata 提交），
//!   行为与改造前逐字节一致。
//!
//! ## 手牌叙事 → 链上操作映射（嵌入式 v1 模型）
//!
//! 手牌开始时未镜像买入（客户端 P 层密钥协议是 v2 升级项，见 keys 模块
//! 信任模型），结算时按 HandStart 参与者惰性补齐账本事实：
//!
//! 1. `OpenTable`（未开过时；费率 = 游戏/镜像同源 rake 参数 + 嵌入式
//!    treasury/operator 托管钥）；
//! 2. 每参与者：`Deposit`（PLAY 即铸，REAL 须已有存款桥铸出的余额）→
//!    `BuyIn`（stack 面额 seat note）→ `Transfer`（seat 拆为
//!    `total_bet` 面额 seat + 余款回余额——settle 关系要求
//!    Σinputs == plan.gross_pot == Σ终局投入）；
//! 3. `Settle`（plan 由 `poker_settlement_core::derive_settlement_plan`
//!    从镜像 pre-payout 快照派生；`plan.gross_pot` 必须等于镜像 pot；
//!    rake 与游戏层 `rake_collected` 逐分对账）；
//! 4. 出证：PLAY = host attestation（无归档）；REAL = 本地 prover 完整
//!    STARK 验证（需 canonical 归档——由调用方经 `hand_proof` 提供，
//!    生产归档生产者是既有残余边界，见 BLOCKERS B6 记录）。
//!
//! 每一步的软确认经 [`super::runtime::emit_soft_confirm`] 广播
//! `SOFT_CONFIRM` 事件（level=soft），批次出证后推 level=proven。

use poker_appchain::fee::FeePolicy;
use poker_appchain::keys::spend_digest;
use poker_appchain::note::{AssetClass, NoteSpec};
use poker_appchain::ops::scope;
use poker_appchain::ops::Operation;
use poker_appchain::pipeline::Priority;
use poker_appchain::settlement::{
    rake_outputs, settle_effect, settle_spend_scope, validate_settlement, HandProofBinding,
    RakeSplitRecord, SettleInput, SettlementRecord, SpendAuth,
};
use poker_settlement_core::{
    derive_settlement_plan, SettlementBoards, TableSnapshot, SettlementPlan, SETTLEMENT_SEATS,
};

use super::runtime::AppchainRuntime;

use std::sync::Arc;

/// 结算出口（`STARKNET_SETTLEMENT_EXIT`）。
///
/// - `Appchain`（默认，dev）：嵌入式 sequencer 软确认链 + 本地出证；
/// - `Starknet`：遗留路径（register_aggregate/settle_hand calldata 提交），
///   保留可配——回退目标与生产行为不变。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SettlementExit {
    /// 嵌入式 appchain 出口（默认，devnet/dev 语义）。
    #[default]
    Appchain,
    /// 遗留 Starknet 提交路径（行为与改造前一致）。
    Starknet,
}

impl SettlementExit {
    /// 大小写不敏感解析；空/未知回默认 Appchain（dev 语义）。
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "starknet" | "legacy" => Self::Starknet,
            _ => Self::Appchain,
        }
    }
}

/// Appchain 出口结算回执。
#[derive(Debug, Clone)]
pub struct AppchainSettleReceipt {
    /// settle 操作的帧链序号（proven 水位推进依据）。
    pub settle_op_index: u64,
    /// 手绑定（REAL = 归档 batch_digest；PLAY = 派生域摘要）。
    /// bin 构建当前无读取方（观测/审计字段 + 场景测试断言）。
    #[allow(dead_code)]
    pub hand_binding: [u8; 32],
    /// 出证是否已落批（水位覆盖）；false = 软确认态、出证异步继续。
    pub proven: bool,
    /// 覆盖本手的批次根（proven 时 Some）。
    pub batch_root: Option<[u8; 32]>,
}

/// 镜像 pre-payout 快照 → poker_settlement_core 计划派生的输入投影。
pub(super) struct MirrorProjection {
    pub(super) snapshot: TableSnapshot<'static>,
    pub(super) boards: SettlementBoards,
    /// 参与者：(镜像座位号, 钱包 felt 32B, 终局投入 total_bet, 手牌起 stack)。
    pub(super) participants: Vec<(usize, [u8; 32], u64, u64)>,
    /// 镜像 pot（pre-payout 快照）——gross_pot 口径对账锚（REAL 路径还被
    /// 归档 scope 镜像 pot@74 逐字节绑定复核）。
    pub(super) mirror_pot: u64,
}

/// 出口入口：从终局镜像结算（hooks Appchain 分支调用）。
///
/// `hand_proof`：REAL 结算的 canonical 归档绑定（无归档的 REAL 手在本
/// 出口拒绝——出证策略 fail-closed，调用方回退遗留路径）。
///
/// # Errors
/// 手型不支持（fold-win/未 river）/ 计划派生失败 / 账本补齐失败 /
/// 结算校验失败 / 出证超时——全部文本错误，语义上"该手不可走 Appchain
/// 出口"，调用方应回退遗留路径。
pub fn settle_from_mirror(
    mirror: &super::super::vm_session::VmTable,
    table_id: u32,
    hand_id: u32,
    participants: &[super::super::prove_log::HandParticipant],
    rake_collected: u64,
    hand_proof: Option<HandProofBinding>,
) -> Result<AppchainSettleReceipt, String> {
    let rt = super::runtime::runtime().ok_or("appchain runtime not initialized")?;
    let asset_class = rt.config.asset_class;
    if asset_class == AssetClass::Real && hand_proof.is_none() {
        return Err(
            "REAL settlement requires canonical archive (hand_proof); no producer wired — \
             falling back to legacy"
                .into(),
        );
    }

    // 1. 镜像 pre-payout 快照选择（与 submit::settle_hand 同一语义）。
    //    fold-win 快照副本须与 settle_table 同生命周期（借用存在其中）。
    let fold_snapshot = mirror
        .pre_settlement_final_fold
        .zip(mirror.pre_settlement.as_ref())
        .map(|(seat, snap)| super::super::submit::apply_pending_final_fold(snap, seat));
    let settle_table = match fold_snapshot.as_ref() {
        Some(snap) => snap,
        None => mirror.pre_settlement.as_ref().unwrap_or(&mirror.table),
    };

    // 2. 结算计划派生（poker_settlement_core——结算语义唯一事实源）。
    let projection = project_snapshot(settle_table, participants)?;
    settle_from_projection(rt, table_id, hand_id, projection, rake_collected, hand_proof)
}

/// 投影驱动的结算落地（[`settle_from_mirror`] 的后半段；测试直接构造
/// 投影驱动同一管线——canonical witness 场景无法经游戏层镜像表达）。
pub(super) fn settle_from_projection(
    rt: &'static Arc<AppchainRuntime>,
    table_id: u32,
    hand_id: u32,
    projection: MirrorProjection,
    rake_collected: u64,
    hand_proof: Option<HandProofBinding>,
) -> Result<AppchainSettleReceipt, String> {
    let asset_class = rt.config.asset_class;
    if asset_class == AssetClass::Real && hand_proof.is_none() {
        return Err(
            "REAL settlement requires canonical archive (hand_proof); no producer wired — \
             falling back to legacy"
                .into(),
        );
    }
    let plan = derive_settlement_plan(&projection.snapshot, &projection.boards)
        .map_err(|e| format!("settlement-core derive failed: {e}"))?;
    // 口径对账：镜像 pot（派奖前快照）== plan.gross_pot == Σ终局投入；
    // REAL 路径该值还会被归档 scope 的镜像 pot@74 逐字节绑定复核。
    if plan.gross_pot != projection.mirror_pot {
        return Err(format!(
            "mirror pot mismatch: plan gross_pot {} vs mirror pot {}",
            plan.gross_pot, projection.mirror_pot
        ));
    }
    if plan.rake != rake_collected {
        return Err(format!(
            "rake mismatch: settlement-core plan {} vs game layer {rake_collected}",
            plan.rake
        ));
    }

    // 3. 账本事实补齐（开桌 + 存入/买入/拆分 seat）。
    let table_id_u64 = u64::from(table_id);
    let policy = rt.fee_policy();
    ensure_table(rt, table_id_u64, policy)?;
    let seats = ensure_seats(rt, table_id_u64, asset_class, &projection, hand_id)?;

    // 4. 手绑定：REAL = 归档 batch_digest（防重放锚，与 zchain e2e 同
    //    模式）；PLAY = 域派生摘要。
    let hand_binding = archive_digest(hand_proof.as_ref())
        .unwrap_or_else(|| hand_binding_derived(table_id, hand_id));

    // 5. 结算记录（plan 投影顺序构造 payouts → rake 分账 → 签名）。
    let record = build_record(
        table_id_u64,
        hand_binding,
        &plan,
        &seats,
        &projection,
        policy,
        hand_proof.clone(),
    )?;
    validate_settlement(&record, &policy)
        .map_err(|e| format!("settlement record invalid: {e}"))?;

    // 6. 软确认提交 + 出证。
    let frame = rt
        .submit_operation(Operation::Settle(Box::new(record.clone())))
        .map_err(|e| format!("sequencer settle rejected: {e}"))?;
    rt.pipeline
        .submit(poker_appchain::pipeline::ProofJob {
            op_index: frame.frame.index,
            table_id: table_id_u64,
            record: std::sync::Arc::new(record),
            policy,
            priority: match asset_class {
                AssetClass::Real => Priority::Real,
                AssetClass::Play => Priority::Play,
            },
        })
        .map_err(|e| format!("pipeline submit rejected: {e}"))?;
    let proven = rt.await_proven(frame.frame.index, rt.prove_timeout()).is_ok();
    let batch_root = if proven {
        rt.with_seq(|seq| seq.batch_covered_through())
            .filter(|t| *t >= frame.frame.index)
            .and_then(|t| rt.with_seq(|seq| seq.batch_root_at(t)))
    } else {
        tracing::warn!(
            "[appchain-exit] table {table_id} hand {hand_id}: settle soft-confirmed at op {} but proof pending — watermark will advance asynchronously",
            frame.frame.index
        );
        None
    };
    tracing::info!(
        "[appchain-exit] table {table_id} hand {hand_id} settled: op={} binding=0x{} proven={proven} pot={}",
        frame.frame.index,
        crate::starknet::chain::hex_encode(&hand_binding),
        plan.gross_pot,
    );
    Ok(AppchainSettleReceipt {
        settle_op_index: frame.frame.index,
        hand_binding,
        proven,
        batch_root,
    })
}

/// REAL 归档的批次摘要（作为 hand_binding——与 zchain e2e 同模式）。
fn archive_digest(hp: Option<&HandProofBinding>) -> Option<[u8; 32]> {
    let hp = hp?;
    let archive = super::prover::TexasAirLocalProver::parse_archive(&hp.archive_bytes).ok()?;
    Some(archive.batch_digest)
}

/// PLAY 手绑定派生（域分离；桌/手/参与者集合绑定，防跨手重放）。
fn hand_binding_derived(table_id: u32, hand_id: u32) -> [u8; 32] {
    poker_appchain::keys::blake2s32(&[
        b"texas-appchain.hand-binding.v1",
        &table_id.to_be_bytes(),
        &hand_id.to_be_bytes(),
    ])
}

/// 镜像快照投影：poker_l1 桌面 → settlement-core 输入（含全量守卫）。
///
/// 仅支持 river showdown（board 5 张 + 争夺座位明文底牌齐全）；fold-win/
/// 早街结束的手返回 Err（→ hooks 回退遗留路径——derive_fold_win_plan 语义
/// 在 settlement-core 无同源函数，v1 不在出口层重实现第二套结算语义）。
fn project_snapshot(
    table: &poker_l1::contracts::texas_poker::types::TexasPokerTable,
    participants: &[super::super::prove_log::HandParticipant],
) -> Result<MirrorProjection, String> {
    use poker_l1::contracts::texas_poker::types::Seat;
    let seat_count = table.seats.len();
    if seat_count > SETTLEMENT_SEATS {
        return Err(format!("mirror seats {seat_count} exceed settlement core"));
    }
    if table.community_cards.len() != 5 {
        return Err(format!(
            "appchain exit supports river-showdown hands only (board {}); fold-win/early hands fall back to legacy",
            table.community_cards.len()
        ));
    }
    let board: Vec<u8> = table
        .community_cards
        .as_slice()
        .iter()
        .map(|c| c.to_index())
        .collect();
    let mut total_bets: Vec<u64> = vec![0; seat_count];
    let mut inactive: Vec<bool> = vec![true; seat_count];
    let mut all_in: Vec<bool> = vec![false; seat_count];
    let mut holes: Vec<&'static [u8]> = vec![&[]; seat_count];
    let mut participants_out: Vec<(usize, [u8; 32], u64, u64)> = Vec::new();

    // 镜像座位 = 升序参与者序（bootstrap join 顺序填座，e2e 对拍钉住）。
    // 手中离局的座位保持参与者占位（DepartedThisHand：贡献保留供分层）。
    let mut joined = 0usize;
    for (seat_idx, seat) in table.seats.iter().enumerate() {
        let (seat_total_bet, folded, is_all_in, hand_cards) = match seat {
            Seat::Playing { playing } => {
                let cards = playing.hand.as_slice();
                (playing.total_bet, seat.is_folded() || seat.has_left_hand(), seat.is_all_in(), cards)
            }
            Seat::DepartedThisHand { total_bet, .. } => (*total_bet, true, false, &[][..]),
            Seat::Waiting { .. } => (0, true, false, &[][..]),
            Seat::Vacant { .. } => continue,
        };
        let Some(participant) = participants.get(joined) else {
            return Err("mirror seat without matching HandStart participant".into());
        };
        joined += 1;
        let wallet_felt = crate::starknet::chain::parse_wallet_felt(&participant.wallet)
            .ok_or_else(|| format!("wallet unparsable: {}", participant.wallet))?
            .to_bytes_be();
        total_bets[seat_idx] = seat_total_bet;
        inactive[seat_idx] = folded;
        all_in[seat_idx] = is_all_in;
        if !folded {
            // 争夺座位：settlement-core 要求恰 2 张明文底牌（river showdown
            // 已物化，见 shadow.rs advance_deadline 快照注释）。
            if hand_cards.len() != 2 {
                return Err(format!(
                    "contested seat {seat_idx} hole cards not materialized ({}); appchain exit unsupported — legacy fallback",
                    hand_cards.len()
                ));
            }
            let cards: &'static [u8] = Box::leak(hand_cards.iter().map(|c| c.to_index()).collect::<Vec<u8>>().into_boxed_slice());
            holes[seat_idx] = cards;
        }
        participants_out.push((seat_idx, wallet_felt, seat_total_bet, participant.stack));
    }
    if joined != participants.len() {
        return Err(format!(
            "participant/mirror mismatch: {} joined vs {} recorded",
            joined,
            participants.len()
        ));
    }
    if participants_out.iter().all(|(_, _, bet, _)| *bet == 0) {
        return Err("no seat contributions in mirror snapshot".into());
    }
    //按钮位必须在镜像桌面范围内（snapshot.button 越界即 derive 拒绝）。
    let snapshot = TableSnapshot {
        seat_count,
        button: table.button.min(seat_count.saturating_sub(1) as u8),
        total_bets: Box::leak(total_bets.into_boxed_slice()),
        inactive: Box::leak(inactive.into_boxed_slice()),
        all_in: Box::leak(all_in.into_boxed_slice()),
        hole_cards: Box::leak(holes.into_boxed_slice()),
        rake_mode: table.rake_mode,
        rake_bps: table.rake_bps,
        rake_cap: table.rake_cap,
    };
    Ok(MirrorProjection {
        snapshot,
        boards: SettlementBoards::single(board),
        participants: participants_out,
        mirror_pot: table.pot,
    })
}

/// 确保桌已开（未开过时 OpenTable；费率开桌冻结）。
fn ensure_table(rt: &AppchainRuntime, table_id: u64, policy: FeePolicy) -> Result<(), String> {
    let open = rt.with_seq(|seq| seq.state().tables.get(&table_id).map(|t| t.open));
    if open == Some(true) {
        return Ok(());
    }
    if open == Some(false) {
        return Err(format!("table {table_id} closed in appchain ledger"));
    }
    policy
        .validate()
        .map_err(|e| format!("fee policy invalid: {e}"))?;
    let frame = rt
        .submit_operation(Operation::OpenTable { table_id, policy })
        .map_err(|e| format!("open table rejected: {e}"))?;
    // 嵌入式 dev 模型：host 背书的开桌帧即对账锚，立即证明化。若留在
    // 软确认态，连续前缀水位永远过不了首帧——后续惰性铸出的余额 note
    // 恒为 unproven，BuyIn 的 proven-only 准入从此全部被拒（死锁）。
    rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
    Ok(())
}

/// 每座位账本事实补齐：Deposit（按需）→ BuyIn（stack seat note）→
/// Transfer（seat 拆到 total_bet 面额）。返回 (镜像座位号 → settle 输入)。
struct SeatInput {
    seat_idx: usize,
    wallet: [u8; 32],
    input: SettleInput,
}

fn ensure_seats(
    rt: &AppchainRuntime,
    table_id: u64,
    asset_class: AssetClass,
    projection: &MirrorProjection,
    hand_id: u32,
) -> Result<Vec<SeatInput>, String> {
    let mut out = Vec::new();
    for (seat_idx, wallet, total_bet, stack) in &projection.participants {
        if *total_bet == 0 {
            continue; // 未参与争夺（无投入）——不进结算输入
        }
        if *stack == 0 {
            return Err(format!("seat {seat_idx} has total_bet but zero start stack"));
        }
        let key = super::keys::owner_key_of(wallet);
        let owner = key.public_bytes();
        let secret = super::keys::spend_secret_of(wallet);
        // 1. 余额 note：PLAY 缺额即铸（嵌入式 dev 模型）；REAL 须已有
        //    存款桥铸出的真实余额（储备对账锚——绝不无储备铸 REAL）。
        let balance = rt.with_seq(|seq| {
            seq.state()
                .notes
                .values()
                .find(|e| {
                    e.note.owner == owner
                        && e.note.table_id.is_none()
                        && e.note.asset_class == asset_class
                        && e.note.amount >= *stack
                })
                .map(|e| e.note.clone())
        });
        let balance = match balance {
            Some(note) => note,
            None if asset_class == AssetClass::Play => {
                let deposit_id = poker_appchain::keys::blake2s32(&[
                    b"texas-appchain.seat-deposit.v1",
                    &table_id.to_be_bytes(),
                    &hand_id.to_be_bytes(),
                    wallet,
                ]);
                let frame = rt
                    .submit_operation(Operation::Deposit {
                        deposit_id,
                        owner,
                        asset_class,
                        amount: *stack,
                    })
                    .map_err(|e| format!("seat deposit rejected: {e}"))?;
                // 存款段证明化（与 zchain e2e / WAL 恢复同语义）：托管桥/
                // 嵌入式铸造即对账锚。mark_proven 走连续前缀语义——若有
                // 在途未证结算 op 挡在前缀上，水位不推进（绝不越过未证
                // 明的结算，§5.4 finality 不弱化）。
                rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
                take_note_at(rt, frame.frame.index)
                    .ok_or_else(|| "minted deposit note not found".to_string())?
            }
            None => {
                return Err(format!(
                    "REAL balance insufficient for seat {seat_idx} (need {stack} wei) — deposit bridge must fund first"
                ));
            }
        };
        // 1.5 余额面额对齐：找出的余额 note 只保证 `>= stack`，而 BuyIn
        // 铸出的 seat 面额 = 输入 note 面额之和——超额余额直接买入会铸出
        // 面额更大的 seat，随后按 stack 面额的查找必然落空（"minted seat
        // note not found"，整手回退无法结算）。先把余额拆成恰好 stack 的
        // note（余款留回余额），再买入。
        let balance = if balance.amount > *stack {
            let outputs = vec![
                poker_appchain::note::NoteSpec {
                    asset_class,
                    amount: *stack,
                    owner,
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
                poker_appchain::note::NoteSpec {
                    asset_class,
                    amount: balance.amount - *stack,
                    owner,
                    table_id: None,
                    pot_index: 0,
                    runout_index: 0,
                },
            ];
            let effect = Operation::Transfer {
                spends: vec![],
                notes: vec![],
                outputs: outputs.clone(),
            }
            .effect_digest();
            let frame = rt
                .submit_operation(Operation::Transfer {
                    spends: vec![auth(&key, &secret, &balance, scope::TRANSFER, &effect)],
                    notes: vec![balance],
                    outputs,
                })
                .map_err(|e| format!("balance split rejected: {e}"))?;
            rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
            rt.with_seq(|seq| {
                seq.state()
                    .notes
                    .values()
                    .find(|e| e.created_at_op == frame.frame.index && e.note.amount == *stack)
                    .map(|e| e.note.clone())
            })
            .ok_or_else(|| "split balance note not found".to_string())?
        } else {
            balance
        };

        // 2. BuyIn：余额 → seat note（stack 面额，桌绑定）。
        let seat_note_of_amount = |want: u64| -> Option<poker_appchain::note::Note> {
            rt.with_seq(|seq| {
                seq.state()
                    .notes
                    .values()
                    .find(|e| {
                        e.note.owner == owner
                            && e.note.table_id == Some(table_id)
                            && e.note.amount == want
                            && e.note.asset_class == asset_class
                    })
                    .map(|e| e.note.clone())
            })
        };
        let seat = match seat_note_of_amount(*stack) {
            Some(note) => note,
            None => {
                let effect = Operation::BuyIn {
                    table_id,
                    spends: vec![],
                    notes: vec![],
                    seat_owner: owner,
                }
                .effect_digest();
                let seat_owner = owner;
                let frame = rt
                    .submit_operation(Operation::BuyIn {
                        table_id,
                        spends: vec![auth(&key, &secret, &balance, scope::BUYIN, &effect)],
                        notes: vec![balance],
                        seat_owner,
                    })
                    .map_err(|e| format!("buy-in rejected: {e}"))?;
                // 同 OpenTable/Deposit：host 背书即证明化，seat note 立即
                // 满足 proven-only 准入（Transfer/Settle 前置）。
                rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
                seat_note_of_amount(*stack)
                    .ok_or_else(|| "minted seat note not found".to_string())?
            }
        };
        // 3. 拆分：seat(stack) → seat(total_bet) + 余额（settle 关系
        //    Σinputs == gross_pot；stack ≥ total_bet 由资金守恒保证）。
        let settle_seat = if seat.amount == *total_bet {
            seat
        } else {
            let rest = seat.amount.saturating_sub(*total_bet);
            let outputs = {
                let mut v = vec![NoteSpec {
                    asset_class,
                    amount: *total_bet,
                    owner,
                    table_id: Some(table_id),
                    pot_index: 0,
                    runout_index: 0,
                }];
                if rest > 0 {
                    v.push(NoteSpec {
                        asset_class,
                        amount: rest,
                        owner,
                        table_id: None,
                        pot_index: 0,
                        runout_index: 0,
                    });
                }
                v
            };
            let effect = Operation::Transfer {
                spends: vec![],
                notes: vec![],
                outputs: outputs.clone(),
            }
            .effect_digest();
            let frame = rt
                .submit_operation(Operation::Transfer {
                    spends: vec![auth(&key, &secret, &seat, scope::TRANSFER, &effect)],
                    notes: vec![seat],
                    outputs,
                })
                .map_err(|e| format!("seat split rejected: {e}"))?;
            // 拆分帧同语义立即证明化（settle 花费的 note 须 proven）。
            rt.with_seq(|seq| seq.mark_proven(frame.frame.index));
            seat_note_of_amount(*total_bet)
                .ok_or_else(|| "split seat note not found".to_string())?
        };
        // settle 花费授权在记录完整后补签（build_record 内）——此处先挂
        // 零签名占位。
        out.push(SeatInput {
            seat_idx: *seat_idx,
            wallet: *wallet,
            input: SettleInput {
                note: settle_seat,
                spend: SpendAuth {
                    commitment: [0; 32],
                    nullifier: [0; 32],
                    sig: poker_appchain::keys::EcdsaSig { bytes: [0; 64] },
                },
            },
        });
    }
    if out.is_empty() {
        return Err("no settle-able seats after ledger sync".into());
    }
    Ok(out)
}

/// 从某帧铸出的 note（deposit/buy-in 单帧单 note 场景）。
fn take_note_at(rt: &AppchainRuntime, op_index: u64) -> Option<poker_appchain::note::Note> {
    rt.with_seq(|seq| {
        seq.state()
            .notes
            .values()
            .find(|e| e.created_at_op == op_index)
            .map(|e| e.note.clone())
    })
}

/// 花费授权（owner 密钥对 (commitment, nullifier, scope, effect) 签名）。
fn auth(
    key: &poker_appchain::keys::OwnerKey,
    secret: &[u8; 32],
    note: &poker_appchain::note::Note,
    scope_tag: &[u8],
    effect: &[u8; 32],
) -> SpendAuth {
    let nf = poker_appchain::felt::felt_to_bytes32(&note.nullifier(secret));
    let d = spend_digest(&note.commitment_bytes(), &nf, scope_tag, effect);
    SpendAuth {
        commitment: note.commitment_bytes(),
        nullifier: nf,
        sig: key.sign(&d),
    }
}

/// 构造结算记录：payouts 按 plan 投影规范序（pot, runout, seat）→ rake
/// 分账（policy 重导出）→ 每输入 settle 授权补签（effect 覆盖 payout_root）。
fn build_record(
    table_id: u64,
    hand_binding: [u8; 32],
    plan: &SettlementPlan,
    seats: &[SeatInput],
    projection: &MirrorProjection,
    policy: FeePolicy,
    hand_proof: Option<HandProofBinding>,
) -> Result<SettlementRecord, String> {
    // owner per seat（settle 输入的座位 ↔ payout 投影座位同一定义域）。
    let owner_of_seat: std::collections::HashMap<usize, [u8; 33]> = seats
        .iter()
        .map(|s| {
            (
                s.seat_idx,
                super::keys::owner_key_of(&s.wallet).public_bytes(),
            )
        })
        .collect();
    let asset_class = seats
        .first()
        .map(|s| s.input.note.asset_class)
        .ok_or("no seats")?;
    // 规范投影序（与 validate_payout_projection 的期望序一致）。
    let mut payouts: Vec<NoteSpec> = Vec::new();
    for pot in &plan.pots {
        let active_runouts = if pot.is_contested() {
            usize::from(plan.schedule.count())
        } else {
            1
        };
        for (runout_index, runout) in pot.runouts.iter().enumerate().take(active_runouts) {
            for (seat, amount) in runout.awards.iter().enumerate() {
                if *amount == 0 {
                    continue;
                }
                let owner = *owner_of_seat.get(&seat).ok_or(format!(
                    "plan awards seat {seat} without a settle input (unprovable)"
                ))?;
                payouts.push(NoteSpec {
                    asset_class,
                    amount: *amount,
                    owner,
                    table_id: None,
                    pot_index: pot.pot_index,
                    runout_index: u8::try_from(runout_index).unwrap_or(u8::MAX),
                });
            }
        }
    }
    let mut record = SettlementRecord {
        table_id,
        hand_binding,
        policy_commitment: policy.commitment_bytes(),
        pot: plan.gross_pot,
        inputs: seats.iter().map(|s| s.input.clone()).collect(),
        payouts,
        rake: RakeSplitRecord {
            total: plan.rake,
            treasury_out: None,
            operator_out: None,
        },
        plan: plan.clone(),
        hand_proof,
    };
    // rake 分账输出（收款人 = 策略绑定的嵌入式 treasury/operator 托管钥）。
    let (t_spec, o_spec) = rake_outputs(&record, &policy);
    record.rake.treasury_out = t_spec;
    record.rake.operator_out = o_spec;
    // settle 授权补签：先落 (commitment, nullifier)，再计算完整结算效果
    // 摘要（含 payout_root——赔付结构篡改必然签名失败），最后对
    // (commitment, nullifier, scope, effect) 签名。
    let scope = settle_spend_scope(&hand_binding);
    for (input, seat) in record.inputs.iter_mut().zip(seats.iter()) {
        let secret = super::keys::spend_secret_of(&seat.wallet);
        input.spend.commitment = input.note.commitment_bytes();
        input.spend.nullifier =
            poker_appchain::felt::felt_to_bytes32(&input.note.nullifier(&secret));
    }
    let effect = settle_effect(&record);
    for (input, seat) in record.inputs.iter_mut().zip(seats.iter()) {
        let d = spend_digest(&input.spend.commitment, &input.spend.nullifier, &scope, &effect);
        input.spend.sig = super::keys::owner_key_of(&seat.wallet).sign(&d);
    }
    let _ = projection; // 参与者对账已在 project_snapshot 内完成
    Ok(record)
}
