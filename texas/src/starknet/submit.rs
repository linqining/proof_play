//! 结算与上链：一手牌结束后
//! 1. `derive_settlement_plan` 计算分池 / rake / awards（poker_l1 内置）
//! 2. `Orchestrator::prove_and_verify_chain` 把本手 ProveTask 证成 receipt 链
//! 3. `prove_outer_aggregate` + `verify_outer_aggregate` 产出已验证聚合
//! 4. 组装 `register_aggregate` / `settle_hand` 的 Cairo calldata
//! 5. 经 starknet-txmgr 提交到 PokerSettlement 合约（2026-10-01 起发送面
//!    换 txmgr：nonce 租约/回执轮询/幂等重放分类归交易管理层；calldata
//!    构建不动）
//!
//! 生产投递主路径是 settle-queue 队列（hooks 入队、batch-poster 驱动，
//! 见 settle_wiring）；本模块的 [`submit_settlement`] 是同语义的直发面
//! （e2e 冒烟/运维通道）。
//!
//! dev 模式（未配置 settlement 合约/操作员）只生成 calldata 并记日志，
//! 保证无链环境可以跑完整流程（证明生成照常执行）。

use poker_l1::contracts::texas_poker::settlement::{
    SettlementPlan, derive_fold_win_plan, derive_settlement_plan,
};
use poker_l1::contracts::texas_poker::types::TexasPokerTable;
use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::outer_aggregate::{
    VerifiedOuterAggregate, prove_outer_aggregate, verify_outer_aggregate,
};
use poker_texas_air::starknet_settlement::{
    AggregateDigestFelts, RegisterAggregateCalldata, SettleHandCalldata,
};
use starknet::accounts::Account;
use starknet::core::types::Felt;
use starknet::core::utils::starknet_keccak;
use starknet_txmgr::provider::ProviderSend;
use starknet_txmgr::{ReplayVerdict, SendOutcome, TxError, TxManager, TxManagerConfig};

use super::vm_session::VmTable;

/// 一手牌的完整结算产物。
pub struct HandSettlement {
    pub hand_id: u32,
    pub plan: SettlementPlan,
    /// `register_aggregate` calldata（felts，对齐 Cairo 合约 ABI）。
    pub register_calldata: Vec<Felt>,
    /// `settle_hand` calldata（felts，对齐 Cairo 合约 ABI，双 felt digest 形式）。
    pub settle_calldata: Vec<Felt>,
    /// 聚合摘要（32 字节大端）。
    pub aggregate_digest: [u8; 32],
    /// 重映射后的参与者（真实钱包 felt，settle 顺序）——Hand-batch 路径复用。
    pub players_remapped: Vec<Felt>,
    /// 与 players 对应的净输赢（零和）。
    pub deltas: Vec<i128>,
    /// 重映射后的 Poseidon 结算摘要（register root / Hand-batch 路径共用）。
    pub settlement_digest: Felt,
    /// 本手动作日志哈希（#18 Phase C 切片 1 = Poseidon 吸收链根）：
    /// settlement digest 吸收链尾词，dapv register 承诺与 v2 公开段尾词共用。
    pub action_log_digest: Felt,
    /// 本手动作日志词条对（每条 2 felt：[日志打包词, 合法性词]，切片 2）——
    /// 电路 30 槽重放 + "合法默认"校验的见证。
    pub action_entries: Vec<[Felt; 2]>,
    /// G 链首 receipt 的 pre state root（hand_binding 输入）。
    pub pre_state_root: [u8; 32],
    /// G 链末 receipt 的 post state root（hand_binding 输入）。
    pub post_state_root: [u8; 32],
}

/// 结算镜像中当前手牌：证明 + 分池 + calldata。
///
/// 同步执行（prove 约 2 秒/hand），调用方应放在 `tokio::task::spawn_blocking` 里。
pub fn settle_hand(
    mirror: &VmTable,
    rake_recipient: Option<poker_l1::Address>,
    wallet_map: &[(poker_l1::Address, Felt)],
    action_log_digest: Felt,
    action_log: &[crate::pokergame::actions::ActionLogEntry],
) -> Result<HandSettlement, String> {
    // #18 Phase C 切片 1：词条 → 电路见证词组；未知动作名/超上限在构建期拒绝。
    use crate::pokergame::actions::{ACTION_LOG_MAX_ENTRIES, action_entry_word, legality_word};
    if action_log.len() > ACTION_LOG_MAX_ENTRIES {
        return Err(format!(
            "action log has {} entries, exceeds circuit maximum {ACTION_LOG_MAX_ENTRIES}",
            action_log.len()
        ));
    }
    let mut action_entries = Vec::with_capacity(action_log.len());
    for entry in action_log {
        let word = action_entry_word(entry)
            .ok_or_else(|| format!("unknown action name {:?} in action log", entry.action))?;
        let legality = legality_word(entry)
            .ok_or_else(|| format!("unknown action name {:?} in action log", entry.action))?;
        action_entries.push([word, legality]);
    }
    if mirror.tasks.is_empty() {
        return Err("mirror has no prove tasks for this hand".into());
    }
    // 只证明当前手的任务，且只聚合首个连续的 dual-proof 任务段：
    // outer aggregate 仅支持 4 种密码学动作（shuffle/reconstruct/fold_with_proof/
    // reveal tokens）；join/start_hand/下注等由 VerifiedChain 的 method proofs 覆盖，
    // 若混入会把聚合 receipt 链截断（state-root 不连续）。
    let hand_id = mirror.table.hand_id;
    use poker_texas_air::method_kind::MethodKind;
    let is_dual = |k: &MethodKind| {
        matches!(
            k,
            MethodKind::SubmitShuffleV2
                | MethodKind::SubmitPlayerRevealTokens
                | MethodKind::SubmitReconstructDeck
                | MethodKind::FoldWithProof
        )
    };
    let mut tasks: Vec<poker_texas_air::prove_task::ProveTask> = Vec::new();
    let mut seen_dual = false;
    for t in mirror.tasks.iter().filter(|t| t.hand_id == hand_id) {
        if is_dual(&t.method_kind) {
            tasks.push(t.clone());
            seen_dual = true;
        } else if seen_dual {
            break; // 第一个非 dual 任务结束聚合窗口
        }
    }
    if tasks.is_empty() {
        return Err(format!("mirror has no dual-proof tasks for hand {hand_id}"));
    }
    let tasks = &tasks;

    // 0. 派奖前快照优先：VM 在 advance_deadline 时已派奖（pot 清零、board 复位），
    //    而 settle_hand 需要 pre-payout 状态（board 5 张、pot、total_bet）。
    //    fold-win 快照打在终局弃牌应用之前：先在副本上落这记弃牌，
    //    derive_fold_win_plan 才能看到"恰好一名未弃牌玩家"的终局形态。
    let fold_snapshot = mirror
        .pre_settlement_final_fold
        .zip(mirror.pre_settlement.as_ref())
        .map(|(seat, snap)| apply_pending_final_fold(snap, seat));
    let settle_table = fold_snapshot
        .as_ref()
        .or(mirror.pre_settlement.as_ref())
        .unwrap_or(&mirror.table);

    // 1. 分池 / rake / awards（库内计算，含零和校验）。
    //    fold-win 分派：全场仅剩一名未弃牌玩家时走 derive_fold_win_plan
    //    （无牌面校验，"no flop, no drop" 抽水）。2026-09-04 前 fold-win 手
    //    在 derive_settlement_plan 的牌面校验上必然失败（board<5 / 未亮牌）
    //    → 输赢从不上链（线上复现：玩家链上余额只剩买入流水）。
    let unfolded_count = settle_table
        .seats
        .iter()
        .filter(|seat| seat.is_occupied() && !seat.is_folded() && !seat.has_left_hand())
        .count();
    let plan = if unfolded_count <= 1 {
        derive_fold_win_plan(settle_table)
            .map_err(|e| format!("derive_fold_win_plan failed: {e}"))?
    } else {
        derive_settlement_plan(settle_table)
            .map_err(|e| format!("derive_settlement_plan failed: {e}"))?
    };

    // 2. 证明链（receipt chain）。
    let _chain = Orchestrator::prove_and_verify_chain(tasks)
        .map_err(|e| format!("prove_and_verify_chain failed [{:?}]: {e}", e.category()))?;

    // 3. outer aggregate：证明 + 验证，产出可信任的聚合工件。
    let bundle = prove_outer_aggregate(tasks)
        .map_err(|e| format!("prove_outer_aggregate failed [{:?}]: {e}", e.category()))?;
    let verified: VerifiedOuterAggregate = verify_outer_aggregate(tasks, &bundle)
        .map_err(|e| format!("verify_outer_aggregate failed [{:?}]: {e}", e.category()))?;
    let digest = verified.aggregate_digest();

    // 4. Cairo calldata。
    let settle = SettleHandCalldata::new(
        digest,
        hand_id,
        settle_table,
        &plan,
        rake_recipient,
        action_log_digest,
    )
    .map_err(|e| {
        // #24⑤：稳定错误类别进运维日志（telemetry 可按类别告警/重试）。
        format!("SettleHandCalldata::new failed [{:?}]: {e}", e.category())
    })?;

    // 4.5 参与者地址重映射：VM 座位只存钱包 felt 的低 160 位（poker_l1
    //     Address 为 20 字节），而 vault 余额以完整钱包 felt 为键。上链前把
    //     players 重映射回真实钱包地址（映射来自本手 HandStart 记录 + treasury，
    //     见 hooks::hand_wallet_map），并按同一映射重算 settlement digest——
    //     合约 settle_hand 会用 calldata 的 players 重算 Poseidon 承诺并与
    //     register_aggregate 写入的 root 精确比对。
    //     截断公式（felt 低 20 字节）唯一权威在 poker_l1
    //     caller_id::wallet_to_address（与 mirror addr_from_starknet 同源，
    //     e2e 对拍断言）；这里 felt → hex 后交由权威实现截断。
    let remap_player = |p: Felt| -> Felt {
        let truncated: [u8; 20] =
            poker_l1::contracts::texas_poker::runtime::caller_id::wallet_to_address(&format!(
                "{p:#x}"
            ))
            .expect("canonical felt hex always truncates to 20 bytes");
        wallet_map
            .iter()
            .find(|(addr, _)| *addr == truncated)
            .map(|(_, wallet)| *wallet)
            .unwrap_or(p)
    };
    let players_remapped: Vec<Felt> = settle.players().iter().map(|p| remap_player(*p)).collect();

    // 派彩单位换算：vault 的 chip_balance 以 STRK wei 记账（deposit 1:1 wei），
    // SettlementPlan 的 deltas 以服务端 chips（1 chip = WEI_PER_CHIP wei）计。
    // settle_hand 上链前必须放大到 wei，且 Poseidon digest 与 calldata 用同一
    // 放大值（合约按 calldata 重算承诺与 register root 比对）。
    // 2026-09-04 修复：此处曾局部定义 1e14，与全局 config::WEI_PER_CHIP(1e15)
    // 差 10 倍——买入按 1e15 记账、结算按 1e14 挪账，链上余额与游戏输赢每手
    // 漂移 9/10。统一引用全局常量，杜绝两份定义（dual_settle 同步修）。
    const WEI_PER_CHIP: i128 = super::config::WEI_PER_CHIP as i128;
    let deltas_wei: Vec<i128> = settle
        .deltas()
        .iter()
        .map(|d| d.checked_mul(WEI_PER_CHIP))
        .collect::<Option<Vec<_>>>()
        .ok_or("delta wei overflow")?;

    let mut digest_fields: Vec<Felt> = vec![Felt::from(u64::from(settle.hand_id()))];
    for (p, d) in players_remapped.iter().zip(deltas_wei.iter()) {
        digest_fields.push(*p);
        let magnitude = u64::try_from(d.unsigned_abs()).map_err(|_| "delta magnitude overflow")?;
        if *d >= 0 {
            digest_fields.push(Felt::from(1u64));
        } else {
            digest_fields.push(Felt::from(0u64));
        }
        digest_fields.push(Felt::from(magnitude));
    }
    // #18 Phase B：动作日志哈希为吸收链尾词（与合约 compute_settlement_digest
    // 及 settlement_private 电路同公式）。
    digest_fields.push(action_log_digest);
    let settlement_digest = starknet_crypto::poseidon_hash_many(&digest_fields);

    // register_aggregate：本手一个 aggregate，settlement root 取重映射后的 digest。
    let register = RegisterAggregateCalldata::new(
        std::slice::from_ref(&verified),
        hand_id,
        hand_id,
        vec![settlement_digest],
    )
    .map_err(|e| format!("RegisterAggregateCalldata::new failed: {e}"))?;

    let register_calldata = register.to_felts();
    let settle_calldata = build_settle_calldata(digest, &settle, &players_remapped, &deltas_wei);

    // G 链首尾 state root（hand_binding 的输入）：首 receipt 的 pre、
    // 末 receipt 的 post。
    let receipts = verified.chain().receipts();
    let pre_state_root = receipts
        .first()
        .ok_or("verified chain has no receipts")?
        .pre_state_root()
        .bytes();
    let post_state_root = receipts
        .last()
        .expect("non-empty checked above")
        .post_state_root()
        .bytes();

    Ok(HandSettlement {
        hand_id,
        plan,
        register_calldata,
        settle_calldata,
        aggregate_digest: digest,
        players_remapped,
        deltas: settle.deltas().to_vec(),
        settlement_digest,
        action_log_digest,
        action_entries,
        pre_state_root,
        post_state_root,
    })
}

/// `settle_hand(aggregate_digest: (felt252, felt252), hand_id: u64,
///               players: Span<ContractAddress>, deltas: Span<i128>)` 的 calldata。
///
/// 合约使用双 felt digest；Rust builder 的 `to_felts()` 是单 felt 旧格式，
/// 这里按当前合约 ABI 手工组装。`players` 为重映射后的真实钱包地址。
fn build_settle_calldata(
    digest: [u8; 32],
    settle: &SettleHandCalldata,
    players: &[Felt],
    deltas_wei: &[i128],
) -> Vec<Felt> {
    let felts = AggregateDigestFelts::split(&digest).expect("32-byte digest always splits");
    let mut out = Vec::with_capacity(5 + players.len() * 2);
    out.push(felts.hi);
    out.push(felts.lo);
    out.push(Felt::from(settle.hand_id()));
    // #18 Phase B：legacy settle_hand 的动作日志哈希标量（hand_id 之后）。
    out.push(settle.action_log_digest());
    out.push(Felt::from(players.len() as u64));
    out.extend(players.iter().copied());
    out.push(Felt::from(deltas_wei.len() as u64));
    out.extend(deltas_wei.iter().map(|d| i128_to_felt(*d)));
    out
}

/// register 幂等重放 / settle 幂等重放的错误文案匹配已删除（2026-10-01，
/// rollup-components 条目 2）——语义吸收进 starknet-txmgr replay.rs 的
/// `classify_execution_error`（含 dual 合约 "Binding already registered"
/// 注册相），由 [`drive_two_leg_settlement`] 按 `SendOutcome` 消费。

/// 构建一次性发送面句柄（txmgr 的生产实现包 operator 账户）。
/// 每次提交独立 [`TxManager`]：nonce 基线从链上现查（账户块位
/// PreConfirmed，含在途交易——与本进程其它 execute_v3 发送面（vault
/// 续钟/离桌释放）无跨调用 nonce 租约残留）。
pub(crate) async fn fresh_txmgr()
-> Result<TxManager<ProviderSend<super::chain::OperatorAccount>>, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let operator = chain
        .operator()
        .await
        .ok_or("operator account unavailable")?;
    Ok(build_txmgr(std::sync::Arc::new(ProviderSend::new(
        operator,
    ))))
}

pub(crate) fn build_txmgr<S: starknet_txmgr::StarknetSend>(
    send: std::sync::Arc<S>,
) -> TxManager<S> {
    // 配置缺省与 batch-poster 对齐（TxManagerConfig::default 的资源上限
    // 由 ProviderSend 的 estimate 分支接管；重试/回执轮询缺省即生产值）。
    TxManager::new(send, TxManagerConfig::default())
}

/// 两笔结算的 txmgr 驱动（register → settle；rollup-components 条目 2）。
///
/// - **可见性 = register 腿回执包含**：txmgr 轮询回执直至交易入块才决议，
///   settle 腿随后提交即见注册落地——旧 `wait_register_visible` 的 view
///   轮询语义已吸收进 txmgr 层（回执包含是更强的可见性判据）。
/// - **幂等重放**：txmgr 按合约错误文案分类（replay.rs），
///   `RegisterReplay` → "already-registered" 标记串放行 settle 腿；
///   `SettleReplay` → 幂等成功收尾（"already-settled"）。
/// - **每腿独立 TxManager**：重放决议不消耗 nonce（估计失败即无交易广
///   播），共用租约序会留下 nonce 空洞；独立构建则每腿基线现查、无空洞。
pub(crate) async fn drive_two_leg_settlement<S: starknet_txmgr::StarknetSend>(
    send: std::sync::Arc<S>,
    account: Felt,
    register_call: starknet_txmgr::Call,
    settle_call: starknet_txmgr::Call,
    register_tag: &str,
    settle_tag: &str,
) -> Result<(String, String), String> {
    let register_hash = {
        let mgr = build_txmgr(send.clone());
        match mgr
            .submit_ordered(account, register_tag, vec![register_call])
            .await
        {
            Ok(SendOutcome::Receipted(r)) => format!("{:#x}", r.tx_hash),
            Ok(SendOutcome::IdempotentReplay(ReplayVerdict::RegisterReplay)) => {
                tracing::info!("{register_tag}: already registered on-chain (idempotent replay)");
                "already-registered".to_string()
            }
            Ok(SendOutcome::IdempotentReplay(ReplayVerdict::SettleReplay)) => {
                // register 腿见到 settle 相文案 = 本手早已完整结算。
                return Ok(("already-settled".to_string(), "already-settled".to_string()));
            }
            Ok(SendOutcome::IdempotentReplay(ReplayVerdict::NotReplay)) => {
                return Err(format!("{register_tag} leg: not-replay invariant"));
            }
            Err(TxError::Broadcast { last, .. }) => {
                return Err(format!("{register_tag} submit failed: {last}"));
            }
            Err(e) => return Err(format!("{register_tag} submit failed: {e}")),
        }
    };
    let mgr = build_txmgr(send);
    match mgr
        .submit_ordered(account, settle_tag, vec![settle_call])
        .await
    {
        Ok(SendOutcome::Receipted(r)) => Ok((register_hash, format!("{:#x}", r.tx_hash))),
        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::SettleReplay)) => {
            Ok((register_hash, "already-settled".to_string()))
        }
        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::RegisterReplay)) => Err(format!(
            "{settle_tag} leg hit register-replay text (anomaly)"
        )),
        Ok(SendOutcome::IdempotentReplay(ReplayVerdict::NotReplay)) => {
            Err(format!("{settle_tag} leg: not-replay invariant"))
        }
        Err(TxError::Broadcast { last, .. }) => Err(format!("{settle_tag} submit failed: {last}")),
        Err(e) => Err(format!("{settle_tag} submit failed: {e}")),
    }
}

/// 把结算产物提交到链上。返回交易哈希（register, settle）。
///
/// 时序保证（txmgr 面）：settle_hand 在合约内断言 aggregate 已注册——
/// register 腿经 txmgr 轮询回执至**入块**才决议，settle 腿随后提交时注册
/// 已在链上可见；重放文案（Digest/Aggregate/Binding already registered、
/// Hand already settled）由 txmgr 分类为幂等成功语义。
pub async fn submit_settlement(
    settlement: &HandSettlement,
    settlement_address: &str,
) -> Result<(String, String), String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let contract = super::chain::parse_felt(settlement_address)
        .ok_or("invalid settlement contract address")?;
    let operator = chain
        .operator()
        .await
        .ok_or("operator account unavailable")?;
    let send = std::sync::Arc::new(ProviderSend::new(operator.clone()));

    let register_call = starknet_txmgr::Call::new(
        contract,
        starknet_keccak("register_aggregate".as_bytes()),
        settlement.register_calldata.clone(),
    );
    let settle_call = starknet_txmgr::Call::new(
        contract,
        starknet_keccak("settle_hand".as_bytes()),
        settlement.settle_calldata.clone(),
    );

    drive_two_leg_settlement(
        send,
        operator.address(),
        register_call,
        settle_call,
        "register_aggregate",
        "settle_hand",
    )
    .await
}

/// i128 → felt（负数取模补，与合约 `from_felt_signed_i128` 对齐；
/// poker_texas_air::starknet_settlement::i128_to_felt 为私有，这里按同一语义实现）。
pub fn i128_to_felt(value: i128) -> Felt {
    if value >= 0 {
        Felt::from(value.unsigned_abs())
    } else {
        -Felt::from(value.unsigned_abs())
    }
}

/// fold-win 快照补应用终局弃牌：`apply_mirror_bet` 的 `mark_pre_settlement`
/// 打在 `fold(seat)` 应用之前，快照里该座位仍是未弃牌——派发前在副本上
/// 落这记弃牌，`derive_fold_win_plan` 才能看到"恰好一名未弃牌"的终局形态。
/// 座位越界时原样返回副本（防御，不 panic）。
pub(crate) fn apply_pending_final_fold(snap: &TexasPokerTable, seat: u8) -> TexasPokerTable {
    let mut table = snap.clone();
    if let Some(target) = table.seats.get_mut(usize::from(seat)) {
        target.set_status(poker_l1::contracts::texas_poker::types::SeatStatus::Folded);
    }
    // 对齐 VM end_without_showdown 的第一步：把本轮在途 bet（含翻前盲注）
    // 收进 pot。快照打在终局 fold 之前，盲注/当街下注尚未收集——
    // derive_fold_win_plan 守卫要求 Σ total_bet == table.pot，翻前
    // fold 的手必然 0 ≠ 盲注总和（2026-09-08 hand 1788804610：
    // contribution 200 vs pot 0）。river fold 的手因各街已在
    // advance_round 收集而碰巧通过。
    let total: u64 = table.seats.iter().map(|s| s.bet()).sum();
    for s in table.seats.iter_mut() {
        if s.bet() > 0 {
            let _ = s.set_bet(0);
        }
    }
    table.pot += total;
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-04：fold-win 快照补弃牌——快照里两名未弃牌（含待落弃的
    /// 输家），应用后必须恰好剩一名（赢家），且 pot/total_bet 不变。
    #[test]
    fn pending_final_fold_yields_single_unfolded() {
        use poker_l1::contracts::texas_poker::card::Card;
        use poker_l1::contracts::texas_poker::types::{SeatStatus, TexasPokerTable};
        use poker_l1::object_model::ObjectID;
        let mut table = TexasPokerTable::new(ObjectID::new([0xF2; 20], 0), [0xEE; 20], 2, 1, 2);
        table.seats[0].fixture_set_player([1; 20]);
        table.seats[0].fixture_set_total_bet(300);
        table.seats[0].set_status(SeatStatus::Active);
        table.seats[1].fixture_set_player([2; 20]);
        table.seats[1].fixture_set_total_bet(100);
        table.seats[1].set_status(SeatStatus::Active);
        table.pot = 400;

        let mut folded = apply_pending_final_fold(&table, 1);

        let unfolded: Vec<usize> = folded
            .seats
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_occupied() && !s.is_folded())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(unfolded, vec![0], "winner must be the only unfolded seat");
        assert!(folded.seats[1].is_folded());
        // 派发守卫的精确形态：恰一名未弃牌 → fold 计划路径。
        assert_eq!(unfolded.len(), 1);
        // 财务守卫：Σ total_bet == pot（本例在途 bet=0，pot 不变）。
        assert_eq!(folded.pot, 400);
        assert_eq!(folded.seats[0].total_bet(), 300);
        assert_eq!(folded.seats[1].total_bet(), 100);
        // 补弃牌后可直接派生 fold-win 计划（翻后 3 张 board 的抽水路径）。
        folded.community_cards = vec![Card::new(2, 4), Card::new(3, 6), Card::new(2, 8)]
            .try_into()
            .unwrap();
        folded.rules.rake_mode = poker_l1::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
        folded.rules.rake_bps = 500;
        folded.rules.rake_cap = 1_000;
        let plan = poker_l1::contracts::texas_poker::settlement::derive_fold_win_plan(&folded)
            .expect("fold plan derives after final fold applied");
        assert_eq!(plan.rake, 10, "400 - 200 uncalled = 200 contested * 5%");
        assert_eq!(plan.awards[0], 390);
    }

    /// 2026-09-08（hand 1788804610 线上）：翻前 fold 的快照里盲注还在
    /// 在途 bet、pot=0——补弃牌必须把它们收进 pot，否则
    /// derive_fold_win_plan 守卫 Σ total_bet == pot 必然失败
    /// （"contribution 200 does not match table pot 0"）。
    #[test]
    fn pending_final_fold_collects_preflop_blinds_into_pot() {
        use poker_l1::contracts::texas_poker::types::{SeatStatus, TexasPokerTable};
        use poker_l1::object_model::ObjectID;
        let mut table = TexasPokerTable::new(ObjectID::new([0xF3; 20], 0), [0xEF; 20], 2, 1, 2);
        table.seats[0].fixture_set_player([1; 20]);
        table.seats[1].fixture_set_player([2; 20]);
        for (i, blind) in [100u64, 100].iter().enumerate() {
            table.seats[i].fixture_set_total_bet(*blind);
            table.seats[i].set_bet(*blind).unwrap();
            table.seats[i].set_status(SeatStatus::Active);
        }
        table.pot = 0;

        let folded = apply_pending_final_fold(&table, 1);

        assert!(folded.seats[1].is_folded());
        assert_eq!(
            folded.pot, 200,
            "in-flight blinds must be collected into pot"
        );
        assert!(folded.seats.iter().all(|s| s.bet() == 0), "bets drained");
        let sum: u64 = folded.seats.iter().map(|s| s.total_bet()).sum();
        assert_eq!(sum, folded.pot, "Σ total_bet == pot after collection");
        let plan = poker_l1::contracts::texas_poker::settlement::derive_fold_win_plan(&folded)
            .expect("preflop fold-win plan must derive (no board → no rake)");
        assert_eq!(plan.rake, 0, "no flop, no drop");
        assert_eq!(plan.awards[0], 200);
    }

    #[test]
    fn i128_felt_roundtrip_semantics() {
        let pos = i128_to_felt(42);
        assert_eq!(pos, Felt::from(42_u64));
        let neg = i128_to_felt(-42);
        // -42 mod P ≈ P - 42，非零且与 +42 不同。
        assert_ne!(neg, Felt::from(42_u64));
        assert_ne!(neg, Felt::ZERO);
    }
}

#[cfg(test)]
mod txmgr_send_tests {
    use super::*;
    use starknet_txmgr::Call as TxCall;
    use starknet_txmgr::mock::{MockSend, MockSendScript, ReceiptKind};

    fn felt(v: u64) -> Felt {
        Felt::from(v)
    }

    fn call(word: u64) -> TxCall {
        TxCall::new(felt(0xabc), felt(0xdef), vec![felt(word)])
    }

    // 两腿驱动（tokio current-thread 测试；回执脚本立即成功时不产生真实
    // sleep，nonce-race 退避不在本组用例）。
    fn futures_drive(
        send: std::sync::Arc<MockSend>,
    ) -> impl std::future::Future<Output = Result<(String, String), String>> {
        drive_two_leg_settlement(
            send,
            felt(7),
            call(1),
            call(2),
            "register_aggregate",
            "settle_hand",
        )
    }

    /// 两笔顺序提交：register 回执 → settle 回执，返回两笔哈希。
    #[tokio::test]
    async fn two_leg_happy_path() {
        let send = std::sync::Arc::new(MockSend::new(MockSendScript {
            chain_nonce: 100,
            broadcast_results: vec![Ok(()), Ok(())],
            receipts_by_broadcast: vec![
                vec![Some(ReceiptKind::Succeeded)],
                vec![Some(ReceiptKind::Succeeded)],
            ],
            view_results: vec![],
        }));
        let (reg, settle) = futures_drive(send.clone()).await.unwrap();
        assert_eq!(reg, "0x1000");
        assert_eq!(settle, "0x1001");
        // 两腿都广播且各一次。
        assert_eq!(send.broadcast_count(), 2);
        assert_eq!(send.intents()[0].calls[0].calldata[0], felt(1));
        assert_eq!(
            send.intents()[1].calls[0].calldata[0],
            felt(2),
            "settle 在 register 之后"
        );
    }

    /// register 幂等重放（"Digest already registered"）→ 放行 settle 腿
    ///（旧 is_register_replay 语义，分类已归 txmgr replay.rs）。
    #[tokio::test]
    async fn register_replay_proceeds_to_settle() {
        let send = std::sync::Arc::new(MockSend::new(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![
                Err("ExecutionError: Digest already registered".into()),
                Ok(()),
            ],
            receipts_by_broadcast: vec![vec![], vec![Some(ReceiptKind::Succeeded)]],
            view_results: vec![],
        }));
        let (reg, settle) = futures_drive(send).await.unwrap();
        assert_eq!(reg, "already-registered");
        assert_eq!(settle, "0x1001");
    }

    /// settle 幂等重放（"Hand already settled"）→ 幂等成功收尾。
    #[tokio::test]
    async fn settle_replay_returns_already_settled() {
        let send = std::sync::Arc::new(MockSend::new(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![Ok(()), Err("ExecutionError: Hand already settled".into())],
            receipts_by_broadcast: vec![vec![Some(ReceiptKind::Succeeded)]],
            view_results: vec![],
        }));
        let (reg, settle) = futures_drive(send).await.unwrap();
        assert_eq!(reg, "0x1000");
        assert_eq!(settle, "already-settled");
    }

    /// register 腿见到 settle 相文案 = 本手早已完整结算（双标记串）。
    #[tokio::test]
    async fn settle_replay_on_register_leg_short_circuits() {
        let send = std::sync::Arc::new(MockSend::new(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![Err("ExecutionError: Hand already settled".into())],
            receipts_by_broadcast: vec![],
            view_results: vec![],
        }));
        let (reg, settle) = futures_drive(send.clone()).await.unwrap();
        assert_eq!(
            (reg.as_str(), settle.as_str()),
            ("already-settled", "already-settled")
        );
        assert_eq!(send.broadcast_count(), 1, "settle 腿不再提交");
    }

    /// register 广播持续失败（非重放）→ 有界重试耗尽报错（txmgr 熔断语义
    /// 在进程内一次性 manager 上：Err 返回给调用方，不残留停机位）。
    #[tokio::test]
    async fn register_broadcast_failure_is_error() {
        let send = std::sync::Arc::new(MockSend::new(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![Err("rpc: connection refused".into())],
            receipts_by_broadcast: vec![],
            view_results: vec![],
        }));
        let err = futures_drive(send.clone()).await.unwrap_err();
        assert!(
            err.contains("register_aggregate submit failed"),
            "err = {err}"
        );
        assert!(err.contains("rpc: connection refused"), "err = {err}");
        // 有界重试上限（TxManagerConfig::default 的 max_attempts_per_tx=3）。
        assert_eq!(send.broadcast_count(), 3);
    }
}
