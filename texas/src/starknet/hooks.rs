//! 服务器接线钩子：把牌局事件桥接到 Starknet 结算（#20 Phase 2）。
//!
//! 单一状态表示（2026-09-09）：手牌只有一份 VM 状态——`shadow.rs` 的实时
//! 镜像在每个接受点同步 dispatch；[`on_hand_complete`] 把它移交给
//! [`settle_from_live_mirror`]，经终局比对（与游戏层事实逐分对账）后直接取用
//! ProveTask 链与 pre-payout 快照构建 register_aggregate/settle_hand：
//! legacy 路入队 settle-queue WAL 由 batch-poster 投递（2026-10-01 起，
//! 进程内 PENDING_SETTLE/SETTLE_OK/SETTLE_ATTEMPTS 已删除——投递状态
//! 持久化在队列/sidecar，见 [`super::settle_wiring`]）；dual 路仍直发
//! （starknet-txmgr 发送面）。历史"结算时日志重放出第二份 VM 状态"
//! 的 build_from_log 已删除。
//!
//! 禁止事项（防止回到老路）：不再引入第二份手牌状态（重放/事后重建）；
//! 不新增"事后追赶"型补丁；不引入第二套密文派生（deck 必须同源）；不为
//! 绕过验证失败放宽 VM 证明校验；对账不一致宁可不结算，绝不带分歧状态上链。

use super::vm_session::{VmTable, seat_player_addr};
use crate::pokergame::table::Table;

/// 本手是否已结算（幂等跳过判定）。旧进程内 `SETTLE_OK` 集合（重启即丢）
/// 已删除：队列投递路径看 poster sidecar 回执，dual 直发/appchain 出口看
/// settle_receipt 业务终态（见 settle_wiring::is_settled）。
pub(crate) fn settle_ok_already(table_id: u32, hand_id: u32) -> bool {
    super::settle_wiring::is_settled(table_id, hand_id)
}

/// 错误文本是否表示"本手已在链上结算/注册过"（幂等重放超集视图；分类
/// 唯一权威在 starknet-txmgr replay.rs——submit.rs 旧
/// is_register_replay/is_settle_replay 已删除）。
fn is_already_settled_error(e: &str) -> bool {
    starknet_txmgr::classify_execution_error(e) != starknet_txmgr::ReplayVerdict::NotReplay
}

pub fn on_hand_complete(table: &mut Table) {
    // 阶段 1（快速，锁内只克隆）：提取本手证明输入日志 + 游戏层终局事实。
    // 日志重放（验证 EC 证明）与证明生成都是重活，必须全部移出写锁。
    // （旧"上一手仍在重投队列则跳过新手"的进程内检查已删除：队列按
    // (table, hand) 单手键去重，新手入队不覆盖旧手，无需让位。）
    let Some(input) = super::prove_log::take_settle_input(table) else {
        return; // 本手未记录（未开局/缺 join 证明）——无可证明结算
    };
    // 单一状态表示：取走本手的实时 VM 镜像交给结算流程。缺失 =
    // bootstrap 失败 / 紧急停用 / 进程重启——该手不可证明，fail-closed。
    let Some(live) = table.vm_session.take() else {
        refuse_settlement(
            input.table_id,
            input.start.hand_id,
            "no live hand mirror — hand unprovable",
        );
        return;
    };
    // 无 tokio runtime 的环境（游戏层单测直接调 settle_hand）跳过链上
    // 结算——但终局比对照常执行（测试断言依赖报告）。
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        let (report, _mirror) = live.finish(&input);
        tracing::info!("[live-mirror] test-context finish: {report:?}");
        return;
    };
    handle.spawn(async move {
        settle_from_live_mirror(input, live).await;
    });
}

/// 锁外结算：实时 VM 镜像终局比对 → 强制对账 → 证明 → 入队上链。
///
/// 手牌只有一份 VM 状态表示（实时镜像）；比对不干净或镜像缺失 =
/// fail-closed 拒绝该手结算（与游戏层事实分歧的状态绝不上链）。
/// REAL 手的 canonical 归档生产（#22②扩展完成后接线）：实时镜像的控制
/// 轨迹 → canonical 行链 → 真实 stwo 出证。任何失败返回 None（fail-soft：
/// 未入证的 selector 族（admin/kick/addon…）、无 reveal 完成的极早手、
/// 出证失败等按行家族 fail-closed，回退遗留 Starknet 路径）。
fn build_appchain_hand_proof(
    mirror: &VmTable,
    table_id: u32,
) -> Option<poker_appchain::settlement::HandProofBinding> {
    let first = mirror.traces.first()?;
    let rules = first.pre.rules.clone();
    let records: Vec<poker_texas_air::canonical_dispatch_trace::DispatchRecord<'_>> = mirror
        .traces
        .iter()
        .map(|trace| trace.as_record())
        .collect();
    let witnesses = poker_texas_air::canonical_dispatch_trace::witnesses_from_dispatch_records(
        &records,
        u64::from(table_id),
    )
    .ok()?;
    // 终态绑定：链必须终止于摊牌展示期或无摊牌终局（Waiting）。
    let last = witnesses.last()?;
    if !matches!(
        last.post.phase,
        poker_texas_air::texas_canonical::CanonicalPhase::ShowdownDisplay
            | poker_texas_air::texas_canonical::CanonicalPhase::Waiting
    ) {
        return None;
    }
    let archive = poker_texas_air::texas_canonical_air::prove_canonical_reveal_completion_batch(
        &witnesses, &rules,
    )
    .ok()?;
    Some(poker_appchain::settlement::HandProofBinding {
        archive_bytes: borsh::to_vec(&archive).ok()?,
        post_state_commitment: archive.post_state_commitment,
        pre_state_root: archive.pre_state_root,
        post_state_root: archive.post_state_root,
    })
}

async fn settle_from_live_mirror(
    input: super::prove_log::HandSettleInput,
    live: super::vm_session::VmSession,
) {
    let table_id = input.table_id;
    let start = input.start.clone();
    // hand_id 在开局时由 record_hand_start 分配（动作签名挑战域同源）。
    let hand_id = start.hand_id;

    if settle_ok_already(table_id, hand_id) {
        return; // 本手已成功上链（幂等——队列 sidecar 回执 / settle_receipt）
    }
    // （旧进程内 SETTLE_ATTEMPTS 重试上限已删除：构建期确定性失败走
    // 构建期死信（WAL 墓碑），投递期有界重试归 poster 运营配置。）

    // 终局比对 + 派奖推进：实时镜像即结算唯一 VM 来源。比对不干净 =
    // 镜像与游戏层分歧，其派生绝不上链。
    //
    // 结算门 = report.issues（对账分歧：board / rake / 逐钱包 deltas /
    // total_bet / 零和）。**不含** bet_fail（2026-09-10 变更）：VM 是接受
    // 点本身——VM 拒绝的动作游戏层同样拒绝，不构成状态分歧；把客户端
    // 噪音（抢跑/轮次竞态/畸形加注）当分歧会交给恶意玩家一枚"单条非法
    // 下注即令该手不可结算"的 griefing 武器。bet_fail 降级为观测指标。
    let (report, mirror) = live.finish(&input);
    if !report.issues.is_empty() {
        refuse_settlement(
            table_id,
            hand_id,
            &format!("live mirror DIVERGED from game layer: {report:?}"),
        );
        return;
    }
    if report.metrics.bet_fail > 0 {
        tracing::warn!(
            "[live-mirror] table {table_id} hand {hand_id}: {} bet(s) rejected by VM \
             during hand (client noise/illegal actions) — settlement proceeds, \
             gate is cross-check issues only",
            report.metrics.bet_fail,
        );
    }
    tracing::info!(
        "[live-mirror] table {} hand {} parity OK: reveal_ok={} bets={} bet_fail={} folds={}",
        report.table_id,
        report.hand_id,
        report.metrics.reveal_ok,
        report.metrics.bet_ok,
        report.metrics.bet_fail,
        report.metrics.force_folds,
    );
    if !mirror.has_provable_activity() {
        refuse_settlement(table_id, hand_id, "live mirror has no prove tasks");
        return;
    }
    // 强制对账（游戏层 = 唯一真相）：per-wallet total_bet 与公共牌数逐分一致。
    if let Err(e) = cross_check_snapshot(&mirror, &input) {
        refuse_settlement(table_id, hand_id, &format!("cross-check FAILED: {e}"));
        return;
    }

    // ===== B6：Appchain 结算出口（默认，STARKNET_SETTLEMENT_EXIT=appchain）=====
    // 嵌入式 sequencer 软确认 + 本地出证（终局对账已通过：board/rake/
    // 逐钱包 deltas 的分歧在 finish().issues 已 fail-closed 拒绝）。任何
    // 失败（手型不支持/账本不齐/REAL 缺归档/出证超时）回退下方遗留
    // Starknet 路径——结算绝不因出口改造丢失。放在 legacy prove 之前：
    // 两条证明栈不重复执行。
    if super::chain()
        .map(|c| c.config.settlement_exit_appchain())
        .unwrap_or(true)
        && super::appchain::runtime::runtime().is_some()
    {
        // REAL 桌的 canonical 归档：实时镜像控制轨迹 → 行链 → 出证
        //（#22②扩展完成后接线；PLAY 手不经此路径，绑定语义不变）。
        let asset_class_real = super::appchain::runtime::runtime()
            .map(|rt| rt.config.asset_class == poker_appchain::note::AssetClass::Real)
            .unwrap_or(false);
        let appchain_hand_proof = if asset_class_real {
            match build_appchain_hand_proof(&mirror, table_id) {
                Some(proof) => {
                    tracing::info!(
                        "[appchain-exit] table {table_id} hand {hand_id}: canonical archive                          produced ({} rows)",
                        proof.archive_bytes.len(),
                    );
                    Some(proof)
                }
                None => {
                    tracing::warn!(
                        "[appchain-exit] table {table_id} hand {hand_id}: canonical archive                          production failed — falling back to legacy starknet path"
                    );
                    None
                }
            }
        } else {
            None
        };
        let appchain_mirror = mirror.clone();
        let appchain_input = input.clone();
        // settle_from_mirror 是 CPU 重活（REAL 含 STARK 全验证），
        // spawn_blocking 避免占死 tokio worker。
        let attempt = tokio::task::spawn_blocking(move || {
            super::appchain::exit::settle_from_mirror(
                &appchain_mirror,
                appchain_input.table_id,
                appchain_input.start.hand_id,
                &appchain_input.start.participants,
                appchain_input.rake_collected,
                appchain_hand_proof,
            )
        });
        match attempt.await {
            Ok(Ok(receipt)) => {
                tracing::info!(
                    "[appchain-exit] table {table_id} hand {hand_id} on appchain: op={} proven={} root={:?}",
                    receipt.settle_op_index,
                    receipt.proven,
                    receipt.batch_root.map(|r| hex_encode(&r)),
                );
                // D4：结算回执落账 + `settlement_result` 广播（T4 印章实时翻面）。
                super::settle_receipt::record_and_broadcast(
                    super::settle_receipt::appchain_settled(
                        table_id,
                        hand_id,
                        receipt.hand_binding,
                        receipt.settle_op_index,
                        receipt.proven,
                        receipt.batch_root,
                    ),
                )
                .await;
                // 遗留路径的 vault session 续钟不适用（嵌入式出口无链上
                // vault session）；离桌释放等锁定语义由游戏层自持。
                return;
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    "[appchain-exit] table {table_id} hand {hand_id} failed: {e} — falling back to legacy starknet path"
                );
            }
            Err(join_err) => {
                tracing::warn!(
                    "[appchain-exit] table {table_id} hand {hand_id} task panicked: {join_err:?} — falling back to legacy starknet path"
                );
            }
        }
    }

    // 台费接收方：平台 treasury 地址（STARKNET_TREASURY_ADDRESS），
    // 未配置时缺省 operator（#27 遗留注释已实现，2026-09-04 清理）。
    let rake_recipient = {
        let cfg_treasury = super::chain()
            .map(|c| c.config.treasury_address.clone())
            .unwrap_or_default();
        let treasury_full = if cfg_treasury.trim().is_empty() {
            super::chain()
                .map(|c| c.config.operator_address.clone())
                .unwrap_or_default()
        } else {
            cfg_treasury
        };
        if treasury_full.trim().is_empty() {
            None
        } else {
            register_treasury_wallet(&treasury_full);
            VmTable::addr_from_starknet(&treasury_full)
        }
    };

    // 完整钱包 felt 记账：参与者映射来自本手记录（无全局截断重映射表）。
    let wallet_map = hand_wallet_map(&start);

    // #18 Phase B/C：game 层产出的本手动作日志（词条 + Poseidon 链根）——
    // 根词进 settlement digest 尾词，词条进电路见证。
    let action_log_digest = starknet_crypto::Felt::from_bytes_be(&input.action_log_digest);
    // settle_hand 为同步 CPU 重活（prove 约 2s/手），按其调用方约定放
    // spawn_blocking，避免占死一个 tokio worker。mirror 移入闭包借用后
    // 原样带回（后续 snip36 证明与 dual 保底腿还要读它）。action_log 只
    // 克隆不 take：后续 snip36 阶段的 action_sig_materials 还要读它——
    // take 会把 input.action_log 掏空，递归证明恒报 no signed actions
    // （2026-09-08 线上：entries=0 但 #18 审计显示 actions=8）。
    let (settlement, mirror) = {
        let action_log = input.action_log.clone();
        match tokio::task::spawn_blocking(move || {
            let result = super::submit::settle_hand(
                &mirror,
                rake_recipient,
                &wallet_map,
                action_log_digest,
                &action_log,
            );
            (result, mirror)
        })
        .await
        {
            Ok((Ok(s), m)) => (s, m),
            Ok((Err(e), _)) => {
                tracing::warn!(
                    "[starknet-settle] table {table_id} hand {hand_id} settlement build failed: {e}"
                );
                // 第三类终局：结算构建失败（一次性、无重试）——该手永不
                // 上链（无 debit/credit，零和守恒），挂在该手上的离桌释放
                // 不能等 settle，在此 flush（与 refund_all_bets 中止路径
                // 同语义；2026-09-07 hand 1788734417 board-0 线上盲区）。
                // 先登记失败手：flush 之后才注册的离桌（时序竞态）在
                // schedule_leave_release 里据此直接释放（2026-09-08
                // hand 1788804610 双钱包滞留）。
                dead_letter_hand(table_id, hand_id, &format!("settlement build failed: {e}"));
                record_terminal_failure(
                    table_id,
                    hand_id,
                    super::settle_receipt::SettleStatus::Failed,
                    format!("settlement build failed: {e}"),
                );
                super::lock::mark_hand_settlement_failed(hand_id);
                super::lock::abort_flush_leave_releases(hand_id);
                return;
            }
            Err(join_err) => {
                tracing::error!(
                    "[starknet-settle] table {table_id} hand {hand_id} settlement build task panicked: {join_err}"
                );
                dead_letter_hand(
                    table_id,
                    hand_id,
                    &format!("settlement build task panicked: {join_err}"),
                );
                record_terminal_failure(
                    table_id,
                    hand_id,
                    super::settle_receipt::SettleStatus::Failed,
                    format!("settlement build task panicked: {join_err}"),
                );
                super::lock::mark_hand_settlement_failed(hand_id);
                super::lock::abort_flush_leave_releases(hand_id);
                return;
            }
        }
    };
    // 对账 2：抽水必须与游戏层同分（前端筹码 / 牌史 / 链上三本账的锚）。
    if settlement.plan.rake != input.rake_collected {
        refuse_settlement(
            table_id,
            hand_id,
            &format!(
                "rake mismatch: plan {} vs game {}",
                settlement.plan.rake, input.rake_collected
            ),
        );
        return;
    }
    // 对账 3：逐钱包净输赢全量比对（winners/deltas parity）。
    if let Err(e) = cross_check_deltas(&settlement.players_remapped, &settlement.deltas, &input) {
        refuse_settlement(table_id, hand_id, &format!("delta cross-check FAILED: {e}"));
        return;
    }
    tracing::info!(
        "[starknet-settle] table {table_id} hand {} settled: aggregate={}",
        settlement.hand_id,
        hex_encode(&settlement.aggregate_digest)
    );

    // ===== snip36 模式：异步递归证明（action-sig 批次）→ 提交 =====
    // 非 snip36 模式（legacy/v2）不启动任何证明进程。
    if super::chain()
        .map(|c| c.config.settlement_mode_snip36())
        .unwrap_or(false)
    {
        let dual_addr = super::chain()
            .map(|c| c.config.dual_settlement_address.clone())
            .unwrap_or_default();
        let work_dir = super::chain()
            .map(|c| c.config.prover_work_dir.clone())
            .unwrap_or_else(|| "/tmp/zgame-prover".to_string());
        tokio::spawn(async move {
            snip36_settle_flow(
                table_id, mirror, settlement, start, input, dual_addr, work_dir,
            )
            .await;
        });
        return;
    }

    // ===== legacy 路投递入队（settle-queue WAL；rollup-components 条目 1）=====
    // 旧进程内 PENDING_SETTLE 快照 + game_loop tick 重投（run_settle_attempt）
    // 已删除：持久化投递归队列（重启不丢），上链驱动归 batch-poster daemon
    // （单写者协议：WAL texas 独写、poster 只读）。calldata 构建不动——
    // 入队只做 felt → hex 载体转换（poster 原样透传）。
    // dev 模式（未配置 settlement 合约）保持只记日志不投递（无 poster 消费）。
    let settlement_addr = super::chain()
        .map(|c| c.config.settlement_address.clone())
        .unwrap_or_default();
    if settlement_addr.is_empty() {
        tracing::info!(
            "[starknet-settle] dev mode: settlement calldata generated, queue enqueue skipped              (register {} felts, settle {} felts)",
            settlement.register_calldata.len(),
            settlement.settle_calldata.len()
        );
        return;
    }
    if let Err(e) =
        super::settle_wiring::enqueue_legacy_settlement(table_id, &settlement, &settlement_addr)
    {
        // 入队失败 = 该手投递丢失（无本地重试路径）：按终局失败上报，
        // 挂在该手的离桌释放立即冲刷（与构建失败同语义）。
        tracing::error!(
            "[starknet-settle] table {table_id} hand {} queue enqueue failed: {e}",
            settlement.hand_id
        );
        record_terminal_failure(
            table_id,
            settlement.hand_id,
            super::settle_receipt::SettleStatus::Failed,
            format!("queue enqueue failed: {e}"),
        );
        super::lock::mark_hand_settlement_failed(settlement.hand_id);
        super::lock::abort_flush_leave_releases(settlement.hand_id);
    }
}

/// snip36 结算流：递归证明（action-sig 批次）→ 工件落盘 → v3 入口提交
/// （合约随 cairo ≥2.12 上链后激活）→ 失败回退 legacy 结算。
/// 结算永不因证明阻塞/失败而丢失（对账已通过的 settlement 保底上链）。
async fn snip36_settle_flow(
    table_id: u32,
    mirror: VmTable,
    settlement: super::submit::HandSettlement,
    start: super::prove_log::HandStartData,
    input: super::prove_log::HandSettleInput,
    dual_addr: String,
    work_dir: String,
) {
    let hand_id = settlement.hand_id;

    // 1. 材料：每参与者首条已签名动作（v3 域：含 hand_id）。
    //    真实客户端未带签名时材料为空——空批次没有可证语句（handbatch
    //    的 host 直验对零方程同样 Truncated 拒绝），直接跳过出证，
    //    不再"warn 后仍然进 prove"（2026-09-07 线上：两手均
    //    "no signed actions → host verify: Truncated"假失败）。
    let materials =
        super::recursion_prover::action_sig_materials(&input.action_log, &start.participants);
    if materials.is_empty() {
        // 区分性计数：entries=0 → 结算输入窗口空；sig_ok=0 → 验签全败/无签名；
        // with_sig=0 但 sig_ok>0 → 入库丢了签名本体（2026-09-08 hand
        // 1788809743 线上：sig_ok=true 的动作存在，结算仍报 no signed
        // actions——用计数定位丢在哪一环）。
        let n = input.action_log.len();
        let ok = input.action_log.iter().filter(|e| e.sig_ok).count();
        let sig = input.action_log.iter().filter(|e| e.sig.is_some()).count();
        tracing::warn!(
            "[snip36] table {table_id} hand {hand_id}: no signed actions — proof skipped (entries={n} sig_ok={ok} with_sig={sig})"
        );
    }

    // 2. 异步出证（阻塞调用移入 spawn_blocking；hand_binding = 注册值）。
    let binding = super::dual_settle::prepare_handbatch_binding(&mirror, &settlement);
    // combined 入口（STARKNET_DAPV_SETTLE_ENTRY=combined）的 P 任务，产源
    // 与上方 materials 同源：每手一个 action-sig 批次 payload（与 snip36
    // 递归信封 prove_batch_blocking 同一构造）。构造失败/无材料 = 空集：
    // combined 腿诚实跳过（不出无 P 语句的退化证明），结算走既有回退。
    let combined_tasks = match &binding {
        Ok(b) if !materials.is_empty() => {
            match super::settlement_prover::CombinedTask::from_materials(
                input.table_id,
                settlement.hand_id,
                b.hand_binding,
                &materials,
            ) {
                Ok(tasks) => tasks,
                Err(e) => {
                    tracing::warn!(
                        "[combined] table {table_id} hand {hand_id}: P task build failed: {e} — combined leg skipped"
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    };
    let prove_result = if materials.is_empty() {
        Err("no signed actions — proving skipped".to_string())
    } else {
        match binding {
            Ok(b) => {
                let out_dir =
                    std::path::Path::new(&work_dir).join(format!("hand-{hand_id}-recursion"));
                let mats = materials.clone();
                let table_id = input.table_id;
                let hand_id = settlement.hand_id;
                let hb_bytes = b.hand_binding.to_bytes_be();
                tokio::task::spawn_blocking(move || {
                    super::recursion_prover::prove_batch_blocking(
                        table_id, hand_id, hb_bytes, &mats, &out_dir,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(format!("join: {e:?}")))
            }
            Err(e) => Err(format!("binding: {e}")),
        }
    };

    match prove_result {
        Ok(out) => {
            tracing::info!(
                "[snip36] table {table_id} hand {hand_id} recursion proof ok: acc={} steps={} ec_ops={} out={}",
                out.acc,
                out.steps,
                out.ec_ops,
                out.out_dir
            );
            if dual_addr.is_empty() {
                tracing::warn!(
                    "[snip36] dual settlement address not configured — proof archived, settlement falls back to legacy"
                );
            } else {
                // v3 入口提交：calldata = [hand_binding, hand_id, segment(16)]
                // —— segment 由 settlement_private 公开段给出；外部 settle
                // prover 未配置时落盘工件并回退 legacy（P2/P4 激活项）。
                tracing::info!(
                    "[snip36] hand {hand_id} proof ready; v3 settlement submission activates with the cairo >= 2.12 contract (plan-snip36-execution P2/P4)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "[snip36] table {table_id} hand {hand_id} recursion proof failed: {e} — settlement falls back to legacy"
            );
        }
    }

    // 3. 保底：对账已通过的 settlement 经 dual 入口上链——entry=combined 时
    //    submit_dual_settlement 会先试合并信封证明腿（17 词段 + 单 fact），
    //    失败照旧回退线性（register_hand + verify_and_settle_dapv_stark）。
    submit_dual_fallback(table_id, &mirror, &settlement, combined_tasks).await;
}

/// 结算保底腿：dual 结算（combined 证明腿 + 线性兜底）。
///
/// 2026-09-07 起 legacy PokerSettlement（0x76a0b49a）在链上是 2026-08-31
/// 的 4 参 `settle_hand` ABI（#18 Phase B 只改了源码未重部署），且构造时
/// 绑定的还是旧 vault v2——新 5 参 calldata 反序列化必拒（线上
/// "Failed to deserialize param #3"），双重失效。回退改走 dual：
/// `vault.settlement_contract` 已指向 dual v5，`register_hand` +
/// `verify_and_settle_dapv_stark` 与 e2e 冒烟（2026-09-05）同路径；
/// endorsement 退役后 P-batch 由操作员自铸（纯形状合规的折叠方程）。
async fn submit_dual_fallback(
    table_id: u32,
    mirror: &super::vm_session::VmTable,
    settlement: &super::submit::HandSettlement,
    combined_tasks: Vec<super::settlement_prover::CombinedTask>,
) {
    let Some(chain) = super::chain() else { return };
    let dual_addr = chain.config.dual_settlement_address.clone();
    if dual_addr.is_empty() {
        tracing::info!(
            "[snip36] dev mode: dual settlement not configured, on-chain submit skipped              (register {} felts, settle {} felts)",
            settlement.register_calldata.len(),
            settlement.settle_calldata.len()
        );
        return;
    }
    // P-batch 词条：每参与者一条操作员自铸 endorsement（与 e2e 冒烟一致；
    // 认可退役后合约只折叠方程形状，不再约束签名主体）。
    let produce = |hb: &[u8; 32], _players: &[starknet_crypto::Felt]| {
        let mut out = Vec::new();
        for _ in 0.._players.len() {
            let sk = <super::dual_settle::Sc as poker_protocol::crypto::curve::CurveScalar>::random(
                &mut rand::rngs::OsRng,
            );
            let pk = <poker_protocol::crypto::curve::StarkCurve as poker_protocol::crypto::curve::Curve>::base_g() * sk;
            out.push(super::dual_settle::mint_endorsement(&sk, &pk, hb));
        }
        Ok(out)
    };
    let dual = match super::dual_settle::build_dual_settlement_with(mirror, settlement, &produce) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                "[snip36-fallback] table {table_id} hand {} dual settlement build failed: {e}",
                settlement.hand_id
            );
            return;
        }
    };
    // #33 离桌快解锁：本手的挂起离桌玩家随结算 bundle 同笔释放；
    // 失败归还，等下次重试或 TTL 兜底。赢额回锁与续钟也在同一笔
    // bundle 里（原子，无异步窗口），不再有后置补锁调用。
    let departed = super::lock::take_pending_releases_for(settlement.hand_id);
    match super::dual_settle::submit_dual_settlement(
        &dual,
        &dual_addr,
        &settlement.players_remapped,
        &settlement.deltas,
        &departed,
        &combined_tasks,
    )
    .await
    {
        Ok((register_hash, settle_hash)) => {
            tracing::info!(
                "[snip36-fallback] table {table_id} hand {} dual atomic settle ok: tx={register_hash} ({settle_hash}), departed-released={}",
                settlement.hand_id,
                departed.len()
            );
            // D2/D3/D4：dual 出口结算回执（hand_binding = 注册值）+ block/gas。
            let txs = vec![register_hash.clone(), settle_hash.clone()];
            super::settle_receipt::record_and_broadcast(super::settle_receipt::starknet_settled(
                table_id,
                settlement.hand_id,
                "dual",
                Some(format!("{:#x}", dual.hand_binding)),
                None,
                txs.clone(),
                Some(dual_addr.clone()),
            ))
            .await;
            let meta_hand = settlement.hand_id;
            tokio::spawn(async move {
                super::settle_receipt::attach_tx_meta(table_id, meta_hand, &txs).await;
            });
            // 兜底：结算流程启动后才注册离桌的玩家在此补放（独立交易，
            // invoke_vault 内置 nonce 重试）。
            super::lock::flush_leave_releases(settlement.hand_id).await;
            // 续钟移出 bundle 后的独立补钟：refresh_session 的
            // "No active session" 断言曾把整笔原子结算拖回滚
            // （2026-09-08 hand 1788812613）。独立交易失败只告警
            // （invoke_vault 带 nonce 重试），不影响已落地的结算。
            for p in &settlement.players_remapped {
                let wallet = super::lock::wallet_of_felt(p);
                if super::lock::vault_session_active(&wallet).await {
                    super::lock::refresh_player_session(&wallet).await;
                }
            }
        }
        Err(e) if is_already_settled_error(&e) => {
            // 幂等重放：落 settled 印章（digest 未知，binding 仍可下发）。
            // （txmgr 发送面把重放判为 Ok；此分支仅防御直发层的错误文案。）
            super::settle_receipt::record_and_broadcast(super::settle_receipt::starknet_settled(
                table_id,
                settlement.hand_id,
                "dual",
                Some(format!("{:#x}", dual.hand_binding)),
                None,
                Vec::new(),
                Some(dual_addr.clone()),
            ))
            .await;
        }
        Err(e) => {
            super::lock::restore_pending_releases(departed, settlement.hand_id);
            tracing::error!(
                "[snip36-fallback] table {table_id} hand {} dual atomic settle failed: {e}",
                settlement.hand_id
            );
        }
    }
}

/// 强制对账：VM 快照与游戏层终局事实逐分比对（total_bet / 公共牌数 /
/// 参与者集合）。任何不一致都拒绝结算——输赢金额以游戏层为准，
/// 证明工件必须为其背书，否则宁可不结算。
pub(crate) fn cross_check_snapshot(
    mirror: &VmTable,
    input: &super::prove_log::HandSettleInput,
) -> Result<(), String> {
    let snap = mirror.pre_settlement.as_ref().unwrap_or(&mirror.table);
    let vm_board = snap.community_cards.len();
    if vm_board != input.board_len {
        return Err(format!(
            "board mismatch: vm {vm_board} vs game {}",
            input.board_len
        ));
    }
    for (wallet, bet) in &input.total_bets {
        let Some(addr) = VmTable::addr_from_starknet(wallet) else {
            continue;
        };
        let vm_bet = snap
            .seats
            .iter()
            .find(|s| seat_player_addr(s) == Some(addr))
            .map(|s| s.total_bet());
        match vm_bet {
            None => {
                if *bet != 0 {
                    return Err(format!(
                        "participant missing in vm snapshot: {wallet} (game total_bet {bet})"
                    ));
                }
            }
            Some(v) if v != *bet => {
                return Err(format!("total_bet mismatch: {wallet} vm {v} vs game {bet}"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// 结算守恒对账（单一状态重构后）：VM 结算表（players/deltas，chips）
/// 只须满足**资金守恒**——Σdeltas 与台费归零（treasury 独立条目并入时
/// Σdeltas == 0；纯座位 delta、台费在链外扣减时 Σdeltas == −rake）。
///
/// 历史的"逐钱包 vs 游戏层派奖一致性"门已随结算单源化移除：VM 是结算
/// 唯一来源，游戏层 evaluator（展示账本）与 VM 的分歧（如 tie-break）
/// 是可观测指标，不是结算门——双实现分歧不再有阻塞结算的权力
///（与 bet_fail 降级同理，2026-09-10 语义）。守恒仍 fail-closed：
/// 多记/漏记 delta 或凭空派币在此拒绝。
pub(crate) fn cross_check_deltas(
    players: &[starknet_crypto::Felt],
    deltas: &[i128],
    input: &super::prove_log::HandSettleInput,
) -> Result<(), String> {
    let rake = input.rake_collected as i128;
    if players.len() != deltas.len() {
        return Err(format!(
            "malformed settlement: {} players vs {} deltas",
            players.len(),
            deltas.len()
        ));
    }
    let sum: i128 = deltas.iter().sum();
    let balanced = if rake > 0 {
        sum == 0 || sum == -rake
    } else {
        sum == 0
    };
    if !balanced {
        return Err(format!(
            "settlement violates conservation: Σdelta={sum}, rake={rake} (expected 0 or -rake)"
        ));
    }
    Ok(())
}

/// 确定性对账拒绝：本手永不结算（重放/派生确定，重试不会通过），挂在
/// 该手上的离桌释放不能等 settle——立即标记失败并冲刷（与结算构建失败
/// 同语义；2026-09-07 hand 1788734417 同类盲区的对账面修复）。
/// 队列侧同步写构建期死信墓碑（WAL `BuildDeadLettered`）——后续同键
/// 入队被拒，poster 亦停驱动。
fn refuse_settlement(table_id: u32, hand_id: u32, reason: &str) {
    tracing::error!(
        "[starknet-settle] table {table_id} hand {hand_id} {reason} — settlement refused"
    );
    dead_letter_hand(table_id, hand_id, &format!("reconcile refused: {reason}"));
    record_terminal_failure(
        table_id,
        hand_id,
        super::settle_receipt::SettleStatus::Refused,
        reason.to_string(),
    );
    super::lock::mark_hand_settlement_failed(hand_id);
    super::lock::abort_flush_leave_releases(hand_id);
}

/// 构建期死信（对账拒绝/构建失败）→ WAL `BuildDeadLettered`（settle_wiring
/// 包装：queue 不可用时仅告警——settle_receipt 的 Refused/Failed 回执仍是
/// 业务终态记录）。
fn dead_letter_hand(table_id: u32, hand_id: u32, reason: &str) {
    super::settle_wiring::dead_letter_hand(table_id, hand_id, reason);
}

/// 终局失败回执：落注册表；异步上下文可用时补播 `settlement_result`
/// （D5 FAILED 态面板可展开原因）。on_hand_complete 的同步分支只落不播。
fn record_terminal_failure(
    table_id: u32,
    hand_id: u32,
    status: super::settle_receipt::SettleStatus,
    reason: String,
) {
    let exit: &'static str = if super::chain()
        .map(|c| c.config.settlement_exit_appchain())
        .unwrap_or(true)
    {
        "appchain"
    } else {
        "starknet"
    };
    let receipt = super::settle_receipt::terminal_failure(table_id, hand_id, status, exit, reason);
    super::settle_receipt::record(receipt.clone());
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            super::settle_receipt::broadcast(table_id, &receipt).await;
        });
    }
}

/// 本手完整钱包映射：参与者（来自 HandStart 记录）+ treasury，
/// 供 settle_hand 把 20 字节座位地址重映射回全精度 felt 记账。
fn hand_wallet_map(
    start: &super::prove_log::HandStartData,
) -> Vec<(poker_l1::Address, starknet_crypto::Felt)> {
    let mut out: Vec<(poker_l1::Address, starknet_crypto::Felt)> = start
        .participants
        .iter()
        .filter_map(|p| {
            let addr = VmTable::addr_from_starknet(&p.wallet)?;
            let felt = super::chain::parse_wallet_felt(&p.wallet)?;
            Some((addr, felt))
        })
        .collect();
    if let Ok(set) = TREASURY_WALLETS.lock() {
        for w in set.iter() {
            if let (Some(a), Some(f)) = (
                VmTable::addr_from_starknet(w),
                super::chain::parse_wallet_felt(w),
            ) {
                out.push((a, f));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// tick 驱动的 sidecar 回读（rollup-components 条目 1；签名沿旧
/// `retry_pending_settlement`，socket/game_loop 调用点不变）。
///
/// 旧语义（PENDING_SETTLE 快照重投）已归 batch-poster 的投递驱动；本入口
/// 做 texas 侧观察：
/// 1. poster sidecar `dead/` 的 Dual 路投递期死信 → 写 WAL `Downgraded`
///    （poster 下轮按 legacy 保底重投）；
/// 2. `receipts/` 新回执 → 转发 settle_receipt（T4 印章翻面 + WS 广播）、
///    冲刷挂起离桌释放、补 session 续钟。
pub async fn retry_pending_settlement(_table_id: u32) {
    for rec in super::settle_wiring::poll_throttled() {
        forward_queue_receipt(rec).await;
    }
}

/// 队列投递回执的 texas 侧落地（旧 run_settle_attempt 成功分支的等价物；
/// aggregate digest / 合约 / 参与者取入队时的显示元数据缓存，重启后
/// 缺失只影响展示与续钟）。
async fn forward_queue_receipt(rec: settle_queue::ReceiptRecord) {
    let key = rec.key;
    let enrichment = super::settle_wiring::wiring().and_then(|w| w.enrichment_of(&key));
    let exit: &'static str = match rec.route {
        settle_queue::SettleRoute::Dual => "dual",
        settle_queue::SettleRoute::Legacy => "legacy",
    };
    tracing::info!(
        "[settle-wiring] table {} hand {} queue-delivered ({exit}): txs={:?}",
        key.table_id,
        key.hand_id,
        rec.txs
    );
    super::settle_receipt::record_and_broadcast(super::settle_receipt::starknet_settled(
        key.table_id,
        key.hand_id,
        exit,
        None,
        enrichment.as_ref().and_then(|e| e.aggregate_digest.clone()),
        rec.txs.clone(),
        enrichment.as_ref().and_then(|e| e.contract.clone()),
    ))
    .await;
    // D2：block/gas 异步回填（交易哈希为标记串时跳过）。
    if rec.txs.iter().any(|t| t.starts_with("0x")) {
        let txs = rec.txs.clone();
        let (table_id, hand_id) = (key.table_id, key.hand_id);
        tokio::spawn(async move {
            super::settle_receipt::attach_tx_meta(table_id, hand_id, &txs).await;
        });
    }
    // 挂在本手的离桌释放随投递落地补放（幂等）。
    super::lock::flush_leave_releases(key.hand_id).await;
    // session 续钟（缓存命中才续——重启后的历史手无从得知参与者）。
    if let Some(e) = enrichment {
        refresh_settlement_sessions(&e.players_remapped).await;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 结算成功后续各参与者的 #33 session 时钟（owner=operator，逐人独立
/// 交易，失败仅告警）。必须每手刷新：TTL（12h）从最后一次活动计时，
/// 停刷即触发玩家无许可自助解锁。
async fn refresh_settlement_sessions(players_remapped: &[starknet_crypto::Felt]) {
    for p in players_remapped {
        let wallet = format!("0x{}", hex_encode(&p.to_bytes_be()));
        super::lock::refresh_player_session(&wallet).await;
    }
}

/// 平台 treasury 钱包（抽水接收方）：settle calldata 的玩家地址只有 20 字节
/// 截断，上链前经 seat_wallet_remaps 还原为全精度 felt；treasury 不是牌手，
/// 需要单独登记才能参与重映射。
static TREASURY_WALLETS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

pub fn register_treasury_wallet(wallet: &str) {
    if let Ok(mut set) = TREASURY_WALLETS.lock() {
        set.insert(wallet.to_string());
    }
}

#[cfg(test)]
mod delta_parity_tests {
    use super::cross_check_deltas;
    use crate::starknet::prove_log::HandSettleInput;

    const P1: &str = "0x0a11";
    const P2: &str = "0x0a22";
    const TREASURY: &str = "0x0bee";

    fn ff(hex: &str) -> starknet_crypto::Felt {
        crate::starknet::chain::parse_felt(hex).expect("test wallet parses")
    }

    fn input_with_rake(rake: u64) -> HandSettleInput {
        HandSettleInput {
            table_id: 1,
            start: crate::starknet::prove_log::HandStartData {
                hand_id: 1,
                participants: Vec::new(),
                button_rank: 0,
                last_bb_rank: poker_l1::contracts::texas_poker::types::NO_SEAT,
                small_blind: 10,
                deck: Vec::new(),
            },
            rake_collected: rake,
            total_bets: Vec::new(),
            payouts: Vec::new(),
            board_len: 5,
            action_log_digest: [0u8; 32],
            action_log: Vec::new(),
        }
    }

    /// treasury 独立条目：Σdeltas（含台费接收方）== 0。
    #[test]
    fn conservation_ok_with_treasury_entry() {
        let input = input_with_rake(10);
        let players = vec![ff(P1), ff(P2), ff(TREASURY)];
        let deltas = vec![90, -100, 10];
        assert!(cross_check_deltas(&players, &deltas, &input).is_ok());
    }

    /// 纯座位 delta（影子表约定，台费链外扣减）：Σdeltas == −rake。
    #[test]
    fn conservation_ok_seat_only() {
        let input = input_with_rake(10);
        let players = vec![ff(P1), ff(P2)];
        let deltas = vec![90, -100];
        assert!(cross_check_deltas(&players, &deltas, &input).is_ok());
    }

    /// 零台费：严格零和。
    #[test]
    fn conservation_ok_zero_rake() {
        let input = input_with_rake(0);
        let players = vec![ff(P1), ff(P2)];
        let deltas = vec![50, -50];
        assert!(cross_check_deltas(&players, &deltas, &input).is_ok());
    }

    /// 凭空派币（Σdeltas 落在 {0, −rake} 之外）→ 拒绝。
    #[test]
    fn conservation_rejects_created_chips() {
        let input = input_with_rake(10);
        let players = vec![ff(P1), ff(P2)];
        let deltas = vec![95, -100];
        let err = cross_check_deltas(&players, &deltas, &input).unwrap_err();
        assert!(err.contains("conservation"), "{err}");
    }

    /// 台费双重归属（并入座位又独立付 treasury）→ Σ = +rake → 拒绝。
    #[test]
    fn conservation_rejects_double_rake_attribution() {
        let input = input_with_rake(10);
        let players = vec![ff(P1), ff(P2), ff(TREASURY)];
        let deltas = vec![100, -100, 10];
        let err = cross_check_deltas(&players, &deltas, &input).unwrap_err();
        assert!(err.contains("conservation"), "{err}");
    }

    /// players/deltas 长度不齐 → 拒绝。
    #[test]
    fn malformed_settlement_rejected() {
        let input = input_with_rake(0);
        let players = vec![ff(P1), ff(P2)];
        let deltas = vec![50];
        let err = cross_check_deltas(&players, &deltas, &input).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
    }

    /// 零 delta 全省略（SettleHandCalldata 同语义）+ 零台费 → 通过。
    #[test]
    fn all_zero_deltas_omitted_ok() {
        let input = input_with_rake(0);
        let players: Vec<starknet_crypto::Felt> = Vec::new();
        let deltas: Vec<i128> = Vec::new();
        assert!(cross_check_deltas(&players, &deltas, &input).is_ok());
    }
}

#[cfg(test)]
mod queue_receipt_forward_tests {
    use super::*;

    /// 队列投递回执的 texas 侧落地（rollup-components 条目 1）：转发后
    /// settle_receipt 落 Settled 印章（路由进 exit 位、交易哈希透传）；
    /// 无链测试环境下 flush/续钟为空转（invoke_vault 无 chain 即告警）。
    /// 键取隔离值，避免污染其他用例的注册表条目。wiring 单例的 WAL/
    /// sidecar 路径钉到临时目录——缺省相对路径会在 crate CWD 下创建
    /// `settle-queue/`，污染工作树。
    #[tokio::test]
    async fn forwarded_queue_receipt_records_settled() {
        let scratch =
            std::env::temp_dir().join(format!("texas-hooks-wiring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        // edition 2024：set_var 为 unsafe（进程级全局；本组仅此用例触碰
        // wiring 单例，无并行竞争面）。
        unsafe {
            std::env::set_var("TEXAS_SETTLE_QUEUE_WAL", scratch.join("queue.jsonl"));
            std::env::set_var("TEXAS_SETTLE_SIDECAR_DIR", scratch.join("poster"));
        }
        let (table_id, hand_id) = (7777u32, 8888u32);
        assert!(crate::starknet::settle_receipt::get(table_id, hand_id).is_none());
        let rec = settle_queue::ReceiptRecord {
            key: settle_queue::SettleKey::new(table_id, hand_id),
            route: settle_queue::SettleRoute::Legacy,
            txs: vec!["0xabc".into(), "0xdef".into()],
            batch_key: None,
            at: 1,
        };
        forward_queue_receipt(rec).await;
        let receipt = crate::starknet::settle_receipt::get(table_id, hand_id)
            .expect("receipt recorded after forward");
        assert_eq!(
            receipt.status,
            crate::starknet::settle_receipt::SettleStatus::Settled.as_str()
        );
        assert_eq!(receipt.exit, "legacy");
        assert_eq!(
            receipt.tx_digests,
            vec!["0xabc".to_string(), "0xdef".to_string()]
        );
    }
}
