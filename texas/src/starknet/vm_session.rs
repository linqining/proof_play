//! 单一 VM 会话（VmSession）——手牌的唯一 VM 状态表示（单一状态重构，
//! 原 shadow.rs 实时镜像 + mirror.rs 机械层合并；"mirror" 双状态模式已
//! 移除：VM 是规则与相位的唯一裁判，游戏层经 refresh_from_vm 派生视图）。
//!
//! 分层：
//! - [`VmTable`]：VM 表的 dispatch 包装（认证上下文 + ProveTask 收集）
//!   与已接受命令的应用原语（reveal canonical 重排 / bet / force_fold、
//!   pre-payout 快照、开局 deck 注入引导）；
//! - [`VmSession`]：每手一个，持有 [`VmTable`] + pk/wallet 映射 + 观测
//!   指标；游戏层 Table 的接受点（vm_try_bet / vm_try_reveal /
//!   vm_force_fold / refresh_from_vm）全部经此 dispatch。
//!
//! 类型桥接：服务端现有代码把前端 JSON 解析为 zgame poker_protocol（0.2.0）类型；
//! poker_l1 使用 poker_texas_air 内的 poker_protocol（0.1.0）类型。两份副本的
//! crypto/proofs 结构逐字节一致（构建期 diff 验证），通过 borsh roundtrip 转换。

// 实时 VM 镜像的机械层（`VmTable` + 开局引导 + 类型桥接）。
//
// 手牌只有一份 VM 状态表示：`shadow.rs` 的实时镜像在每个接受点同步
// dispatch（单一状态），结算时经其 `finish` 直接取用 ProveTask 链与
// pre-payout 快照。本模块不再持有"日志重放"路径——历史的
// `build_from_log`（结算时构建第二份 VM 状态）已随单一状态重构删除。
//
// 剩余职责：
// - [`VmTable`]：dispatch 包装（认证上下文 + ProveTask 收集）与
//   已接受命令的应用原语（reveal 重排 / bet / force_fold）；
// - [`bootstrap_vm_table`]：实时镜像的开局引导（join 重放 + deck 注入 +
//   DealHole 窗口），与 shadow.rs 共用；
// - [`conv`]：zgame poker_protocol → ptx 类型的桥接。
//
// 类型桥接：服务端现有代码把前端 JSON 解析为 zgame poker_protocol（0.2.0）类型；
// poker_l1 使用 poker_texas_air 内的 poker_protocol（0.1.0）类型。两份副本的
// crypto/proofs 结构逐字节一致（构建期 diff 验证），通过 borsh roundtrip 转换。

use poker_l1::contracts::dispatch::DispatchContext;
use poker_l1::contracts::texas_poker::dispatch::{self as texas_dispatch};
use poker_l1::contracts::texas_poker::dispatch::{
    RaiseArgs, RedealHoleCardArgs, SeatIndexArgs, SubmitReconstructDeckArgs,
    SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
use poker_l1::contracts::texas_poker::runtime::caller_id::wallet_to_address;
use poker_l1::contracts::texas_poker::types::{
    CipherDeck, SeatMask, ShuffleState, TexasPokerTable,
};
use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
// 别名：源仓库里 ptx_protocol 是 poker_protocol 的重命名依赖；迁入工作区后
// cargo 不允许同一路径依赖出现两次，这里用 use 别名等价替代。
use poker_protocol as ptx_protocol;
// 公开 re-export：e2e 测试与上层 hook 复用这些类型别名。
pub use ptx_protocol::crypto::DefaultCurve as PtxCurve;
pub use ptx_protocol::crypto::ElGamalCiphertext as PtxElGamalCiphertext;
pub use ptx_protocol::crypto::types::ECPoint as PtxECPoint;
pub use ptx_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as PtxRevealTokenProof;

/// 单桌镜像。生命周期：建桌 → 每手 start → 操作 → 结算 → 下一手。
#[derive(Clone, Debug)]
pub struct VmTable {
    pub table: TexasPokerTable,
    /// 当前手牌收集的证明任务（每手结算后清空）。
    pub tasks: Vec<ProveTask>,
    /// 控制轨迹（控制逻辑入 AIR 的原料）：每次**改变状态**的 dispatch 记录
    /// (命令 pre/post + 其全部 normalize micro-steps 的 pre/post)。canonical
    /// witness 生产者据此把一次 dispatch 展开为链式单街 micro-step 行——
    /// all-in 连跳不再折叠成一对 pre/post（PotCollected 单街投影分歧的
    /// 结构性修复基础）。每手与 tasks 同步清空。
    pub traces: Vec<DispatchTrace>,
    /// 派奖前快照（board/pot/total_bet 完整），供 SettleHandCalldata 构建。
    /// 在 showdown 展示期结束、advance_deadline 派奖之前调用 [`mark_pre_settlement`]。
    pub pre_settlement: Option<TexasPokerTable>,
    /// fold-win 快照的"待应用终局弃牌"座位：`mark_pre_settlement` 打在
    /// `fold(seat)` 应用之前，快照里该座位仍为未弃牌——结算派发时须先把
    /// 这一记弃牌应用到快照副本上，`derive_fold_win_plan` 才能看到
    /// "恰好一名未弃牌玩家"（showdown 路径恒为 None）。
    pub pre_settlement_final_fold: Option<u8>,
    /// 本 mirror 的 table_id 种子（hand_binding 的 table_id 分量）。
    pub table_seed: u64,
    /// 服务器 caller 地址（镜像内管理操作如 advance_deadline 的 caller）。
    caller: poker_l1::Address,
    block_height: u64,
    /// 抽水参数（begin_reveal_hand 时写入镜像桌面）。
    pub rake_bps: u16,
    pub rake_cap: u64,
    /// 测试时钟偏移（毫秒，生产恒 0；#[cfg(test)] 场景由测试写入）。
    #[cfg(test)]
    pub test_clock_offset_ms: u64,
}

/// 一次 dispatch 的控制轨迹：命令本身的 pre/post + normalize 级联的
/// 逐步 pre/post。post 链与下一步的 pre 逐字节咬合（同一表快照），
/// witness 生产者据此构造 call_seq 连续的 canonical 行链。
#[derive(Clone, Debug)]
pub struct DispatchTrace {
    /// dispatch 的方法 selector（canonical kind 映射依据）。
    pub selector: [u8; 32],
    /// canonical Borsh 命令载荷（与 ProveTask.raw_args 同源）。
    pub args: Vec<u8>,
    /// 认证时间戳（canonical completion opening 依据）。
    pub timestamp_ms: u64,
    /// 命令应用前的表。
    pub pre: TexasPokerTable,
    /// 命令 + 全部 normalize 之后的表（下一 trace 的 pre）。
    pub post: TexasPokerTable,
    /// normalize 级联的逐步轨迹（含命令内部触发的级联）。
    pub normalization: poker_l1::contracts::texas_poker::state_machine::NormalizationTrace,
}

impl DispatchTrace {
    /// 根 crate 生产者（canonical_dispatch_trace）的输入记录。
    pub fn as_record(&self) -> poker_texas_air::canonical_dispatch_trace::DispatchRecord<'_> {
        poker_texas_air::canonical_dispatch_trace::DispatchRecord {
            selector: &self.selector,
            args: &self.args,
            timestamp_ms: self.timestamp_ms,
            pre: &self.pre,
            post: &self.post,
            steps: self
                .normalization
                .steps
                .iter()
                .map(|s| poker_texas_air::canonical_dispatch_trace::StepRecord {
                    step: s.step,
                    pre: &s.pre,
                    post: &s.post,
                })
                .collect(),
        }
    }
}

impl VmTable {
    /// 建桌。`table_id_seed` 用于派生确定性的镜像对象 ID。
    pub fn new(
        table_id_seed: u64,
        creator: poker_l1::Address,
        max_players: u8,
        small_blind: u64,
        big_blind: u64,
        caller: poker_l1::Address,
    ) -> Self {
        let table = TexasPokerTable::new(
            ObjectID::new([0x5A; 20], table_id_seed),
            creator,
            max_players,
            small_blind,
            big_blind,
        );
        Self {
            table,
            table_seed: table_id_seed,
            tasks: Vec::new(),
            traces: Vec::new(),
            pre_settlement: None,
            pre_settlement_final_fold: None,
            caller,
            block_height: 1,
            // 与服务端 collect_rake_for_settlement 同源读 env
            // （STARKNET_RAKE_BPS/CAP）：镜像 deltas 是链上结算的权威输入，
            // 参数必须与服务端牌桌账同一套，否则改 env 只改一半，
            // 链上/前端每手偏差 = 抽水差额（2026-09-04 审核发现）。
            rake_bps: crate::pokergame::rake::rake_params().rake_bps,
            rake_cap: crate::pokergame::rake::rake_params().rake_cap,
            #[cfg(test)]
            test_clock_offset_ms: 0,
        }
    }

    /// 测试专用：快进镜像共识时钟（生产不可达——cfg(test) 字段）。
    #[cfg(test)]
    pub fn advance_test_clock(&mut self, delta_ms: u64) {
        self.test_clock_offset_ms += delta_ms;
    }

    /// 派奖前打快照（showdown reveal 完成、advance_deadline 之前调用）。
    pub fn mark_pre_settlement(&mut self) {
        self.pre_settlement = Some(self.table.clone());
    }

    fn test_clock_offset_ms(&self) -> u64 {
        #[cfg(test)]
        {
            self.test_clock_offset_ms
        }
        #[cfg(not(test))]
        {
            0
        }
    }

    fn context(&self, caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xA4; 32],
            },
            chain_id: 377,
            block_height: self.block_height,
            // 测试时钟偏移（生产恒 0）：e2e 需要把镜像共识时间快进过
            // deadline 以驱动 AdvanceDeadline 的超时分支，真时钟睡 10s 不可行。
            block_timestamp: crate::relayer::util::now_ms() + self.test_clock_offset_ms(),
        }
    }

    /// dispatch 一个动作并收集产出的 ProveTask（仅本模块的应用原语调用）。
    /// 控制轨迹同步捕获（控制逻辑入 AIR）：arm → dispatch → take，命令
    /// pre/post 与全部 normalize micro-steps 落入 [`Self::traces`]。
    fn apply(
        &mut self,
        caller: poker_l1::Address,
        selector: &[u8; 32],
        args: Vec<u8>,
    ) -> Result<(), String> {
        self.block_height += 1;
        let ctx = self.context(caller);
        let pre = self.table.clone();
        poker_l1::contracts::texas_poker::state_machine::arm_normalization_trace();
        let result = texas_dispatch::dispatch(&ctx, &mut self.table, selector, &args);
        // 无论成败都先取走轨迹（解除线程槽；拒绝路径的命令原子回滚，
        // 其轨迹不进 traces——只有落地状态的变化才可证明）。
        let mut normalization =
            poker_l1::contracts::texas_poker::state_machine::take_normalization_trace()
                .unwrap_or_default();
        let result = result.map_err(|e| format!("mirror dispatch failed: {e}"))?;
        // dispatch 级的 deadline 再武装（Betting{deadline:0} → arm）发生在
        // normalize 之后、不在任何 step 内——canonical 行模型的 post 含已
        // 武装的 deadline，末步 post 以 dispatch 终态为准（行链与命令行
        // 的 post 咬合）。
        if let Some(last) = normalization.steps.last_mut() {
            last.post = self.table.clone();
        }
        let output: DispatchOutput = borsh::from_slice(&result.return_value)
            .map_err(|e| format!("mirror dispatch output decode failed: {e}"))?;
        if let Some(task) = output.prove_task {
            self.tasks.push(task);
        }
        if self.table != pre {
            self.traces.push(DispatchTrace {
                selector: *selector,
                args,
                timestamp_ms: ctx.block_timestamp,
                post: self.table.clone(),
                normalization,
                pre,
            });
        } else {
            let _ = normalization; // 无状态变更（如 tick）：无可证明轨迹
        }
        Ok(())
    }

    /// 玩家入座（对应 SIT_DOWN_V2 的 join 步骤；仅 `begin_reveal_hand` 重放调用）。
    ///
    /// `player` 为玩家 Starknet 地址（20 字节），`pk` 为其 mental-poker ElGamal 公钥
    /// （与前端 pkHex 同源），`pk_ownership_proof` 为 80 字节 Schnorr 证明。
    fn join(
        &mut self,
        player: poker_l1::Address,
        buy_in_chips: u64,
        pk: PtxECPoint,
        tx_pk: Option<poker_l1::signature::TaggedPubkey>,
        pk_ownership_proof: Vec<u8>,
    ) -> Result<(), String> {
        use poker_l1::contracts::texas_poker::dispatch::JoinTableArgs;
        let args = borsh::to_vec(&JoinTableArgs {
            player,
            buy_in: buy_in_chips,
            pk,
            // P1-2 会话委托：核验过的会话交易公钥（None = 未登记哨兵，
            // 签名路径 fail-closed；mirror 注入路径不需要 tx 签名）。
            tx_pk: tx_pk.unwrap_or_else(|| poker_l1::signature::TaggedPubkey {
                tag: poker_l1::signature::encode_tag(
                    poker_l1::signature::SignatureScheme::Stark,
                    poker_l1::signature::CURRENT_VERSION,
                ),
                raw: vec![0u8; 32],
            }),
            pk_ownership_proof,
        })
        .map_err(|e| format!("encode join args: {e}"))?;
        self.apply(player, &texas_dispatch::selectors::join_table(), args)
    }

    /// 方案A 注入式开局：把游戏层**已终局**（全部客户端洗牌已验证、底牌已发）的
    /// deck 原样注入 VM，并让 VM 直接进入 DealHole reveal 窗口。
    ///
    /// `plan` 为按游戏座位号升序排列的参与座位（与 VM DealHole 的升序座位规范
    /// 对齐，保证 deck index → 玩家映射逐字节一致）；`button_rank` 是游戏层按钮
    /// 在该序列中的序号。此调用发生在任何 dispatch 之前，不产生 ProveTask，
    /// 后续 reveal/bet 任务在该注入状态上连续（满足 MethodBatch 状态连续性）。
    pub fn begin_reveal_hand(
        &mut self,
        deck: Vec<PtxElGamalCiphertext>,
        plan: &[(
            poker_l1::Address,
            u64,
            PtxECPoint,
            Option<poker_l1::signature::TaggedPubkey>,
            Vec<u8>,
        )],
        button_rank: u8,
        last_bb_rank: u8,
        hand_id: u32,
    ) -> Result<(), String> {
        // 全新手状态（VmTable 由调用方刚构造）：清上一手残留，保证
        // deck 注入点是干净 canonical 状态。
        self.pre_settlement = None;
        self.pre_settlement_final_fold = None;
        self.tasks.clear();
        self.traces.clear();
        self.table.community_cards.clear();
        self.table.pot = 0;
        self.table.hand_id = hand_id;

        // join：按升序座位计划重放（VM find_empty_seat 顺序填座 →
        // mirror 座位 rank == 游戏座位 rank）。
        for (player, buy_in, pk, tx_pk, proof) in plan {
            self.join(*player, *buy_in, pk.clone(), tx_pk.clone(), proof.clone())
                .map_err(|e| format!("begin_reveal join: {e}"))?;
        }
        if self
            .table
            .seats
            .iter()
            .all(|s| seat_player_addr(s).is_none())
        {
            return Err("begin_reveal: no joined seats".into());
        }
        // join_table 产生的座位是 Waiting（等待大盲）状态；VM 原生流程由
        // start_hand 的 promote_waiting_for_big_blind 提升，注入式开局跳过
        // start_hand，这里等价执行"全新桌全体 Waiting 座位同时入局"规则，
        // 使 DealHole 的 active 座位集合与游戏层参与者一致。
        for seat in self.table.seats.iter_mut() {
            seat.promote_waiting();
        }

        // button 对齐：游戏层按钮在参与座位中的 rank（VM post_blinds 据此
        // 计算盲注位置，与游戏层盲注玩家保持一致）。dead button 轮转轨道
        // last_bb_rank 一并注入：VM post_blinds 的轮转基准与游戏层
        // set_blinds 同源（游戏层对离场基准回退到前驱参与者，与
        // rank_of_rotation_base 的压缩映射一致），过渡手逐位一致。
        self.table.button = button_rank.min(self.table.max_players.saturating_sub(1) as u8);
        self.table.last_bb_seat = last_bb_rank;

        // 抽水规则：到手牌进入翻后（flop 及以后，即出现公共牌的争夺底池）才抽，
        // 翻前结束（无人跟注的 uncontested 底池）不抽。VM 结算的硬性不变量
        // `uncontested pot must not be raked` 天然满足前半条；这里启用百分比
        // 模式使"到翻后的争夺底池"按 bps 抽水（有单手 cap）。
        self.table.rake_mode = poker_l1::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
        self.table.rake_bps = self.rake_bps;
        self.table.rake_cap = self.rake_cap;

        // deck 注入 + contributor 全量 + 直接进入 DealHole：
        // pending_mask = 0（游戏层洗牌已在注入前完成，VM 跳过洗牌阶段），
        // advance_shuffle 触发 ShuffleComplete → start_preflop_reveal_phase →
        // 按 VM 规范（升序座位，每人 2 张）创建 DealHole reveal 窗口。
        let cards: [PtxElGamalCiphertext; 52] = deck
            .try_into()
            .map_err(|_| "mirror deck must contain exactly 52 cards".to_string())?;
        self.table.deck_state.encrypted = CipherDeck::Active(Box::new(cards));
        self.table.deck_state.cards_dealt = 0;
        self.table.deck_state.owner_readable_hole_cards.clear();
        let mut contributor_mask: SeatMask = 0;
        for idx in 0..usize::from(self.table.max_players) {
            if seat_player_addr(&self.table.seats[idx]).is_some() {
                contributor_mask |= 1u16 << idx;
            }
        }
        self.table.deck_state.contributor_mask = contributor_mask;
        self.table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0,
                    completed_mask: 0,
                },
                crate::relayer::util::now_ms(),
            )
            .map_err(|e| format!("mirror enter_initial_shuffling failed: {e}"))?;
        // 规范化推进：武装 deadline + 驱动 ShuffleComplete → DealHole，
        // 与 dispatch 后的 canonical 归一化保持一致。
        let mut events = Vec::new();
        poker_l1::contracts::texas_poker::state_machine::normalize_until_blocked(
            &mut self.table,
            crate::relayer::util::now_ms(),
            &mut events,
        )
        .map_err(|e| format!("mirror normalize after deck injection: {e}"))?;
        if self.table.reveal_token_state().is_none() {
            return Err("begin_reveal: DealHole reveal window did not start".into());
        }
        // 开局引导不是玩家命令：join 重放与 deck 注入的轨迹不进 traces——
        // 轨迹流从 DealHole 窗口起（首个真实命令的 pre = 注入后的 canonical
        // 起点状态，witness 生产者的链头绑定基准）。
        self.traces.clear();
        Ok(())
    }

    /// 当前 DealHole/Board/Showdown reveal 窗口中该座位待提交的密文
    /// （canonical 顺序）。调用方据此把客户端提交的 token 集合重排成
    /// VM 要求的 canonical 顺序（全有或全无）。
    pub fn pending_reveal_ciphertexts(
        &self,
        seat_index: u8,
    ) -> Result<Vec<PtxElGamalCiphertext>, String> {
        let Some(state) = self.table.reveal_token_state() else {
            return Err("reveal phase is NONE".into());
        };
        let mut out = Vec::new();
        for a in &state.assignments {
            if a.pending_mask & (1u16 << seat_index) != 0 {
                // showdown：验证目标是 ledger 保存的完整密文（与客户端生成
                // 证明所用密文逐字节一致）；其他阶段用当前 deck 密文。
                let ct = if self.table.reveal_phase()
                    == poker_l1::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN
                {
                    let poker_l1::contracts::texas_poker::types::RevealTarget::Hole {
                        seat_index: owner,
                        card_slot,
                    } = a.target
                    else {
                        return Err("showdown assignment must target hole".into());
                    };
                    self.table
                        .deck_state
                        .owner_readable_hole_cards
                        .get(owner, card_slot)
                        .map(|p| p.full_ciphertext)
                        .ok_or_else(|| "showdown partial ledger missing".to_string())?
                } else {
                    *self
                        .table
                        .deck_state
                        .encrypted
                        .get(a.encrypted_card_index as usize)
                        .ok_or_else(|| "reveal card index out of range".to_string())?
                };
                out.push(ct);
            }
        }
        Ok(out)
    }

    /// 玩家揭牌令牌提交（tokens/proofs 须已按 VM canonical 顺序重排，
    /// 见 [`Self::apply_recorded_reveal`]）。
    pub fn submit_reveal_tokens(
        &mut self,
        seat_index: u8,
        reveal_tokens: Vec<PtxECPoint>,
        proofs: Vec<PtxRevealTokenProof<PtxCurve>>,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitRevealTokensArgs {
            seat_index,
            reveal_tokens,
            proofs,
        })
        .map_err(|e| format!("encode reveal args: {e}"))?;
        self.apply(
            caller,
            &texas_dispatch::selectors::submit_player_reveal_tokens(),
            args,
        )
    }

    /// 持有者换牌（redeal_hole_card）：L1 校验下注轮/持有者/账本条目后
    /// 挂起下注轮并开启 Redealing 令牌窗口（进证明轨迹）。
    pub fn redeal_hole_card(&mut self, seat_index: u8, card_slot: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&RedealHoleCardArgs {
            seat_index,
            card_slot,
        })
        .map_err(|e| format!("encode redeal args: {e}"))?;
        self.apply(caller, &texas_dispatch::selectors::redeal_hole_card(), args)
    }

    /// 弃牌（仅 [`Self::apply_recorded_bet`] 调用）。
    pub(crate) fn fold(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::fold(), args)
    }

    /// 过牌（[`Self::apply_recorded_bet`] 与 e2e 对拍测试调用）。
    pub(crate) fn check(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::check(), args)
    }

    /// 跟注（[`Self::apply_recorded_bet`] 与 e2e 对拍测试调用）。
    pub(crate) fn call(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::call(), args)
    }

    /// 加注。`total_bet` 是加注后本轮总下注额（与 WS RAISE 语义一致）。
    /// 仅 [`Self::apply_recorded_bet`] 调用。
    pub(crate) fn raise(&mut self, seat_index: u8, total_bet: u64) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&RaiseArgs {
            seat_index,
            total_bet,
        })
        .map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::raise(), args)
    }

    /// 超时强制推进（game_loop tick 驱动）。
    pub fn advance_deadline(&mut self) -> Result<(), String> {
        // ShowdownDisplay 派奖前打快照：此刻摊牌 reveal 已完成（seat.hand 已物化
        // 两张明文牌），board/pot/total_bet 仍完整——正是 SettleHandCalldata 需要
        // 的 pre-payout 表。派奖后 board 复位、pot 清零，无法再派生 settlement plan。
        if matches!(
            self.table.hand_phase,
            poker_l1::contracts::texas_poker::types::HandPhase::ShowdownDisplay { .. }
        ) {
            self.mark_pre_settlement();
        }
        self.apply(
            self.caller,
            &texas_dispatch::selectors::advance_deadline(),
            Vec::new(),
        )
    }

    /// 玩家提交重构牌组（reconstruct V3 statement + proof）。L1 全字段重验
    /// （owner/aggregate/cards/carriers/epoch/digests 均由镜像状态重算），
    /// 最后一份提交在 normalize 内联完成 deck 重建 + 进入重构洗牌。
    pub fn submit_reconstruct_deck(
        &mut self,
        seat_index: u8,
        statement: poker_protocol::zk_shuffle::reconstruction::ReconstructionStatement<
            poker_protocol::crypto::DefaultCurve,
        >,
        proof: poker_protocol::zk_shuffle::reconstruction::ReconstructProof<
            poker_protocol::crypto::DefaultCurve,
        >,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitReconstructDeckArgs {
            seat_index,
            statement,
            proof,
        })
        .map_err(|e| format!("encode reconstruct args: {e}"))?;
        self.apply(
            caller,
            &texas_dispatch::selectors::submit_reconstruct_deck(),
            args,
        )
    }

    /// 玩家提交洗牌（重构后重洗相位；开局洗牌不经 dispatch——镜像在
    /// record_hand_start 时注入终局 deck）。
    pub fn submit_shuffle_v2(
        &mut self,
        seat_index: u8,
        output_cards: Vec<PtxElGamalCiphertext>,
        shuffle_proof: poker_protocol::zk_shuffle::ShuffleProof,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitShuffleV2Args {
            seat_index,
            output_cards,
            shuffle_proof,
        })
        .map_err(|e| format!("encode shuffle args: {e}"))?;
        self.apply(
            caller,
            &texas_dispatch::selectors::submit_shuffle_v2(),
            args,
        )
    }

    /// 当前镜像牌组（52 张，poker_l1 类型）。
    #[cfg(test)]
    pub fn deck(&self) -> Vec<PtxElGamalCiphertext> {
        self.table.deck_state.encrypted.to_vec()
    }

    /// 按玩家地址查镜像座位号。
    pub fn seat_index_of(&self, player: poker_l1::Address) -> Option<u8> {
        self.table
            .seats
            .iter()
            .position(|s| seat_player_addr(s) == Some(player))
            .map(|i| i as u8)
    }

    fn seat_player(&self, seat_index: u8) -> Result<poker_l1::Address, String> {
        self.table
            .seats
            .get(seat_index as usize)
            .and_then(seat_player_addr)
            .ok_or_else(|| format!("mirror seat {seat_index} has no player"))
    }

    /// 手牌是否已收集到至少一个证明任务（有任务才有可结算的证明链）。
    pub fn has_provable_activity(&self) -> bool {
        !self.tasks.is_empty()
    }

    /// 测试/诊断：镜像 L1 牌组第 i 张密文（两层牌组一致性校验用）。
    #[cfg(test)]
    pub fn current_deck_card(
        &self,
        index: usize,
    ) -> Option<poker_protocol::crypto::ElGamalCiphertext> {
        self.table.deck_state.encrypted.get(index).map(|ct| *ct)
    }

    /// 从 Starknet felt 地址派生 poker_l1 地址。
    ///
    /// 截断公式（felt 低 20 字节）的**唯一权威**在
    /// `poker_l1::...::runtime::caller_id::wallet_to_address`（e2e 有对拍
    /// 断言）。本封装仅补 texas 侧的输入面：钱包端会以上送十进制 felt 串
    /// （bigint.toString()），`wallet_to_address` 只吃 hex——先经
    /// [`chain::parse_felt`] 解出 felt 再 hex 化喂给权威实现，两条输入
    /// 路径最终落在同一公式上。
    pub fn addr_from_starknet(felt_str: &str) -> Option<poker_l1::Address> {
        let felt = super::chain::parse_wallet_felt(felt_str)?;
        wallet_to_address(&format!("{felt:#x}")).ok()
    }

    /// 应用一条记录的 reveal 令牌命令（移植原 `mirror_sync_reveal` 锁内逻辑：
    /// 客户端令牌按密文逐字节匹配重排成 VM canonical 顺序后提交）。
    pub fn apply_recorded_reveal(
        &mut self,
        seat_index: u8,
        tokens: &[poker_protocol::z_poker::protocol::RevealToken],
    ) -> Result<(), String> {
        let mut converted: Vec<(PtxECPoint, PtxRevealTokenProof<PtxCurve>)> = Vec::new();
        let mut cards: Vec<poker_protocol::crypto::ElGamalCiphertext> = Vec::new();
        for t in tokens {
            let (Ok(tok), Ok(proof)) = (
                conv::ec_point(&poker_protocol::crypto::types::ECPoint(
                    t.reveal_token.clone(),
                )),
                conv::reveal_token_proof(&t.proof),
            ) else {
                return Err("reveal token conv failed".into());
            };
            converted.push((tok, proof));
            cards.push(t.encrypted_card.clone());
        }
        let targets = self.pending_reveal_ciphertexts(seat_index)?;
        if targets.len() != converted.len() {
            return Err(format!(
                "reveal set size mismatch: vm expects {}, client submitted {}",
                targets.len(),
                converted.len()
            ));
        }
        // canonical 重排：VM 要求 token 覆盖全部 pending assignment 且按
        // assignment 顺序（全有或全无）。按密文逐字节匹配客户端 token。
        let mut ordered: Vec<Option<usize>> = vec![None; targets.len()];
        for (ti, card) in cards.iter().enumerate() {
            for (pos, target) in targets.iter().enumerate() {
                if target.c1 == card.c1 && target.c2 == card.c2 {
                    ordered[pos] = Some(ti);
                    break;
                }
            }
        }
        if ordered.iter().any(|o| o.is_none()) {
            return Err("reveal set does not cover vm assignments byte-wise".into());
        }
        let mut pt_tokens = Vec::with_capacity(targets.len());
        let mut proofs = Vec::with_capacity(targets.len());
        for pos in 0..targets.len() {
            let ti = ordered[pos].expect("checked complete above");
            let (tok, proof) = converted[ti].clone();
            pt_tokens.push(tok);
            proofs.push(proof);
        }
        self.submit_reveal_tokens(seat_index, pt_tokens, proofs)
    }

    /// 应用一条记录的下注命令（移植原 `apply_mirror_bet`：终局 fold 先打
    /// pre-payout 快照并记录待应用弃牌座位）。
    pub fn apply_recorded_bet(
        &mut self,
        seat_index: u8,
        action: &str,
        total_bet: Option<u64>,
    ) -> Result<(), String> {
        match action {
            "fold" => {
                // 终局 fold 检测：本次弃牌后只剩 1 名未弃牌玩家时，VM 会在同
                // 一次 fold 转换里直接派奖并 reset——先打快照（快照打在 fold
                // 应用之前，结算派发时先在快照副本上落这记弃牌）。
                let unfolded_others = self
                    .table
                    .seats
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != seat_index as usize)
                    .filter(|(_, s)| s.is_occupied() && !s.is_folded() && !s.is_waiting())
                    .count();
                if unfolded_others == 1 {
                    self.mark_pre_settlement();
                    self.pre_settlement_final_fold = Some(seat_index);
                }
                self.fold(seat_index)
            }
            "check" => self.check(seat_index),
            "call" => self.call(seat_index),
            "raise" => match total_bet {
                Some(tb) => self.raise(seat_index, tb),
                None => Err("raise requires total_bet".into()),
            },
            other => Err(format!("unknown betting action {other}")),
        }
    }

    /// 应用一条记录的强制弃牌（移植原 `mirror_force_fold`：VM 拒绝不致命——
    /// 与旧同步路径语义一致，状态不变仅跳过，不影响本手可证明性）。
    pub fn apply_recorded_force_fold(&mut self, seat_index: u8) {
        // 仅当座位可弃牌时派发（已弃牌/等待中/离局的手牌阶段下为无操作）。
        let applicable = self
            .table
            .seats
            .get(seat_index as usize)
            .map(|s| s.is_occupied() && !s.is_folded() && !s.is_waiting())
            .unwrap_or(false);
        let unfolded_others = self
            .table
            .seats
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != seat_index as usize)
            .filter(|(_, s)| s.is_occupied() && !s.is_folded() && !s.is_waiting())
            .count();
        if applicable && unfolded_others == 1 {
            self.mark_pre_settlement();
            self.pre_settlement_final_fold = Some(seat_index);
        }
        if !applicable {
            return;
        }
        let args = match borsh::to_vec(&texas_dispatch::SeatIndexArgs { seat_index }) {
            Ok(a) => a,
            Err(_) => return,
        };
        let _ = self.apply([0xC0; 20], &texas_dispatch::selectors::force_fold(), args);
    }
}

/// 实时镜像（shadow.rs）的开局引导：按 HandStart 快照构建镜像、按升序
/// 座位 join、注入终局 deck、直接进入 DealHole reveal 窗口。
pub(crate) fn bootstrap_vm_table(
    table_id: u32,
    start: &super::prove_log::HandStartData,
    hand_id: u32,
) -> Result<VmTable, String> {
    let bb = start.small_blind.saturating_mul(2);
    let mut mirror = VmTable::new(
        u64::from(table_id),
        [0xC0; 20],
        9,
        start.small_blind,
        bb,
        [0xC0; 20],
    );
    let mut plan: Vec<(
        poker_l1::Address,
        u64,
        PtxECPoint,
        Option<poker_l1::signature::TaggedPubkey>,
        Vec<u8>,
    )> = Vec::new();
    for p in &start.participants {
        let addr = VmTable::addr_from_starknet(&p.wallet)
            .ok_or_else(|| format!("bad wallet felt: {}", p.wallet))?;
        plan.push((
            addr,
            p.stack,
            p.pk.clone(),
            p.tx_pk.clone(),
            p.pk_ownership_proof.clone(),
        ));
    }
    mirror
        .begin_reveal_hand(
            start.deck.clone(),
            &plan,
            start.button_rank,
            start.last_bb_rank,
            hand_id,
        )
        .map_err(|e| format!("begin_reveal: {e}"))?;
    // 抽水规则与游戏层同源（rake_params → STARKNET_RAKE_BPS/CAP）。
    // VmTable::new 只带 poker_l1 内建缺省（500bps），live 镜像若不同步，
    // plan.rake 恒按缺省抽——对账 2 每手拒绝 "rake mismatch: plan N vs
    // game 0"（2026-09-26 线上：plan 9 = 180×500bps vs game 0）。与
    // begin_reveal_hand 同步点（本文件 rake 同源注释，2026-09-04 审核）
    // 同一结论的第二处落点：改 env 只改一半的教训在此收口。
    mirror.table.rules.rake_mode =
        poker_l1::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
    mirror.table.rules.rake_bps = crate::pokergame::rake::rake_params().rake_bps;
    mirror.table.rules.rake_cap = crate::pokergame::rake::rake_params().rake_cap;
    Ok(mirror)
}

/// 从座位提取玩家地址（settle_hand 参与者来源）。
pub fn seat_player_addr(
    seat: &poker_l1::contracts::texas_poker::types::Seat,
) -> Option<poker_l1::Address> {
    use poker_l1::contracts::texas_poker::types::Seat;
    match seat {
        Seat::Playing { playing } => Some(playing.occupied.player),
        Seat::Waiting { occupied } => Some(occupied.player),
        Seat::DepartedThisHand { player, .. } => Some(*player),
        Seat::Vacant { .. } => None,
    }
}

/// zgame poker_protocol → ptx poker_protocol 的 borsh roundtrip 转换。
/// 两份副本结构一致（构建期 diff 校验），转换仅跨 crate 类型边界。
pub mod conv {
    use super::*;

    pub fn ciphertext(
        ct: &poker_protocol::crypto::ElGamalCiphertext,
    ) -> Result<PtxElGamalCiphertext, String> {
        let bytes = borsh::to_vec(ct).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("ciphertext borsh bridge: {e}"))
    }

    pub fn ciphertexts(
        cts: &[poker_protocol::crypto::ElGamalCiphertext],
    ) -> Result<Vec<PtxElGamalCiphertext>, String> {
        cts.iter().map(ciphertext).collect()
    }

    pub fn ec_point(p: &poker_protocol::crypto::types::ECPoint) -> Result<PtxECPoint, String> {
        let bytes = borsh::to_vec(p).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("ec point borsh bridge: {e}"))
    }

    pub fn reveal_token_proof(
        proof: &poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof<
            poker_protocol::crypto::DefaultCurve,
        >,
    ) -> Result<PtxRevealTokenProof<PtxCurve>, String> {
        let bytes = borsh::to_vec(proof).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("reveal token proof borsh bridge: {e}"))
    }
}

// 实时 VM 镜像——手牌的唯一 VM 状态表示（Phase 2b 权威切换载体）。
//
// 游戏层每个接受点同步 dispatch 到本模块持有的 VM 表（权威应用，
// 拒绝即拒绝客户端动作），手牌结束时把 VM 终局派生（board / rake /
// 逐钱包 deltas）与游戏层事实逐分比对。比对干净 → 这份镜像就是
// **结算的唯一 VM 状态来源**（ProveTask 链、pre-payout 快照、状态根
// 全部取自这里）；比对不干净 → fail-closed 拒绝该手结算。历史上
// "结算时从日志重放出第二份 VM 状态"的 `build_from_log` 已删除。
//
// 权威域（Phase 2b 逐域切换完成情况）：
// - **betting**：`vm_try_bet`——VM 校验并应用，游戏层下注账本
//   经 `apply_betting_view` 派生；turn 轮转归 VM。
// - **reveal**：`vm_try_reveal`——VM canonical 重排 + 证明验证 +
//   窗口推进；游戏层 reveal_token_state 退化为 ceremony 调度视图。
// - **deck**：洗牌仪式产物经 bootstrap 注入后为只读快照（方案A），
//   非独立演化的状态。
// - **生命周期**：街道推进/收尾由 VM 相位驱动游戏层 ceremony
//   （apply_betting_view 的联锁触发）。
//
// 开关（两个，均在启动时读环境变量并缓存）：
// - 默认开启（单一表示的正确性前提）；`TEXAS_SHADOW_PROVER=0`
//   作为紧急停用开关（停用期间的手牌不可证明、不上链——与历史
//   "缺 join 证明则 hand unprovable" 同类语义）。
// - `prover_mode()`：证明走向选择。`TEXAS_PROVER_MODE=dev`（或
//   `TEXAS_ENV=dev`）→ **本地 prover**——proved 模式的批次 attestation
//   在进程内 host ρ-fold 校验后直接出具、settlement 电路 fact 本地登记，
//   不依赖外部 prover 服务（`STARKNET_PROVER_URL`）；`remote`（默认）
//   → 外部 prover 服务，生产语义（服务器绝不进程内出证）。
//
// 开销说明：reveal 在游戏层与 VM 各验证一次（双倍 EC 成本）——这是
// 单一状态 + fail-closed 的代价；betting 动作为纯整数搬运，开销可忽略。

use poker_l1::contracts::texas_poker::settlement::{derive_fold_win_plan, derive_settlement_plan};
use poker_l1::contracts::texas_poker::types::HandPhase;

use super::prove_log::HandSettleInput;

/// 游戏层 Table 的镜像接线（accept 点与权威入口）。
impl crate::pokergame::table::Table {
    /// 下注动作接受点与权威提交（betting.rs handle_*）：VM 校验并应用，
    /// 返回派生视图；None = 本手无实时镜像（不可证明手——fail-closed，
    /// 动作直接拒绝）。
    pub fn vm_try_bet(
        &mut self,
        pk_hex: &str,
        action: &'static str,
        total_bet: Option<u64>,
    ) -> Option<Result<BettingView, String>> {
        self.vm_session
            .as_mut()
            .map(|sh| sh.try_bet(pk_hex, action, total_bet))
    }

    /// reveal 令牌接受点与权威提交（Table::submit_player_reveal_tokens）：
    /// VM canonical 重排 + 证明验证 + 窗口推进；None = 本手无实时镜像。
    pub fn vm_try_reveal(
        &mut self,
        pk_hex: &str,
        tokens: &[poker_protocol::z_poker::protocol::RevealToken],
    ) -> Option<Result<RevealView, String>> {
        self.vm_session
            .as_mut()
            .map(|sh| sh.try_reveal(pk_hex, tokens))
    }

    /// 换牌请求接受点与权威提交（Table::redeal_cards_for_player）：L1 校验
    /// "下注轮 + 调用者即持有者 + 账本条目存在 + deck 未耗尽"后挂起下注轮、
    /// 开启 Redealing 令牌窗口；None = 本手无实时镜像（fail-closed 拒绝）。
    /// 换牌改变发牌游标与手牌账本，是必须进证明轨迹的核心协议动作。
    pub fn vm_try_redeal(&mut self, pk_hex: &str, card_slot: u8) -> Option<Result<(), String>> {
        self.vm_session
            .as_mut()
            .map(|sh| sh.try_redeal(pk_hex, card_slot))
    }

    /// VM 侧换牌将消费的 deck 卡（L1 `cards_dealt` 游标位）。游戏层在协议级
    /// redeal 之前用它做两层游标对齐校验（fail-closed：不一致 = 镜像已失配）。
    pub fn vm_peek_redeal_card(
        &self,
    ) -> Option<
        Result<
            (
                u8,
                poker_l1::contracts::texas_poker::types::ElGamalCiphertext,
            ),
            String,
        >,
    > {
        self.vm_session.as_ref().map(|sh| {
            let table = &sh.vm.table;
            let index = table.deck_state.cards_dealt;
            let ct = *table
                .deck_state
                .encrypted
                .get(usize::from(index))
                .ok_or_else(|| "redeal exhausted the encrypted deck".to_string())?;
            Ok((index, ct))
        })
    }

    /// 超时推进接受点：把"超时"这一事件本身驱动为 L1 的 AdvanceDeadline
    /// dispatch（permissionless），踢人/分支级联全部进证明轨迹。
    pub fn vm_try_advance_deadline(&mut self) -> Option<Result<(), String>> {
        self.vm_session.as_mut().map(|sh| sh.try_advance_deadline())
    }

    /// 测试专用：快进镜像共识时钟（跨过当前相位的 deadline）。
    #[cfg(test)]
    pub fn vm_advance_test_clock(&mut self, delta_ms: u64) {
        if let Some(sh) = self.vm_session.as_mut() {
            sh.advance_test_clock(delta_ms);
        }
    }

    /// 重构牌组提交接受点：statement 转发 L1 全字段重验（方案 A：重构进轨迹）。
    pub fn vm_try_submit_reconstruct_deck(
        &mut self,
        pk_hex: &str,
        statement: poker_protocol::zk_shuffle::reconstruction::ReconstructionStatement<
            poker_protocol::crypto::DefaultCurve,
        >,
        proof: poker_protocol::zk_shuffle::reconstruction::ReconstructProof<
            poker_protocol::crypto::DefaultCurve,
        >,
    ) -> Option<Result<(), String>> {
        self.vm_session
            .as_mut()
            .map(|sh| sh.try_submit_reconstruct_deck(pk_hex, statement, proof))
    }

    /// 重构后重洗的洗牌提交接受点。
    pub fn vm_try_submit_shuffle(
        &mut self,
        pk_hex: &str,
        output_cards: Vec<poker_protocol::crypto::ElGamalCiphertext>,
        shuffle_proof: poker_protocol::zk_shuffle::ShuffleProof,
    ) -> Option<Result<(), String>> {
        self.vm_session
            .as_mut()
            .map(|sh| sh.try_submit_shuffle(pk_hex, output_cards, shuffle_proof))
    }

    /// reconstruct statement 上下文读取（epoch/digests/carriers 权威来源）。
    pub fn vm_reconstruct_context(&self) -> Option<Result<VmReconstructContext, String>> {
        self.vm_session.as_ref().map(|sh| sh.reconstruct_context())
    }

    /// 强制弃牌接受点（手牌进行中移除玩家）。
    pub fn vm_force_fold(&mut self, wallet: &str) {
        if let Some(sh) = self.vm_session.as_mut() {
            sh.force_fold(wallet);
        }
    }

    /// 单一同步入口（单一状态重构）：从 VM **当前**状态重派生下注视图并
    /// 应用到游戏层。dispatch 被拒绝、超时推进、后台兜底等一切"没有随
    /// 返回视图"的路径统一走这里——不再存储"拒绝时快照"（历史
    /// `last_rejected_view` 补丁点已删除：派生是纯读，无需缓存）。
    pub(crate) fn refresh_from_vm(&mut self) {
        let Some(sh) = self.vm_session.as_ref() else {
            return;
        };
        let view = sh.current_view();
        self.apply_betting_view(&view);
    }
}

/// betting 域权威提交：VM 校验并应用，返回派生视图。
/// 单手实时镜像：一张 live VM + 命令映射 + 计数。
#[derive(Debug)]
pub struct VmSession {
    table_id: u32,
    hand_id: u32,
    vm: VmTable,
    /// pk_hex（游戏层座位标识）→ VM 20 字节地址。
    by_pk: std::collections::HashMap<String, poker_l1::Address>,
    /// wallet hex → VM 20 字节地址。
    by_wallet: std::collections::HashMap<String, poker_l1::Address>,
    /// VM 20 字节地址 → 参与者钱包 hex（终局 deltas 对账回全精度 felt 用）。
    addr_to_wallet: std::collections::HashMap<poker_l1::Address, String>,
    metrics: Metrics,
}

#[derive(Default, Debug, Clone)]
pub struct Metrics {
    pub reveal_ok: usize,
    pub bet_ok: usize,
    /// VM 拒绝的下注动作数（**观测指标，不是结算门**，2026-09-10 变更）：
    /// VM 是接受点本身，被拒动作游戏层同样拒绝，不构成状态分歧。hooks
    /// 的结算门只看 `FinishReport.issues`（对账分歧）；本计数仅 warn 日志，
    /// 用于监控客户端噪音（抢跑/轮次竞态/畸形加注）的规模。
    pub bet_fail: usize,
    pub force_folds: usize,
}

/// 终局比对报告（finish 时产出；测试经 take_last_report_for_test 读取）。
#[derive(Debug, Clone)]
pub struct FinishReport {
    pub table_id: u32,
    pub hand_id: u32,
    pub metrics: Metrics,
    /// 派生/对账分歧（空 = 实时 VM 与游戏层完全一致）。
    pub issues: Vec<String>,
}

/// betting 域的权威视图（从 VM 状态提取，游戏层据此派生自己的下注状态）。
#[derive(Debug, Clone, Default)]
pub struct BettingView {
    /// 全部座位（VM 座位序 = 参与者升序）。
    pub seats: Vec<BettingViewSeat>,
    /// VM 已收集底池（不含当前街在途下注）。
    pub pot: u64,
    /// 当前街在途下注合计（VM pot + street_bets = 游戏层派生 pot）。
    pub street_bets: u64,
    /// 当前行动者（pk hex；None = 无行动者/非下注相位）。
    pub current_turn_pk: Option<String>,
    /// VM 本轮当前注额。
    pub current_bet: Option<u64>,
    /// VM 本轮最小加注额。
    pub min_raise: Option<u64>,
    /// VM 是否处于下注相位。
    pub in_betting: bool,
    /// VM 已在本次 dispatch 内结束本手（fold-win）。
    pub hand_over: bool,
    /// 终局前底池（hand_over 时游戏层派奖基数）。
    pub fold_win_pot: Option<u64>,
}

/// reveal 域的权威视图（ceremony 调度用派生信息）。
#[derive(Debug, Clone, Default)]
pub struct RevealView {
    /// VM 揭牌窗口是否仍开启（false = 已全消化、相位已推进）。
    pub window_open: bool,
    /// 当前已揭示公共牌数。
    pub revealed_board: usize,
    /// 仍未提交的座位（pk hex，去重升序）。
    pub pending_pks: Vec<String>,
}

/// reconstruct V3 的 statement 上下文（全部由镜像 L1 状态重算，客户端/游戏层
/// 不得自算——摘要材料绑定镜像 ObjectID 与 epoch，本地重算必不匹配）。
#[derive(Debug, Clone)]
pub struct VmReconstructContext {
    /// L1 的 reconstruct epoch（进 Reconstructing 时的共识毫秒时间戳）。
    pub reconstruction_epoch: u64,
    /// 应用域摘要（poker_l1 reconstruction_v3_context_digest）。
    pub context_digest: [u8; 32],
    /// deck 贡献者聚合公钥（镜像 contributor mask 派生）。
    pub aggregate_pk: String,
    /// 待提交重构份额的座位（pk hex，升序）——权威 pending 集。
    pub pending_pks: Vec<String>,
    /// 每个待提交座位的 prior-state 摘要。
    pub prior_state_digests: std::collections::HashMap<String, [u8; 32]>,
    /// 每个待提交座位的 owner-readable residual carriers。
    pub residual_carriers:
        std::collections::HashMap<String, Vec<poker_protocol::crypto::ElGamalCiphertext>>,
}

/// 单座位下注视图。
#[derive(Debug, Clone, Default)]
pub struct BettingViewSeat {
    pub pk_hex: String,
    pub folded: bool,
    pub bet: u64,
    pub total_bet: u64,
    pub stack: u64,
    pub has_acted: bool,
}

impl VmSession {
    /// 开局引导（deck 注入 + DealHole 窗口），与结算重放同一 bootstrap。
    pub fn start(table_id: u32, start: &super::prove_log::HandStartData) -> Result<Self, String> {
        let vm = bootstrap_vm_table(table_id, start, start.hand_id)?;
        let mut by_pk = std::collections::HashMap::new();
        let mut by_wallet = std::collections::HashMap::new();
        let mut addr_to_wallet = std::collections::HashMap::new();
        for p in &start.participants {
            if let Some(addr) = VmTable::addr_from_starknet(&p.wallet) {
                by_pk.insert(p.pk_hex.clone(), addr);
                by_wallet.insert(p.wallet.clone(), addr);
                addr_to_wallet.insert(addr, p.wallet.clone());
            }
        }
        Ok(Self {
            table_id,
            hand_id: start.hand_id,
            vm,
            by_pk,
            by_wallet,
            addr_to_wallet,
            metrics: Metrics::default(),
        })
    }

    /// reveal 域权威入口：VM 对令牌做 canonical 重排、覆盖性检查与
    /// 证明验证，并推进窗口（全消化时 normalize 自动进入下一相位）。
    /// 错误 = 动作非法，直接拒绝——与游戏层"窗口未开不接受"的客户端
    /// 契约一致，live 路径不再需要 deferred 队列（那是历史日志重放的
    /// 乱序补救，重放已删除）。
    pub fn try_reveal(
        &mut self,
        pk_hex: &str,
        tokens: &[poker_protocol::z_poker::protocol::RevealToken],
    ) -> Result<RevealView, String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("reveal from unknown pk {pk_hex}"))?;
        self.vm.apply_recorded_reveal(seat, tokens)?;
        self.metrics.reveal_ok += 1;
        Ok(self.reveal_view())
    }

    /// 换牌权威入口：L1 校验后挂起下注轮、开启 Redealing 窗口。
    /// 错误 = 动作非法，直接拒绝（与 reveal/bet 同一 fail-closed 语义）。
    pub fn try_redeal(&mut self, pk_hex: &str, card_slot: u8) -> Result<(), String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("redeal from unknown pk {pk_hex}"))?;
        self.vm.redeal_hole_card(seat, card_slot)?;
        Ok(())
    }

    /// 超时推进权威入口：L1 消费当前 deadline 并内联级联（踢未交份额座位、
    /// 按活跃数分支 reset/end/进入 Reconstructing/恢复下注轮），全部进轨迹。
    pub fn try_advance_deadline(&mut self) -> Result<(), String> {
        self.vm.advance_deadline()
    }

    /// 测试专用：快进镜像共识时钟。
    #[cfg(test)]
    pub fn advance_test_clock(&mut self, delta_ms: u64) {
        self.vm.advance_test_clock(delta_ms)
    }

    /// 重构牌组提交权威入口：L1 全字段重验 statement 并累计贡献；最后一份
    /// 提交在 normalize 内联完成 deck 重建 + 进入重构洗牌相位。
    pub fn try_submit_reconstruct_deck(
        &mut self,
        pk_hex: &str,
        statement: poker_protocol::zk_shuffle::reconstruction::ReconstructionStatement<
            poker_protocol::crypto::DefaultCurve,
        >,
        proof: poker_protocol::zk_shuffle::reconstruction::ReconstructProof<
            poker_protocol::crypto::DefaultCurve,
        >,
    ) -> Result<(), String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("reconstruct from unknown pk {pk_hex}"))?;
        self.vm.submit_reconstruct_deck(seat, statement, proof)
    }

    /// 重构后重洗的洗牌提交权威入口（对镜像 L1 牌组验证 BG 证明——同时是
    /// 两层重建牌组逐字节一致性的自然校验）。
    pub fn try_submit_shuffle(
        &mut self,
        pk_hex: &str,
        output_cards: Vec<PtxElGamalCiphertext>,
        shuffle_proof: poker_protocol::zk_shuffle::ShuffleProof,
    ) -> Result<(), String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("shuffle from unknown pk {pk_hex}"))?;
        self.vm.submit_shuffle_v2(seat, output_cards, shuffle_proof)
    }

    /// reconstruct V3 的 statement 上下文（由镜像 L1 状态权威推导）。
    ///
    /// epoch / context_digest / prior_state_digest / residual_carriers 全部
    /// 经 poker_l1 同一实现重算——游戏层不得自算这些字段（摘要材料含镜像
    /// ObjectID，本地重算必不匹配），客户端据此构造 statement，L1 校验才可通过。
    pub fn reconstruct_context(&self) -> Result<VmReconstructContext, String> {
        use poker_l1::contracts::texas_poker::core::utils::{
            reconstruction_v3_context_digest, reconstruction_v3_prior_state_digest,
            reconstruction_v3_residual_carriers,
        };

        let table = &self.vm.table;
        let Some(epoch) = table.reconstruct_epoch_ms() else {
            return Err("mirror is not in reconstruct collecting phase".into());
        };
        let aggregate_pk = table
            .derived_aggregated_pk()
            .map_err(|e| e.to_string())?
            .ok_or("mirror has no aggregate deck key")?;
        let mut ctx = VmReconstructContext {
            reconstruction_epoch: epoch,
            context_digest: reconstruction_v3_context_digest(table),
            aggregate_pk: poker_protocol::z_poker::convert::ecpoint_to_hex(&aggregate_pk.0),
            pending_pks: Vec::new(),
            prior_state_digests: std::collections::HashMap::new(),
            residual_carriers: std::collections::HashMap::new(),
        };
        let pending_mask = table.reconstruct_state().pending_mask;
        for (pk_hex, addr) in &self.by_pk {
            let Some(seat) = self.vm.seat_index_of(*addr) else {
                continue;
            };
            if pending_mask & (1u16 << seat) == 0 {
                continue;
            }
            // 摘要推导要求该座位已有 owner-readable 记录（DealHole 已物化）；
            // 缺失的座位在 L1 submit 时同样被拒，这里跳过并保留 pending。
            match reconstruction_v3_prior_state_digest(table, seat) {
                Ok(digest) => {
                    ctx.prior_state_digests.insert(pk_hex.clone(), digest);
                }
                Err(e) => {
                    tracing::warn!("[RECONSTRUCT] seat {seat} prior digest unavailable: {e}");
                }
            }
            ctx.residual_carriers.insert(
                pk_hex.clone(),
                reconstruction_v3_residual_carriers(table, seat),
            );
            ctx.pending_pks.push(pk_hex.clone());
        }
        ctx.pending_pks.sort();
        Ok(ctx)
    }

    /// 从 VM 状态提取 reveal 视图（ceremony 调度用）。
    fn reveal_view(&self) -> RevealView {
        let t = &self.vm.table;
        let pending_pks = t
            .reveal_token_state()
            .map(|st| {
                st.assignments
                    .iter()
                    .flat_map(|a| {
                        let m = a.pending_mask();
                        (0u8..16).filter(move |i| m & (1u16 << i) != 0)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let pending_pks: Vec<String> = pending_pks
            .into_iter()
            .collect::<std::collections::BTreeSet<u8>>()
            .into_iter()
            .filter_map(|idx| {
                self.by_pk
                    .iter()
                    .find(|(_, addr)| self.vm.seat_index_of(**addr) == Some(idx))
                    .map(|(pk, _)| pk.clone())
            })
            .collect();
        RevealView {
            window_open: t.reveal_token_state().is_some(),
            revealed_board: t.community_cards.len(),
            pending_pks,
        }
    }

    /// 强制弃牌（内部应用原语；VM 拒绝不致命——与旧同步路径语义一致）。
    fn force_fold(&mut self, wallet: &str) {
        let Some(addr) = self.by_wallet.get(wallet) else {
            return; // 非本手参与者（跨手残留）：跳过
        };
        if let Some(seat) = self.vm.seat_index_of(*addr) {
            self.vm.apply_recorded_force_fold(seat);
            self.metrics.force_folds += 1;
        }
    }

    /// 手牌结束：派奖推进 → 派生结算计划 → 与游戏层事实对账。
    ///
    /// 返回 (比对报告, 镜像)。镜像只有在报告**零分歧**（`issues` 为空）
    /// 时才可作为结算来源——调用方（hooks）按 issues 拒绝脏镜像。
    /// `metrics.bet_fail` 是**观测指标**（客户端噪音/非法动作计数），不是
    /// 结算门（2026-09-10：VM 拒绝的动作游戏层同样拒绝，不构成状态分歧；
    /// 把它当门会把"单条非法下注"变成拒结算的 griefing 武器）。
    pub fn finish(mut self, input: &HandSettleInput) -> (FinishReport, VmTable) {
        let mut issues: Vec<String> = Vec::new();

        // 摊牌展示期 → 派奖前快照 + 推进 VM 复位（与结算重放收尾一致）。
        if matches!(self.vm.table.hand_phase, HandPhase::ShowdownDisplay { .. }) {
            self.vm.mark_pre_settlement();
            if let Err(e) = self.vm.advance_deadline() {
                issues.push(format!("payout advance failed: {e}"));
            }
        }

        // pre-payout 表：fold-win 快照先落终局弃牌（与 submit::settle_hand 同一语义）。
        let fold_snapshot = self
            .vm
            .pre_settlement_final_fold
            .zip(self.vm.pre_settlement.as_ref())
            .map(|(seat, snap)| super::submit::apply_pending_final_fold(snap, seat));
        let settle_table = fold_snapshot
            .as_ref()
            .or(self.vm.pre_settlement.as_ref())
            .unwrap_or(&self.vm.table);

        // 对账 1：公共牌数（deck 注入 ↔ VM 的双表示一致性——单一状态
        // 重构后仍保留：牌组在游戏层、明文记录在 VM）。
        if settle_table.community_cards.len() != input.board_len {
            issues.push(format!(
                "board mismatch: vm {} vs game {}",
                settle_table.community_cards.len(),
                input.board_len
            ));
        }

        // 对账 2（守恒，单一状态重构后）：结算计划资金守恒——
        // Σawards + rake == Σtotal_bet（派奖不凭空产生/销毁筹码）。
        //
        // 游戏层派奖与 VM 派奖的**逐钱包一致性**不再是结算门：VM 是结算
        // 唯一来源，游戏层 evaluator（展示/账本）的分歧（如 tie-break）
        // 降级为可观测指标——与 bet_fail 的降级同理（2026-09-10 语义），
        // 不给双实现分歧阻塞结算的权力。
        let unfolded_count = settle_table
            .seats
            .iter()
            .filter(|seat| seat.is_occupied() && !seat.is_folded() && !seat.has_left_hand())
            .count();
        let plan = if unfolded_count <= 1 {
            derive_fold_win_plan(settle_table)
        } else {
            derive_settlement_plan(settle_table)
        };
        match plan {
            Err(e) => issues.push(format!("plan derivation failed: {e}")),
            Ok(plan) => {
                let total_bet: u128 = settle_table
                    .seats
                    .iter()
                    .map(|s| u128::from(s.total_bet()))
                    .sum();
                let awards: u128 = plan.awards.iter().map(|&a| u128::from(a)).sum();
                let rake = u128::from(plan.rake);
                if awards.checked_add(rake) != Some(total_bet) {
                    issues.push(format!(
                        "conservation violated: awards {awards} + rake {rake} != total_bet {total_bet}"
                    ));
                }
                if plan.rake != input.rake_collected {
                    tracing::warn!(
                        "[live-mirror] table {} hand {}: rake divergence (display only): vm {} vs game {}",
                        self.table_id,
                        self.hand_id,
                        plan.rake,
                        input.rake_collected
                    );
                }
            }
        }

        let report = FinishReport {
            table_id: self.table_id,
            hand_id: self.hand_id,
            metrics: self.metrics.clone(),
            issues,
        };
        #[cfg(test)]
        {
            if let Ok(mut g) = LAST_REPORTS.lock() {
                g.insert(report.table_id, report.clone());
            }
            if let Ok(mut g) = LAST_MIRRORS.lock() {
                g.insert(self.table_id, self.vm.clone());
            }
        }
        let mirror = self.vm;
        (report, mirror)
    }

    /// betting 域权威入口：VM 校验并应用下注动作（错误 = 非法动作，
    /// 直接上抛拒绝——不再被统计吞掉）。成功返回从 VM 状态提取的
    /// 下注视图，游戏层据此派生自己的下注状态（派生视图）。
    pub fn try_bet(
        &mut self,
        pk_hex: &str,
        action: &str,
        total_bet: Option<u64>,
    ) -> Result<BettingView, String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("bet from unknown pk {pk_hex}"))?;
        // 终局 fold 检测（与 apply_recorded_bet 的快照判定同构）：
        // 本次弃牌后只剩一名未弃牌玩家 → VM 将在本次 dispatch 内结束本手。
        let unfolded_others = self
            .vm
            .table
            .seats
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != seat as usize)
            .filter(|(_, s)| s.is_occupied() && !s.is_folded() && !s.is_waiting())
            .count();
        let terminal_fold = action == "fold" && unfolded_others == 1;
        // 终局前的底池事实（VM pot + 在途下注）——游戏层派奖需要它：
        // VM 派奖在 dispatch 内部原子完成，事后 pot 已清零。
        let pre_pot = self.vm.table.pot + self.vm.table.seats.iter().map(|s| s.bet()).sum::<u64>();

        if let Err(e) = self.vm.apply_recorded_bet(seat, action, total_bet) {
            self.metrics.bet_fail += 1;
            // 拒绝路径的视图同步由调用方统一走 refresh_from_vm()（从 VM
            // 当前状态纯派生）——VM 可能在本次 dispatch 内已推进相位
            //（如 preflop 完成 → flop reveal 窗口），游戏层不同步会卡死
            // 在旧街视图、reveal token 永远无法提交（失步死锁）。
            // 诊断：带出 mirror VM 实际相位（失步排查）
            return Err(format!(
                "{e} [mirror hand_phase={:?} round_state={}]",
                self.vm.table.hand_phase,
                self.vm.table.round_state()
            ));
        }
        self.metrics.bet_ok += 1;

        let mut view = self.betting_view();
        if terminal_fold {
            view.hand_over = true;
            view.fold_win_pot = Some(pre_pot);
        }
        Ok(view)
    }

    /// 从 VM 状态提取下注视图（座位序 = 参与者升序，pk 反查映射）。
    /// 测试/诊断：镜像 L1 牌组第 i 张密文（两层牌组一致性校验用）。
    #[cfg(test)]
    pub fn current_deck_card(
        &self,
        index: usize,
    ) -> Option<poker_protocol::crypto::ElGamalCiphertext> {
        self.vm.current_deck_card(index)
    }

    /// [`Self::current_view`] 是对外只读入口（refresh_from_vm 的数据源）。
    pub(crate) fn current_view(&self) -> BettingView {
        self.betting_view()
    }

    /// 本手控制轨迹只读视图（canonical witness 生产者的数据源）。
    pub(crate) fn vm_traces(&self) -> &Vec<DispatchTrace> {
        &self.vm.traces
    }

    fn betting_view(&self) -> BettingView {
        use poker_l1::contracts::texas_poker::types::HandPhase;
        let t = &self.vm.table;
        let mut pk_by_seat: Vec<(u8, &str)> = Vec::with_capacity(self.by_pk.len());
        for (pk, addr) in &self.by_pk {
            if let Some(idx) = self.vm.seat_index_of(*addr) {
                pk_by_seat.push((idx, pk));
            }
        }
        pk_by_seat.sort_unstable();

        let (in_betting, current_bet, min_raise, current_turn) = match &t.hand_phase {
            HandPhase::Betting {
                round,
                current_turn,
                ..
            } => (
                true,
                Some(round.current_bet),
                Some(round.min_raise),
                Some(*current_turn),
            ),
            _ => (false, None, None, None),
        };
        let seats = t
            .seats
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let acted = t.acted_mask & (1u16 << i) != 0;
                BettingViewSeat {
                    pk_hex: pk_by_seat
                        .iter()
                        .find(|(idx, _)| *idx == i as u8)
                        .map(|(_, pk)| pk.to_string())
                        .unwrap_or_default(),
                    folded: s.is_folded(),
                    bet: s.bet(),
                    total_bet: s.total_bet(),
                    stack: s.stack(),
                    has_acted: acted,
                }
            })
            .collect();
        BettingView {
            seats,
            pot: t.pot,
            street_bets: t.seats.iter().map(|s| s.bet()).sum::<u64>(),
            current_turn_pk: current_turn
                .and_then(|idx| pk_by_seat.iter().find(|(i, _)| *i == idx))
                .map(|(_, pk)| pk.to_string()),
            current_bet,
            min_raise,
            in_betting,
            // VM 回到 Waiting = 本手已在 dispatch 内终结（fold-win 派奖 +
            // reset）。post-reset 视图不再携带 folded/total_bet 终局事实，
            // 游戏层在 hand_over 分支不得用它改写账本（派奖/对账基准是
            // 游戏层自己的终局前账目）。
            hand_over: matches!(t.hand_phase, HandPhase::Waiting),
            fold_win_pot: None,
        }
    }

    fn seat_of_pk(&self, pk_hex: &str) -> Option<u8> {
        let addr = self.by_pk.get(pk_hex)?;
        self.vm.seat_index_of(*addr)
    }
}

pub(crate) fn enabled() -> bool {
    static ENV_INIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENV_INIT.get_or_init(|| std::env::var("TEXAS_SHADOW_PROVER").ok().as_deref() != Some("0"))
}

/// 证明走向（第二个开关，[`prover_mode`] 的解析结果）。
///
/// - `Local`：本地进程内 prover——dev 联调用。批次 attestation 由
///   `dual_settle::LocalBatchProver` 进程内 host ρ-fold 校验后出具；
///   settlement 电路跳过外部 HTTP prover，fact 由 operator 直接种上
///   链（`register_settlement_fact`），proved 路径在本地 devnet 可闭环。
/// - `Remote`：外部 prover 服务（`STARKNET_PROVER_URL`）——生产语义，
///   服务器绝不进程内出证，prover 不可用即回退 linear。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProverMode {
    Local,
    Remote,
}

/// 证明走向开关：`TEXAS_PROVER_MODE` 显式指定（`dev`/`local` → 本地，
/// `remote`/`http` → 外部服务）；未设置时跟随 `TEXAS_ENV`（=dev → 本地，
/// 其余 → remote）。启动时解析一次并缓存（与 [`enabled`] 同语义）。
pub(crate) fn prover_mode() -> ProverMode {
    static ENV_INIT: std::sync::OnceLock<ProverMode> = std::sync::OnceLock::new();
    *ENV_INIT.get_or_init(|| {
        match std::env::var("TEXAS_PROVER_MODE")
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("dev" | "local") => return ProverMode::Local,
            Some("remote" | "http") => return ProverMode::Remote,
            _ => {}
        }
        if std::env::var("TEXAS_ENV").ok().as_deref() == Some("dev") {
            ProverMode::Local
        } else {
            ProverMode::Remote
        }
    })
}

/// 开局引导（record_hand_start 成功后由 Table 挂载，见 prove_log）。
pub(crate) fn bootstrap(
    table_id: u32,
    start: &super::prove_log::HandStartData,
) -> Option<VmSession> {
    if !enabled() {
        // 紧急停用开关：本手不挂载实时镜像，动作走游戏层本地兜底
        // （*_local / 本地轮转），该手不可证明、不上链（结算 fail-closed）。
        tracing::warn!(
            "[live-mirror] table {table_id} hand {}: disabled by TEXAS_SHADOW_PROVER=0 — hand unprovable",
            start.hand_id
        );
        return None;
    }
    match VmSession::start(table_id, start) {
        Ok(sh) => Some(sh),
        Err(e) => {
            tracing::warn!(
                "[live-mirror] table {table_id} bootstrap failed: {e} — hand unprovable"
            );
            None
        }
    }
}

#[cfg(test)]
static LAST_REPORTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, FinishReport>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 测试读取指定桌的最近一次终局比对报告。
#[cfg(test)]
pub(crate) fn take_last_report_for_test(table_id: u32) -> Option<FinishReport> {
    LAST_REPORTS
        .lock()
        .ok()
        .and_then(|mut g| g.remove(&table_id))
}

#[cfg(test)]
static LAST_MIRRORS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, VmTable>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 测试读取指定桌的最近一次终局镜像（on_hand_complete 已消费实时镜像，
/// 测试经此取用做生产结算路径验证）。
#[cfg(test)]
pub(crate) fn take_last_mirror_for_test(table_id: u32) -> Option<VmTable> {
    LAST_MIRRORS
        .lock()
        .ok()
        .and_then(|mut g| g.remove(&table_id))
}
