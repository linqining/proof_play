# Project Status — Canonical AIR Coverage & Trust Boundary

> 2026-09-05 重写。本文件是 canonical AIR 覆盖/缺口的**权威表述源**
> （docs/TODO.md「canonical AIR 缺口」条目指向这里）。历史叙事
> （Ristretto 迁移、L1 链机制、无交易重放信任模型）已移至
> [`docs/archive/`](archive/)——Plan D（2026-09-05）后协议唯一曲线为
> Stark 曲线，poker_l1 收缩为合约库，常驻 mirror 已删除（结算 =
> 单一状态架构：实时 VM 镜像 + settle 时直接取用，prove_log 仅作对账基准）。

## Workspace model

This workspace is the extracted `poker_texas_air` project: a Starknet
off-chain stwo proving stack. There is no L1 chain, no transaction replay,
and no resident mirror. The proof pipeline is: a per-hand **single VM
session** (`texas/src/starknet/vm_session.rs` — `VmSession`/`VmTable`,
2026-09-14 由 shadow.rs + mirror.rs 合并重组；dispatched synchronously at
every game acceptance point) → ProveTask chain → canonical AIR / outer
aggregate → on-chain settlement (`poker_contracts`), cross-checked against
game-layer facts recorded in `texas/src/starknet/prove_log.rs`. Settlement
digests bind the hand's action log (`action_log_digest` tail word, #18
Phase B).

## 结算任务持久化投递层（settle-queue，2026-10-01 立项）

2026-10-01 起，结算投递层从 texas 进程内静态（hooks.rs 的
PENDING_SETTLE/SETTLE_OK/SETTLE_ATTEMPTS——重启即丢）升级为持久化队列
（`settle-queue/`，正式状态表；todo #50）。要点：

- **条目与判别**：单手键 `(table_id, hand_id)` 仅做队列去重；路由判别器
  `SettleRoute{Legacy, Dual}` 绑 `STARKNET_SETTLEMENT_MODE`
  （`texas/src/starknet/config.rs:136-149`，仅认 legacy|snip36）而非
  `STARKNET_DAPV_SETTLE_ENTRY`（后者无 legacy 值，只作 Dual 路内合约
  入口参数随条目携带）。与 `SettlementExit`（`appchain/exit.rs:59-65`，
  parse 自 "starknet"|"legacy"）的映射：Starknet 变体按 settlement_mode
  细分 SettleRoute，**Appchain 不入队**。
- **单写者文件归属协议**：queue WAL（`queue.jsonl`）唯一写者 = texas
  （append 入队、构建期死信标记、Dual→Legacy 降级迁移——仅由 texas 依据
  poster sidecar 死信回读触发）；poster（`batch-poster/`）独占 sidecar
  （poster-state.json 游标与在途快照 + receipts/ + dead/ + batches/，
  原子写），只读 WAL。**DeadLetter 双源归属**：构建期死信 texas 写 WAL、
  投递期死信（重试耗尽，含降级后仍耗尽）poster 写 `dead/<key>.json`。
- **Dual→Legacy 单向降级迁移**：对齐 snip36 失败回退 legacy 的
  「结算永不丢失」语义（`hooks.rs:423-427`）——dual 腿重试耗尽 → poster
  死信 → texas 降级重投（legacy 保底 payload 由 texas 入队时预构建）→
  poster 清死信按 legacy 重投；重启对账续投。
- **fold 批不进队列键域**：批级状态在 poster sidecar，
  `batch_key = keccak_root` 同时是 zchain 侧幂等键与 MonadProofEnvelope
  主键，`members` 引用单手键——批键做批幂等，单手键只做队列去重。

三层分工勿越界：**prove_log 仍是对账事实源**（`take_settle_input`
`texas/src/starknet/prove_log.rs:434` 入队）；**settle-queue 只管投递
进度**（状态机的 Receipted ≠ 业务终态）；**settle_receipt 的 SettleStatus
（`texas/src/starknet/settle_receipt.rs:36`，Settled/Refused/Failed）仍是
业务终态权威**。texas 侧接线（入队源/发送面切换）见 todo #50 剩余项——
接线落地前 hooks.rs 现行为不变。

## 2026-09-14 单一状态重构（mirror 双状态模式移除）

**动机**：AIR 是 preimage→postimage 行约束，postimage 由宿主计算——控制
逻辑（谁行动/何时收注/何时推街）在游戏层与 VM 两处实现、散落同步点
（apply_betting_view / sync_rejected_view / last_rejected_view /
game_loop 手动轮转）是失步死锁族 bug（09-07 多发公共牌、09-13 reveal
死锁、09-14 双推进活锁）与 PotCollected 投影分歧的根因。

**落地**（`cargo test -p texas` 171 绿 / `-p poker_l1` 364 绿）：

- **fail-closed**：不可证明的手不可玩——`*_local` 本地规则兜底删除；
  无实时 VM 会话时下注/reveal 动作一律拒绝；`TEXAS_SHADOW_PROVER=0`
  不开局；deck 终局时 bootstrap 失败/缺 join 证明 → 中止本手
  （`abort_unprovable_hand`，肇事座位转 sitting_out）。
- **单一同步入口** `refresh_from_vm()`：拒绝/超时/后台路径统一从 VM
  当前状态重派生视图（`last_rejected_view` 补丁点删除）。
- **VM 权威街道推进**：game_loop 的"轮次完成即推街"与本地手动轮转
  分支删除——街道推进唯一触发是 VM dispatch 内 normalize → 视图同步
  的相位联锁（hand_over 语义 = VM `HandPhase::Waiting`，派生可靠）。
- **终局弃牌确定性终结**（bug 修复，2026-09-14 探针实测）：post-reset
  视图不再覆盖游戏层账本（folded/total_bet/stack 全部跳过同步），
  `handle_fold` 在 view.hand_over 时当场 `end_without_showdown`——
  此前手牌卡死在无 turn 的 PreFlop。
- **VM 欠注判定修复**（bug 修复）：`no_further_betting_possible` 补
  "无可行动玩家欠注"条件——all-in 加注后唯一留筹码且欠注的对手仍须
  call/fold，不得连跳收注（对齐游戏层 `is_betting_round_complete` 与
  canonical prover 侧 AdvanceRound 边界）。
- **结算单源**：`cross_check_deltas` 收缩为守恒门（Σdeltas ∈ {0, −rake}）；
  `finish()` issues 收缩为 board 双表示一致 + 计划守恒
  （Σawards + rake == Σtotal_bet）——游戏层 evaluator 与 VM 的逐钱包
  一致性降级为可观测指标（VM 是结算唯一来源）。
- **控制轨迹捕获**（控制逻辑入 AIR 的原料，Stage 2 地基）：
  `poker_l1` 线程局部 `NormalizationTrace`（arm/take，关闭零开销）+
  命令内联级联（终局弃牌/reveal 完成）同样入轨迹；`VmTable.traces`
  记录每手全部 dispatch 的 (命令 pre/post + 逐步 pre/post 链)，
  `trace_capture_tests` 钉板链式咬合契约。

## 2026-09-14 Stage 2（续）：控制逻辑入 AIR——行链生产者 + 封顶盲注 AIR 扩写

**VM 侧对齐**（`cargo test -p poker_l1` 364 绿）：

- `advance_turn` 完成分支与 `start_betting_round` 的 all-in runout 分支：
  turn 清到 NO_SEAT（canonical AdvanceRound 行不变量："final actor 已离场"；
  把 turn 留在最后行动者身上正是陈旧指针的来源），收注 + 推街拆为独立
  `AdvanceBettingRound` micro-step 进 NormalizationTrace；
  `set_current_turn` 幂等化（old == new 不发事件）。
- `start_betting_round` 重置 acted 后为 all-in 座位补 acted 位
  （canonical 镜像不变量 "Folded/AllIn seat must be acted"）。

**AIR 扩写——Reveal completion 容纳封顶盲注**（`texas_canonical.rs`
`validate_reveal_completion_opening` + `texas_canonical_air.rs` rc 约束组）：

- 1BB 盲注 all-in（盲注扣到 stack 归零 → VM AllIn 翻转）此前被
  "blinds cap the seat stack" fail-closed；现放行为受约束的翻转形状：
  - AIR：per-seat `rc_stack_capped` advice（capped ⟺ 盲注座 ∧ post stack
    归零）+ 翻转方向约束（Active→AllIn）+ status/acted 冻结豁免
    （`(is_protocol_submit - capped) * diff`，度 ≤3）+ post acted 掩码 =
    capped 掩码；
  - UTG 扫描（rc_f[2]）改扫 **post 可行动集**：全员 all-in 时
    `rc_no_utg = 1`、post.turn = NO_SEAT（镜像 VM C5 与 validator 的
    `next_active_seat(&post.seats, …)`）；
  - KAT：单封顶/双封顶两形状 validator + trace 级 AIR + 篡改拒绝全过。

**canonical 行链生产者**（`src/canonical_dispatch_trace.rs`，新模块）：

- `project_state_image`：`TexasPokerTable → CanonicalStateImage` 确定性
  投影（deck/rules 用 stage-0 权威推导；governance/settlement/custody/
  roots 用**手级** scope——跨行 immutable；Revealing subtag = purpose
  序数；Betting deadline==0 的中间态以 dispatch 前 armed 值修正）。
- `witnesses_from_dispatch_records`：DispatchTrace → call_seq 连续、逐行
  咬合的 canonical 行链——命令行 + CompleteReveal 内联并入 SubmitReveal
  （Reveal completion opening + blind opening）+ AdvanceBettingRound →
  AdvanceRound 行（board-reveal opening）+ EndWithoutShowdown 行。
- 端到端验收（`texas/src/starknet/canonical_trace_roundtrip.rs`，真实
  stwo 出证）：1BB 盲注 all-in 手的 SubmitReveal×2 → 封顶盲注 Reveal
  completion → all-in Call → AdvanceRound 五行链 validate_batch +
  prove/verify 全通；常规手 preflop 段同样可证。**all-in 连跳收注自此以
  多个单街行呈现——PotCollected 单街投影分歧在 canonical 路径结构性
  消除**。

**剩余边界（fail-closed，后续接线规格）**：

1. ~~postflop RevealStreet / Showdown completion 的 AIR 组合~~ —
   **closed（2026-09-15，#22②扩展全部落地）**。前次会话的 rcs/rcd
   约束组违约（#21892/#21995）根因是完成族 gate 以数值 kind 绑定而
   row() 以布尔发射 flag——本次以 **pre_subtag one-hot 划分**重写：
   - **门结构**：`rcf_gate`（家族门，linearized flag×SubmitReveal）+
     hole/board/showdown 三位 one-hot（AIR 钉 `pre_subtag = hole + 2·board
     + 3·showdown`）→ `rc_gate := rcf∧hole`（preflop 盲注组自动收窄）、
     `rcs_gate := rcf∧board`（RevealStreet）、`rcd_gate := rcf∧showdown`。
     新增 42 列（门/one-hot/rcs 扫描 advice），NUM_COLUMNS 同步；
     freeze 豁免按族生效（`is_reveal_completion` 覆盖三完成变体）。
   - **rcs 组**（Board 窗口完成 → 同街下注轮）：header/street 两比特
     分解、post acted = folded/all-in 补位、pending 清零、逐座位资金/
     状态冻结、current=0/min=BB（公开 blind scope 锚定）、deadline
     = ts + betting_timeout、opening 承诺锚、post-Active UTG 扫描。
   - **rcd 组**（showdown 窗口完成 → ShowdownDisplay）：header 冻结、
     deadline = ts + showdown_display_ms、资金/座位全冻结、下注面清零。
   - **KAT**：street（HU + 三人局含 Folded 座位）/showdown 完成的
     validator + trace 级 AIR + 篡改拒绝 + 真实 stwo prove/verify 全通
     （`canonical_reveal_street_completion_satisfies_air` /
     `canonical_showdown_completion_satisfies_air` /
     `canonical_direct_air_proves_street_and_showdown_completions`）。
2. **生产者全手贯通**（`canonical_dispatch_trace.rs`）：
   - 完成行 opening 按 **purpose** 分类（DealHole→Reveal / Board→
     RevealStreet（bb_amount=BB 通道）/ ShowdownOwner→Showdown）；
   - 完成级联的 runout 形状 `[AdvanceBettingRound, CompleteReveal]`：
     完成行 post 取 advance.pre（真实边界下注轮——trace 末步 post 被
     patch 成 dispatch 终态，不可直接用），advance 以独立行跟随；
   - deadline 修复：VM dispatch 级 disarm/re-arm 使 micro-step 快照带 0，
     按链上连续性回填（完成行 = canonical 公式值 ts+timeout，advance
     行 post = dispatch 终态 re-arm 值，其余 = 上一行 post）；
   - `truncate_at_supported_boundary` **移除**：整手控制轨迹（翻前盲注
     完成 → flop/turn/river 窗口完成 → 摊牌窗口完成 → ShowdownDisplay
     终态）validate + prove/verify 全通
     （`full_hand_control_trace_proves_through_showdown_display`）。
   - 配套放宽（全部镜像"揭示物化"语义，逐条注明）：reveal 完成行放行
     board 承诺轮转（AIR+validator）、非最终 reveal 提交行放行 hole
     承诺物化（摊牌窗口逐座 token，AIR 槽 2 豁免 + validator 同口径）、
     摊牌完成座位冻结豁免 hole 承诺、ShowdownDisplay 投影 street=5、
     AdvanceRound 第 7 号 schedule profile（street 4 → 摊牌窗口：
     purpose=3、cards=0、count=0——摊牌逐座 token 由状态镜像掩码承担，
     AIR `validate_board_reveal_opening` 同步分支）。
3. **hooks REAL 归档接线**（`texas/src/starknet/hooks.rs`
   `build_appchain_hand_proof`）：实时镜像控制轨迹 → 行链 → 出证 →
   `HandProofBinding`（终态 ShowdownDisplay/Waiting 绑定；任何未入证
   selector 族 fail-soft 返回 None 回退遗留路径）。`dev_bot` buy_in
   1000→100（10×BB 垫高退役，1BB 盲注 all-in 极端手型不再是结算盲区）。
4. 密码学方程（BG/DLEQ/reveal token）维持 Plan D native 验证边界。
   全量回归：poker_l1 364 绿、poker_texas_air 225+10+1 绿（含
   `--include-ignored` 慢 prove KAT 59 绿）、texas 175+6 绿。

## 2026-09-15 德扑规则全面场景测试（逻辑正确性验收）

**背景**：`evaluator.rs`/`hand_rank.rs`（牌型评估）此前零测试；摊牌
派奖（`settle_hand`/`evaluate_player_hands`）只有边池分层金额测试、
无真实手牌决胜场景；盲注定位只覆盖单挑。新增
`texas/src/pokergame/table/holdem_scenario_tests.rs`（29 用例，全绿）：

- **牌型评估矩阵**：十类牌型识别（皇家同花顺 → 高牌）、类别排序链
  （真实五张样本逐级压制）、kicker 逐级比较（一对/两对/三条/四条/
  同花）、轮子 A2345 与钢轮、6 高顺压轮子、Broadway 压 K 高、7 选 5
  （同花压顺子、葫芦、对子诱饵）、牌面 playing-the-board 平分、公共
  牌四条 kicker 战、公共轮子 + 底牌 6 陷阱、<5 张无手、六张同花取
  最高五张。
- **摊牌结算端到端**（mental-poker `playing_card` 直接注入 = reveal
  完成等价物）：高对胜出净得 pot−rake（零和守恒断言）、同点数 kicker
  战、三层 all-in 边池逐层派奖（短 all-in 最强牌赢主池 / 次强赢边池 /
  跟满者收回未跟注层——含 35 抽水分摊的精确到账）、三家平分（公共牌
  为各家最优）、弃牌座位排除出评估、<5 张公共牌 F5 平分（奇数筹码归
  首座）。
- **盲注定位与下注序列**：三人首手（按钮即小盲，与 canonical AIR rc
  组同口径）、跨手 dead-button 轨道轮转（SB = 上手 BB）、dead small
  blind（基准座 sitting out → 无小盲）、短盲注 all-in 封顶、min-raise
  链（current_bet/min_raise 推进 + 短 all-in 不重开）、翻前 fold-win
  未跟注返还（no flop no drop）、翻后 fold-win 按 fold_win_rake 公式
  抽水（含未跟注扣减基数）。

回归：texas 204+6 绿（新增 29），poker_l1 364 绿，poker_texas_air
225 绿；无新告警。

## Canonical AIR — composed relations (current)

`texas_canonical_air` (fixed-width ABI, `CanonicalTransitionKind` 0..=28,
29 selectors) composes and admits:

- all fixed mid-round betting relations: `Call` (incl. short all-in), `Raise`,
  `Bet`, funding, join/leave, force/kick, `SetLeaveAfterHand`, `AdvanceRound`,
  betting time-bank extension;
- showdown settlement algebra (`canonical_settlement_air`, 16-row domain +
  borrow/carry decomposition) and the rake opening (`canonical_rake_opening`);
- reveal-assignment ledger opening (`canonical_reveal_opening`);
- non-terminal reveal-timeout cascade scope (`reveal_timeout_cascade`,
  pending-union ascending table walk);
- `AutoFold` timeout suffix, `EndWithoutShowdown`, reset-only and
  reveal/reconstruct timeout reset families;
- state-root **binding** (`state_root_binding` — Flock proof replaces host
  recomputation);
- the fixed non-cascading `AdvanceDeadline` shuffle-timeout micro-step
  (minimum pending seat, refund/pot/chip-pool conservation, deck-commitment
  rebuild);
- the settlement-privacy circuit skeleton (`settlement_private_circuit`,
  P2-M1; §8.2 `action_log_digest` slot wired by #18 Phase B —
  `action_flags` / `accepted_seq_digest` stay zero-reserved).

## Canonical AIR — real gaps (fail-closed)

1. **Curve crypto equalities stay out of AIR** (shuffle / reveal /
   reconstruct). Plan D scope: native verification (host + on-chain EC_OP
   `hand_batch_stark`). Acceptance = a full-residual batch settles in one
   sepolia tx at acceptable gas (Plan D P1.4; contract side ready, not yet
   measured on-chain).
2. **Final shuffle/reveal phase switches** still fail-closed — acceptance:
   canonical AIR composes the complete ShuffleComplete/RevealComplete
   terminal-transition relation.
   **实施就绪设计（2026-09-05 调研定稿，下一步按此实施）**：
   - fail-closed 门的确切位置 = `src/texas_canonical_air.rs:5304` 的
     `non_final_protocol_submit` 冻结约束（post == pre：phase/subtag/street/
     deadline 四组镜像）；`is_protocol_submit = SubmitShuffle | SubmitReveal |
     SubmitReconstruct`（:868），现仅 reconstruct completion 有组合范本
     （:5311-5322：post_phase=1、subtag=RECONSTRUCT、pending mask 重置为
     participants）。
   - VM 完成语义（oracle 依据 = poker_l1 dispatch.rs:2490-2540 的 e2e 测试）：
     ShuffleComplete = 最后一位贡献者提交后 deck 已被替换为最终 output、
     `shuffle_phase()` 离开 BEFORE_PREFLOP、进入发牌/reveal 阶段（pending
     mask 重置为 reveal 参与者、deadline 重挂）；RevealComplete = 最后一份
     reveal token 入账后 `enter_betting(ROUND_PREFLOP)`、street→preflop、
     betting deadline 重挂。
   - 组合面（按 reconstruct completion 的既有范本镜像）：
     ① `src/texas_canonical.rs`：`CanonicalProtocolCompletionKind` 增
        `Shuffle = 2` / `Reveal = 3`；`CanonicalProtocolCompletionOpening`
        增加对应 opening（completed/pending mask、deck 承诺切换
        pre/post、cards_dealt、street/phase 目标值、deadline）；validate
        侧按 :959-962/:1236/:1339 的既有 completion 校验模式镜像。
     ② `src/texas_canonical_air.rs`：witness 行新增 opening 列
        （PROTOCOL 区偏移顺延）；把 :5304 的 `non_final_protocol_submit`
        拆为 `non_final_submit = is_protocol_submit - all_completions`，
        Shuffle/Reveal completion 行改为组合约束（phase/subtag/street/
        deadline 目标值等式 + pending mask 重置等式 + deck 承诺绑定）；
        advice 侧复用 :1424 的 protocol_submit 逆元槽位。
     ③ 测试：两种 completion 的 prove/verify 正例 + 篡改负例
        （phase 目标值/掩码/承诺各自篡改必须拒绝），镜像既有
        RevealTimeout 家族测试形态。
     ④ 纪律：crypto 方程本身仍按 Plan D 留在 native/链上 EC_OP 通道——
        本组合只证明"状态机规范化语义"，不证明洗牌/揭示方程。
   - **实施状态（2026-09-05）**：ShuffleComplete 已全部落地（枚举/校验/AIR
     约束/正反例测试，canonical 145/145；约束度数保持声明值 3——完成单元
     布尔化 + 度数门拆分）。
   - **RevealComplete 实施进展（2026-09-11，#22② 恢复实施）**：
     ① **盲注/规则 opening 通道已落地**——复用 rules-opening（同一条
     Blake2b 语句鉴权完整 `TableRules`）：`CanonicalBlindOpening`
     （small/big blind、ante_mode、ante_amount）+ `blind_opening_of` 投影
     + `validate_rules_opening` 扩展盲注/ante 不变量（big>0、sb≤bb、
     ante 模式合法）。② **host 关系已组合**——`CompletionKind::Reveal = 3`
     + opening 扩展（UTG/SB/BB 座位、实投面额、单挑布尔、reveal 承诺
     端点锚）+ `validate_reveal_completion_opening`（镜像 `post_blinds` +
     `start_betting_round(is_preflop)`：参与者全 Active、无封顶盲注、
     ANTE_MODE_NONE、正常下注开局；越界形状独立错误 fail-closed）+
     正反例测试（UTG/座位/面额/单挑/价格/deadline/承诺锚/封顶逐项）。
     ③ **AIR 组合已贯通（2026-09-11 端到端 prove/verify 绿）**——重写为
     "追加列 + 线性化 gate"布局：~166 条新 advice 列全部追加在 ABI 末尾
     （既有偏移零扰动），完成选择子 `flag×SubmitReveal`（二次）经专用
     度数 1 gate 列线性化（`shuffle_timeout_gate` 模式），全部约束保持
     声明度数 3。位置规则 = 模 9 循环"首个 Active"扫描（每个基座
     button/SB/BB：rotated activity + "此前无 Active"前缀 q 递推 + 首位
     选择子 f = rot·q；SB 含单挑虚拟距离 0 槽 = button 本身；UTG =
     BB 后首个 Active——单挑下该扫描恰好回到 button，与 VM 特例一致）；
     占用收敛（非 Empty/Out 即 Active）+ 计数 ≥2 逆元使该扫描与 VM 的
     mod max_players 扫描一致。盲注面额经公开 blind scope 预处理列
     （13 列，插在 rake scope 与范围表之间）锚定到与 rake 共享的同一条
     rules-hash 语句（`prove_canonical_reveal_completion_batch` +
     `verify_canonical_rake_binding` 扩展）；逐座位资金移动
     （post_bet=posted、pre_stack=post_stack+posted、
     post_total=pre_total+posted）用 limb4 加法进位，盲注座 post stack
     非零（无 AllIn 翻转）由逆元证明；deadline=ts+betting_timeout；
     ante 必须 NONE（scope 列钉零）；reveal 承诺轮转留 native/EC_OP
     通道（suspended 槽钉零，deck/reconstruction 双端冻结锚定）。
     **准入已翻转**：`crypto_admitted` 与 `validate_direct_batch` 对
     SubmitReveal 放行。测试：heads-up + 三人局（非单挑位置分支）
     assert/prove/verify 正例 + 归档盲注脱钩/规则脱钩负例 + 12 列篡改
     负例全绿。**fail-closed 收窄**（host 接受、AIR 拒绝的不可达形状）：
     参与者 <2、占用座含 Folded/Waiting/AllIn、ante≠NONE。
   - **#22④ 准入翻转（2026-09-05）**：`validate_direct_batch` 对
     SubmitShuffle/SubmitReconstruct 放行；协议行全字段冻结集进 AIR
     （turn 双端 NO_SEAT、资金/参数/掩码/hand_id/timeout 配置/9 座位全像/
     非轮转承诺逐 limb 冻结）。canonical 147/147、全量 367/367。
   - **#22⑤ state-root 重算进 AIR——v2 已落地（2026-09-05）**：放弃 v1
     单体组件（1713 列混合布局，691s 仍 ConstraintsNotSatisfied），按
     cairo-air 官方形态重写为五组件分解（`src/poseidon252_v2.rs`）：
     ChainAir 链接组件（吸收/门控/mix 线性/边界/锚点 + 状态链 multiset）
     + MulAir（32×16→48 卷积协处理器）+ ReduceAir（48=z+32q·P 协处理器）
     + 2^16/2^12 范围表；非线性代数经 96 坐标 LogUp 链接元组下放。
     实测：e2e prove+verify **2.91s**（≈237×），五组件 rowcheck 全过，
     篡改负例三连全拒，原生层与 starknet_crypto 位精确等价保持。
     实施细节见 git 历史（原 `docs/plan-poseidon252-v2.md` 已删除）；v1 单体组件
     （`poseidon252_air_component`）已整体移除（2026-09-06：`--include-ignored`
     全量门禁会复活其失败测试；对照价值在 git 历史）。
   - **#22⑤ 字节 scope 组合——完成（2026-09-06）**：v2 验证路径不再做任何
     宿主 Poseidon 重算。三项机制：① 预处理树只含公开字节派生列
     （pos/flag/轮密钥/吸收词/选择子/init + 范围表 + 确定性 enabler），
     验证方用 `public_scope_columns` 重建整棵期望树做根等值比较
     （`v2_expected_preprocessed_root`）；② claimed anchor 字节在首次承诺前
     混入 Fiat–Shamir，ChainAir 终边界改为对 anchor limb **常量**钉住
     （S_ANCHOR 48 列删除）；③ void 元组（padding 漫步终态）移入见证树，
     由 multiset 链强制。同时修复两个真实缺陷：void 演化漏掉 `n_pad` 个
     完整零吸收 padding 置换（log≥9 布局即触发 logup 失衡）；协处理器
     行数公式漏算 padding/leftover 行（改为镜像行循环精确计数）。
     新增 `prove/verify_name_commitment_v2`：把 `zchain.string.v2` 名称
     契约（`canonical_borsh_preimage`）封成链 statement，AIR 重算
     poseidon_hash_many 并钉住锚点——等价测试断言锚点 lane-0 ==
     `table_name_commitment(name)`（legacy 宿主哈希，仅测试用作 oracle）。
     测试 8/8（e2e/rowcheck/篡改三连/name 正反例）；全量门禁 `--include-ignored` 384/384（2026-09-06）；原 v1
     rowcheck、create_table 8/8 回归全绿。**残留**：create_table AIR 的
     name-hash 期望值已切换为消费 v2 归档的 claimed anchor 投影
     （2026-09-11：方法归档 v4 + `name_commitment` 公开输入；后被 v34/v35
     展示名出共识重构整体移除——名字承诺随 metadata 对象出走，本项由
     该重构收口）。
3. ~~Terminal timeout cascade~~ — **closed (2026-09-05)**: the terminal
   cascade batch proofs exist and pass — multi-pending kick batches, the
   kicks→terminal-reset refund batch, the kicks→sole-survivor award batch
   and its raked variant (schedule tamper negatives included).
4. **Reconstruction final composition** — acceptance: reconstruct submission
   leaves fail-closed.
   **实施就绪设计（2026-09-05，与 #22② 同模式）**：reconstruct completion 的
   规范化约束已在 AIR（:5311-5360）；剩余 = (a) 非最终 reconstruct 提交行的
   **全字段冻结集**——turn=NO_SEAT、current_bet/min_raise、pot/chip_pool、
   acted_mask、leave_after_hand_mask、button/max_players、9 座位全像
   （status/acted/stack/bet/total_bet/addon/time_bank/三个承诺）、非轮转承诺
   （board/reveal/rules/governance/settlement/custody/rit）——全部 gate 在
   `is_protocol_submit`（度数 1，冻结约束 ≤3 ✓）；(b) **deck/reconstruction
   承诺轮转** = native/EC_OP 通道残留（与 ② shuffle 同一口径：opening/端点
   锚定 + Plan D ④）；(c) **准入翻转**：`validate_direct_batch` 对
   SubmitShuffle/SubmitReconstruct 放行（完成 opening 行 + 非最终行），
   SubmitReveal/FoldWithProof 维持拒绝；(d) 测试：两 completion + 非最终行
   的 prove/verify 正例与逐字段篡改负例。残留信任：deck/reconstruction
   承诺轮转由 native 验证 + 链上批次背书（既有信任模型），canonical AIR
   只证状态机规范化。
5. **State-root recomputation** (as opposed to binding) inside the AIR —
   acceptance: AIR independently recomputes and matches the
   `state_root_binding` anchor.

Until these compose, a witness-free Stwo verification result alone must not
advance a production table head. `CanonicalTransitionWitness::validate_shape`
and the direct AIR both reject unused-payload smuggling (zero proof
commitments / auxiliary fields / legacy flags / deadline advice outside their
selectors; no-seat sentinel for seatless micro-steps).

## Layered soundness record

- DAPV (P layer) soundness: `docs/SOUNDNESS.md` (theorems 1/2, ρ-binding
  lemma; production instantiation = Stark curve EC_OP + Poseidon challenges).
- Settlement privacy: `docs/design/SETTLEMENT_PRIVACY_PLAN.md` (P2-M1..M4 done; v2
  zero-plaintext settle contract deployed sepolia, server-side enablement
  pending).
- Censorship resistance: `docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`
  (#16/#17/#18 Phase A+B wired; in-circuit legal-default constraints remain
  the mainnet gate).
- Performance baselines: `docs/PERFORMANCE.md` (release numbers, production
  pipeline, on-chain gas; older reports archived).
- Historical design archive: `docs/archive/` (host-zero Ristretto charter,
  old perf reports, trust-model/replay essays, migration blueprints).

Document map: [`docs/README.md`](README.md).

- **2026-09-12（shuffle-chain stage0，路线 A+B 上游半边）**：`src/canonical_shuffle_chain.rs` 生产者+原生 BG/DLEq/V3 双端校验落地；单批全链 13 行（7/8 协议行+下注+结算）prove/verify 绿、log 8 判定维持；新缺口记录：street 断点（StartHand→RevealComplete 不可直连）、级联批隔离、reconstruct 续链不可表达——实测详见 zchain `poker-appchain/docs/SHUFFLE_STAGE0.md`。
