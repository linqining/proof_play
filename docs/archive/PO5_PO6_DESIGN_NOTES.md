> ⚠️ **历史存档(2026-09-05 归档)**:poker_l1 VM host-native 验证的架构快照——
> 曲线叙事(BLS12-381/Ristretto)与链机制(consensus anchor/precompile/syscalls)
> 已过时(Plan D + poker_l1 收缩)。"无 sound 递归聚合、验证 O(N)"的结论仍成立,
> 由 `docs/TODO.md`(canonical AIR 缺口 / 递归协议条目)以新口径接管。

# P0-5 / P0-6 当前实现与可信边界

本文只描述 `poker_texas_air` 当前生产架构。`poker_zkvm` 不在 zchain workspace、依赖图或
本轮交付范围内；这里不把旧 zkVM/递归实验当作可用能力或待修前置条件。

本文的 P0-6 四段 plan 描述的是既有 host-native orchestrator/composition 路径，不能与
直接 `texas_canonical_air` tagged receipt 路径混读。后者不依赖 `ProveTask` 或 host replay：
`verify_canonical_proof` 只提供结构审计，`admit_canonical_proof` 及
`admit_canonical_proof_with_state_openings` 当前明确 fail-closed。尤其是 direct AIR 的
`AdvanceDeadline` 已直接覆盖两条固定宽度分支：`flag = false` 时由 ABI 打开的
`betting_timeout_ms` 驱动 time-bank extension；`flag = true` 时是受限、非级联的 shuffle-timeout
micro-step。后者要求 Shuffling header、pending mask 的最低 active seat、deadline height 和
`shuffle_timeout_ms` 一致；AIR 约束该 seat 变为 Out，返还 `stack + pending_addon`、把其本轮
bet 收入 pot、清空 key/hole commitments、重建剩余 active mask（至少两人）、保持 total/time-bank
历史并以非零新 deck commitment 重建牌堆。其他 seat 和其它 opaque commitments 均不可变。
这只证明 commitment 发生了受限、非零的状态转换，不重新计算洗牌的密码学关系；该关系仍属于
dedicated crypto AIR/host-native verifier 的信任边界。direct AIR 另有受限的非级联 `AutoFold`
timeout suffix，但尚未证明 VM 的 turn/round cascade、settlement 或 reset。direct canonical ABI v5
已把 shuffle/reveal/reconstruct 的九位 pending participant mask 和五项 timeout config 纳入 endpoint
opening；非终局 submit 必须在 AIR 内精确清除 action seat bit，post mask 必须非空。final
`SubmitReconstruct` 已有专用 completion opening：完成条件由 pre pending mask
精确等于 action seat bit 推导，不依赖 `action.flag`，并绑定 authenticated timestamp、checked
shuffle deadline、deck cursor reset、active-seat shuffle mask 重建及 suspended reveal/deck/
reconstruction commitments，从而约束 `Reconstructing/1 -> Shuffling/2` normalization。final
shuffle/reveal 所需的 reveal schedule、blind/ante opening 仍未完成；reconstruction 的
Ristretto 方程和 deck/reveal commitment 重算也尚未组合。因此 production admission 仍
fail-closed，本文下述 legacy plan 完成项不代表 direct canonical proof 已具备 host-zero
admission 语义。

reconstruction 的下一层 no-replay ABI 已落地于 `canonical_reconstruction_binding`：request
call-context 不直接包含最终 transition commitment，而是包含把 request digest、transition
commitment、nullifier 清零后的 `canonical-crypto-scope.v1`，消除 fixed-point。table-wide
fixed-width opening 认证 epoch、pending mask、aggregate/owner keys、每 seat 两张 readable hole
card 与 optional 52-card accumulator；共享 lookup-backed Blake2b batch 将该 opening、canonical
context/prior-state digest、encoded request、pre/post state image 和 crypto scope 一次性绑定。
这一层尚未证明固定 52 card constants、Ristretto contribution equations、accumulator transition
或 final deck/reveal commitment，所以仍只是下一组合层的 statement substrate。

## P0-5：Host-native 验证、digest 绑定与聚合边界

### 已完成

- Orchestrator 从完整 `ProveTask` 重放 canonical VM dispatch，要求 pre/post table、
  `DispatchContext + selector + raw_args`、method input、table/hand/call/version 全部一致。
- 每个 method STARK 由 host-native Stwo verifier 验证，成功后才能签发字段私有的
  `VerificationReceipt`。
- `VerifiedChain` 检查 table/hand、连续 call sequence、完整 state root/version 链；
  `ExpectedChainAnchor` 再绑定精确 receipt 数量、调用 digest 和首尾状态。
- consensus anchor 路径会验证 block/certificate、SMT inclusion proof 和每笔 transaction
  signature，并从签名 pubkey 重建 caller，避免仅从同一批未认证 task 反推 anchor。
- 四条 active Mental Poker crypto route 均有 stage-3 dual-proof package：
  `fold_with_proof`、`submit_shuffle_v2`、`submit_player_reveal_tokens`、
  `submit_reconstruct_deck`。退休的 `join_and_shuffle` 与 WAITING `leave_with_proof` 已从
  source/task/AIR/precompile/package/service 全链路删除，稳定 discriminant 15/16 统一 fail-closed。

### Crypto proof 的当前信任模型

当前选择是 `host-native verifier + canonical request/receipt digest + context binding`，不是
BLS12-381 AIR，也不是 Cairo verifier execution proof：

1. verifier 从已认证 task/pre-state 重建唯一 canonical crypto request；
2. 对该 request 执行一次 host-native BLS12-381 verifier；
3. 成功后签发 `PrecompileCallBinding`。其字段私有、无 wire deserializer、无 unchecked
   constructor，safe Rust 调用者不能伪造；
4. method AIR 约束完整 256-bit request digest 与 receipt digest；
5. production verifier 再校验 canonical bytes、precompile id、ABI、backend、digest，以及
   table/hand/call/seat/pre-post state scope，但不重复同一昂贵 BLS 验证。

公开的 `PrecompileCallBinding::reverify()` 仍保留，供跨进程持久化边界或显式要求独立二次
重放的调用方使用；正常 Orchestrator/dual-proof 路径依赖 verifier-issued capability，一次
native crypto 验证即可。

### 未完成且不应误报

- 当前没有 sound recursive/succinct aggregate proof；验证成本仍是 O(N)。
- descriptor-only `AggregatorAir` 不验证 child proof，生产聚合入口保持 fail-closed。
- host receipt 或 outer digest package 不是“链上常数成本验证”的替代品；若未来需要链上压缩，
  必须另行实现并审计固定 Texas/Stwo verifier program。
- 本地验证不能单独证明交易已被共识收录，必须使用 consensus-derived anchor。

## P0-6：下注动作覆盖范围

### 已完成

- fold/check/call/raise/bet、permissionless `advance_deadline` 与管理员 `force_fold` 都会从
  canonical pre/post table 重放真实 VM action，并把 trusted row 绑定进 STARK transcript。
- mid-round 路径约束 actor 的 stack/bet/total_bet、pot/round 不变和下一行动座位。
- heads-up 最后一个 `check` 已支持 terminal end-of-round：可收池、清零 seat bets、推进
  round、令 `current_turn = None`，并用 sentinel trace encoding 与 canonical post-state 对齐。
- last-opponent `fold` / `fold_with_proof` 已支持 clean terminal settlement：先收集全部 live
  `seat.bet`，再约束 `pre_pot + collected_bets = gross_pot`、`award + rake = gross_pot`、
  `pre_winner_stack + award = post_winner_stack`，最后 reset 到 `WAITING`。生产 verifier 仍从
  canonical VM replay 派生 winner 与完整 pre/post table；`fold_with_proof` 同时保留 native
  DLEq request/receipt digest 和调用上下文绑定。
- terminal showdown reveal 的 settlement + reset 级联已由一次外部 `call_seq + 1` 和内部 stage
  顺序表达，不再依赖旧的双 version bump 特判。
- showdown 已先在 `poker_l1::texas_poker` 规范化为确定性的 `SettlementPlan`：固定 9 座位、
  最多 9 层 side pot、1/2 个 runout、完整 hand rank/winner mask、按 button 顺时针分配奇数
  筹码，并对完整 Borsh plan v2 做 domain-separated Blake2b digest。runout shape 使用
  `SettlementRunoutSchedule::{Single, Twice { start: RitStartStreet }}`，因此 count 与共享前缀
  不再是两份可冲突事实。单座位外层 pot 被视为
  uncalled return，不抽水且不拆成两次 runout。
- 最后一个 showdown reveal 的 canonical replay 必须恰好产生一个
  `SettlementPlanCommitted`。verifier 从事件重建 plan digest、runout count、gross/rake/
  total awards 和固定 9 座位 award；submit-reveal AIR 绑定全部投影，并用 4×16-bit ripple
  carry 约束 `total_awards + rake = gross_pot`。非终局 reveal 出现任何 settlement event
  会 fail-closed。
- Run It Twice 已具备完整 native 状态与 reveal routing：记录触发轮次、共享 board 前缀和
  第二 board；后续公共牌 assignment 显式绑定 `(encrypted index, runout, board position)`，
  reconstruct restart 使用新 deck index 且保留两块已公开 board，终局 plan 的
  `runout_count = 2` 会进入上述 AIR 投影。

### 本轮补齐的 fail-closed 分支

- terminal fold reset 已覆盖 pending addon credit、`want_leave` seat removal/refund，并在
  Settlement component 中固定绑定 9 座位 post stack、post pending addon、post occupancy、
  addon credit/refund 与 chip refund；reset 后所有 pending addon 必须为 0。
- `kick_player` 在 WAITING 状态触发的 nested reset 已规范化为 `ResetOnly` settlement，
  active heads-up 任一玩家被踢时触发的 `PotCollected -> WithoutShowdown -> reset` 也已规范化。
  native 状态机先消除了同一 dispatch 重复 reset/version bump 的级联；method AIR 通过绑定的
  `reset_cascade` 只允许 canonical `version += 2, post_round = WAITING, post_pot = 0`，被踢下注
  与其余 live bets 由 BetCollection component 统一守恒，award/refund/reset 则由 Settlement
  component 约束。其他未建模 multi-version transition 继续 fail-closed。

showdown side pot、多人 winner、hand evaluator、rake 和 RIT 结算现在可由当前生产架构接受，
但其可信性来自 verifier 对 canonical native dispatch 的重放与完整 `SettlementPlan` digest
绑定；STWO AIR 本身不重新执行 hand evaluator 或 side-pot planner。若目标改为“即使 host
verifier 恶意也能由单个 STARK 独立证明结算计算”，仍需把这些算法改写为 AIR/固定 verifier
program，这不属于当前 host-native + digest 架构。

terminal `call` / `raise` / `bet` 的 clean round completion 已支持：native replay 先重建动作后
的下注状态，再约束所有 live `seat.bet` 收池、`pre_pot + collected_bets = post_pot`、清零
seat bets 和下一 reveal phase。这些此前未覆盖的分支不能只增加一个布尔列完成：VM transition
会同时扫描多个 seat、推进 round/reveal phase，甚至执行 settlement/reset。因此现通过下述
四段可组合 transition plan 建模。孤立 single-task archive 仍把四段分别证明，不能只提交 legacy
method proof 绕过 component 验证；当前 hand-stream throughput 路径则把同一 canonical plan 的
active rows 收敛进一份 tagged Stage proof，并与一份 tagged method proof 组成唯一可接受的
two-proof package。

### 可组合 transition plan / legacy single-task 四份独立 STARK proof

新增 `airs::composition`，canonical native replay 会把一个原子 dispatch 规范化为固定顺序：

```text
dispatch pre image
  -> SeatUpdate
  -> BetCollection
  -> RoundAdvance
  -> Settlement/Reset
  -> dispatch post image
```

`CompositeTransitionPlan` 固定绑定 schema version、method/table/hand/call scope、完整 canonical
pre/post table image digest 和四段业务 payload。每段都有相同的 stage header：

- `active + stage_kind + stage_index`；
- 完整 256-bit `plan_digest`（16 个精确 u16/M31 limb）；
- 完整 256-bit `input_digest` / `output_digest`；
- 相邻段强制使用同一 boundary digest。

这里的 boundary digest 是 verifier 从完整原子 replay 生成的 projection commitment，不冒充链上
持久化的 intermediate table root。四个 component 现在分别生成独立 Stwo proof、独立 trace
commitment 和独立 Fiat–Shamir transcript；bundle 验证固定检查
`stage[i].output_digest == stage[i+1].input_digest`，而不要求 VM 在一个 atomic dispatch 中额外
落盘四份中间 table。

四个固定宽度 component 当前包含：

- `SeatUpdate`：acting seat 的 stack/bet/total_bet checked-u64 delta、fold/all-in 和固定 9 座
  `acted_this_round` 前后投影；raise/bet 对其他可行动座位的 acted reset 也进入 payload。
- `BetCollection`：action 后固定 9 座 seat bets，使用 9 段 4×16-bit ripple-carry 在 AIR 内求和，
  再约束 `pre_pot + collected_bets = post_pot`；全员 check 的零金额 collection 仍是 active stage。
- `RoundAdvance`：pre/post round、reveal phase、current turn sentinel、pot 和 community-card count，
  并限制合法的 preflop→flop→turn→river→showdown 边。
- `Settlement`：复用 showdown `SettlementPlanBinding`，无摊牌路径生成 domain-separated deterministic
  plan digest；固定 9 座 awards、addon credits、chip/addon refunds、post stacks、post pending
  addons 和 post occupancy 均进入 AIR，并约束 chip pool / addon pool / rake 守恒和 reset。

production verifier 已在 fold/check/call/raise/bet/advance-deadline/force-fold、`fold_with_proof`、
`kick_player` 和 `submit_player_reveal_tokens` 的 canonical replay 后派生并验证该 plan。single-task
归档按四个 component 验证，tagged hand stream 则从同一 plan 重建 Stage rows；两条存储路径不会
形成第二套可自由选择的业务解释。

`kick_player_v2` 的证明输入也已收窄为 seat-only canonical admin command：目标 seat 仍由管理员显式
选择，`Admin` cause 由该 typed command 决定；deadline 与 reconstruct deadline 路径分别只能产生
`Timeout` / `ReconstructTimeout`。legacy `kick_player(seat, reason)` selector helper、参数结构和
replay 分支已物理删除；proof task、native replay 与 AIR 都只解码 `SeatIndexArgs`。

`AirStatement` / `TexasPublicInputs` 已加入完整 `ComponentStatement`，把 component kind、plan
digest、stage index、input/output boundary commitment 混入 transcript。legacy
`ArchivedCompositionProofBundle` 固定保存 SeatUpdate、BetCollection、RoundAdvance、Settlement
四份 proof；缺失、重复、重排、plan digest 不符或 task scope 不符都会拒绝。当前 tagged service
package 不再内嵌这四份 proof，而是严格保存并验证一份 tagged method proof、一份 tagged Stage
proof 及其唯一 continuous state stream。

这仍不是 recursive/succinct aggregation：legacy single-task composite archive 需要验证原 method
proof 和四份 component proof；tagged hand stream 则整批验证两份 proof，但验证成本仍随 batch
规模和 trace 大小增长。两者解决的是职责拆分、可组合性、吞吐和 fail-closed 边界，不解决链上
常数成本压缩。

### 证明时间优化

以下数据描述 tagged batch 落地前的 legacy 优化阶段。四份 proof 的独立性曾用于本地并行执行：
method proof 与 component bundle 并行，四个
component proof/verify 以两层 Rayon join 并行，durable method archive 与 component archive 的
恢复验证同样并行。proof 数量、每份 trace commitment、Fiat–Shamir transcript、stage 顺序与
plan digest 均未改变。参考开发机上，单个 composite check 从约 22.97s 降至约 7.2s；完整牌局
从约 425.03s 降至约 213.46s。`TEXAS_PROVE_TIMING=1` 可输出 method 与四个 stage 的逐 proof
prove/verify 耗时，计时器默认关闭。

2026-08-06 的完整牌局分项基准进一步确认，主要开销是每份 Stwo proof 的固定启动成本，而不是
Stage 列数线性增长：65 列 `RoundAdvance` 与 610 列 `Settlement` 相差约 9.4 倍，单 proof
prove 时间却只相差约 36%；旧路径 32 次 dispatch 共启动 104 次 component prove，四类 Stage
累计约 800s CPU span。

因此先新增 throughput-oriented `ArchivedCompositionBatchProofBundle`，把同类 Stage 的连续
transition 放进四份固定 1024 行 proof。该版本把 26 个连续 composite transition 从 104 次
Stage prove 降为 4 次，完整牌局 wall-clock 从基准 335.99s 降至 168.14s。

随后 batch archive v2 已进一步改为单份 Tagged-union Stage proof：按 task 顺序、再按
`SeatUpdate -> BetCollection -> RoundAdvance -> Settlement` 顺序，仅写入实际 active Stage 行，
inactive Stage 不占行，剩余行全部为零。`stage_tag` 使用两个 bit 列约束为 `0..3`，各 variant
复用最大 Stage 的列区间，较窄 variant 的尾部由 verifier 重建为零。最坏一笔 transition 激活
四个 Stage，因此服务端保守按 256 task/chunk 分批；实际 row 数单独进入 archive 与 transcript。
这把每个 batch 的 Stwo prover/PCS/FRI 启动数从 4 降为 1，archive 最大 proof 预算也从四份降为
一份。当前完整 32-transition hand 的真实 prove/verify 回归通过，wall-clock 为 134.91s。

批量路径没有沿用只能固定单行的 `BoundAir`。verifier 会重放完整 task 列表，重建每个 canonical
tagged Stage row 和 1024 行 padding，独立重算 Stwo original-trace commitment，并要求它与 proof
的 trace commitment 完全一致；batch ABI version、task/stage-row count、table/hand/call range 和
完整有序 task digest 也进入 transcript。空 batch、超过保守 task 上限、超过 1024 Stage 行、
跨 table/hand、call-seq 不连续、state-root 不连续、task digest/tag/trace commitment 不符均
fail-closed。Stage pipeline 外的方法允许作为 zero-Stage method row 混入同 hand 连续流，但必须
声明 `stage_row_count = 0`，且不会跳过 tagged method proof。当前 batch AIR 本身只约束 active bit、tag bits、tag/index 一致性和
零 padding；完整业务行仍由 verifier-owned replay commitment 绑定，与旧四 batch proof 的安全模型
一致。

旧四-batch 版本的分项 prove span 为 6.00s / 6.04s / 7.28s / 8.33s，batch step wall-clock
为 20.36s。Tagged-union v2 不再产生四份分项 proof；后续基准应读取单条
`batch-stage:Tagged[task/row]` timing，并把它与 method proofs 分开统计。

同步 durable service 已接入共享 batch sidecar。完整 actor-less canonical command payload 落地后，
service package schema 已破坏性升级为 v7，repository schema 升为 v6，旧 package/repository
直接拒绝且不执行迁移。package payload 是严格
single/tagged union：create/join 等 hand stream 外的孤立方法仍保存单任务 archive；`start_hand`
或 composite dispatch 可开启 `PendingProof`，已有 stream 内的同 hand non-composite 方法继续以
zero-Stage row 入队。repository 持久化连续 canonical tasks 和 tentative table，随后在显式
`POST /tables/:id/finalize-proofs`、下一次 `start_hand` 或达到 batch 上限时生成一份 tagged method
STARK + 一份 tagged Stage STARK。成功后整批 job 原子切换为 completed，每个 job 只保存
`batch_id + row_index + row_count`，并共同引用同一 sidecar。restart 会对同一 package 只恢复一次
receipt batch；pending stream 也会重建但继续排除在 verified chain 之外。package、row reference、
job metadata 或 pending lifecycle 任一错配均 fail-closed。P2P repair 已覆盖共享 sidecar：peer 可按
任一 row 的 job ID 返回完整 tagged package，本地验证对应 row 和整份 two-proof package 后按
`batch_id` 只落一份 sidecar，批内所有 job 同时恢复可用。若 completed package 首 row 是
`start_hand`，restart 会在 staged Orchestrator 上先切换 receipt segment，再原子验证/恢复整包。

普通玩家命令的 task payload 已不再重复保存 actor：`join_table.player` 由 authenticated caller
确定，fold/check/call/leave/request-leave 的 seat 由 caller/current actor 确定，
raise/bet/addon/rebuy 只保存金额。verifier 使用 canonical pre-state 重建 legacy dispatch ABI 后再
进入同一个 native 状态机。四类 active proof-bearing Mental Poker payload 也已完成同样收缩：
fold/shuffle/reveal/reconstruct 删除 caller seat，但完整 proof statement、deck、tokens 与 proof 字节
保持不变。join 的非 identity key 与 PK ownership proof 已收敛到 `join_table`。AIR、tagged method、
dual-proof 和 orchestrator 统一从 authenticated replay ABI
解码 crypto 参数，不再把 canonical payload 误当成 legacy wire layout。
consensus anchor 同样从认证 pre snapshot 顺序重放交易携带的旧 ABI，并要求重放终态等于认证 post
snapshot；因此 canonical digest 不会接受一个无法真实执行的 actor 声明。

service 验证热路径已加入 bounded process-local validated-package cache。cache key 是完整 sidecar
字节的 domain-separated Blake2b-256，而不是可复用的 `batch_id`；因此同一路径下替换 package
内容会强制 cache miss 并重新执行严格 decode/verify。一次成功验证会保留 immutable decoded
package 与本次 canonical stream replay 产生的 tasks，后续批内任意 row 的 `verify-proof` 只重复绑定
该 job 的 row index/count、task digest、pre/post root 和 lifecycle metadata，不再重复整批 native
replay 与两份 STARK verification。live finalize 已验证的 package 会直接进入 cache；restart 恢复则
只加载/解码共享 sidecar 一次，校验完整 row job set 后恢复一次 receipt batch 并缓存结果。cache
同时受 64 entries 与 256 MiB encoded-size 上限约束，淘汰只影响性能，不影响 fail-closed 语义。
tagged batch 完成时每个 job 的 `prove_count/chain_length` 也按 row 精确递增，不再把整批最终值
复制给所有 row；repository 会校验 pending rows 共享同一历史基线、最终计数恰好增加 row count，
restart 再校验批内计数位置连续。

原始 method 层的 tagged batch 也已实现。`ArchivedTaggedBatchProofPackage` 对一段同 hand 连续
transition 只包含一份 177-column tagged method STARK 和一份 tagged Stage STARK，并内嵌唯一的
`initial_state + commands + final_state` 连续流，不再要求 durable verifier 额外保存逐 task table
快照。生产入口会先完整
VM replay，再重新执行所需管理员授权与 BLS12-381 native verifier，最后把 request/receipt digest、
command digest、pre/post root/call_seq 和 Stage span 写入窄 method row。call→raise 两步真实 dispatch
已通过 package encode/decode、自包含 restart replay、两份 proof 重建验证和逐 row receipt 签发。
full-hand driver 已把 `start_hand`、两次 shuffle 与后续 composite tasks 一起入队，末尾原子生成
该 two-proof package；Stage pipeline 外的三行拥有零 Stage rows。旧 per-task archive 目前只保留给
create/join×2 和 hand stream 外的同步 service 路径。2026-08-09 debug test profile 的真实
24-transition heads-up full-hand 只剩 3 个 legacy setup proofs，加一个 23-row tagged method /
16-row tagged Stage package，端到端 prove/verify 为 26.55–26.92s。此前只批量化 18 个 composite rows、
仍单独证明 start/shuffle 的版本约 36.30s；更早的 Stage-only batching 路径约 134.91s。

现有 `DualProofBundle` 仍是“method STARK + native crypto request”的两部分传输格式；对
`fold_with_proof` / terminal reveal 这类 composite method，它不能替代当前 durable tagged
package 中的 tagged Stage proof；若走孤立 legacy single-task archive，也不能替代四份 component
proof，因此不能单独作为完整 composite archive。

## 本轮关闭的管理员授权与金额缺口

- `start_hand` / `kick_player` / `force_fold` 使用独立
  `AdminAuthorizationBinding`。production prover 与
  verifier 都从 canonical dispatch 重建 table-creator 权限，并把 ABI、role、完整 256-bit
  request digest 与 receipt digest 放入 AIR。request 覆盖 caller/pubkey、creator、链/块/时间、
  selector/raw args、table/hand/call/version、pre/post root 和 dispatch digest，不能再用
  prover 自报的 `is_admin = 1` 代替授权。
- 签名算法本身仍不在 STWO 中模拟。最终生产接受必须走 consensus-derived anchor；anchor
  现在显式验证 included transaction 的 ECDSA/Ed25519 签名，并将同一 signed call 的 dispatch
  digest 与 method receipt 链比对。未锚定的单 method/chain API 仍只是开发与离线语义验证接口。
- 所有 production trace-visible u64 金额都由 verifier 从 canonical table/input 重建为完整
  4×16-bit limb，并由 `BoundAir` 固定整行；资金加减使用 ripple carry/borrow 与最高 limb
  无溢出约束。本轮具体关闭了：`check` 的 current/seat bet 高 limb、`kick_player` 的完整
  `refund = pre_stack + pre_pending_addon`、`start_hand` 的 ante 高 limb以及
  `pre_pot + ante_collected = post_pot`、auto/force-fold、addon/rebuy 与 reconstruct 路径中
  曾经被零占位掩盖的真实 pot 投影。复审又补齐了 create/join/leave/reset、
  join-and-shuffle/submit-shuffle/leave-with-proof 的 canonical pre/post pot；不改变 pot 的路径
  使用完整 4-limb equality，reset/create 则显式约束 canonical post pot 为零。

## 重新审核后仍存在的证明缺口

- 所有 creator-only method 已绑定 canonical authorization request/receipt digest，但管理员签名
  算法本身、Mental Poker BLS12-381 proof、state-root Poseidon preimage hash、showdown hand
  evaluator/side-pot planner 仍由 host-native verifier 执行；AIR 绑定其 canonical 输入、输出或
  receipt digest，不提供“恶意 host 下仍可独立验证”的执行证明。
- terminal timeout fold 统一由 `advance_deadline` 证明，terminal `force_fold` 复用
  `FoldOutcome::EndWithoutShowdown`；两者都强制携带 SeatUpdate/BetCollection/RoundAdvance/
  Settlement 四段 canonical plan。hand stream 将 active rows 放入 tagged Stage proof；孤立
  single-task archive 才保存四份 component proof。
- `kick_player` 只接受普通 `version + 1` 路径，以及已规范化的 `WithoutShowdown` / `ResetOnly`
  双 bump cascade；其他未来出现的 multi-version advance/settlement 继续 fail-closed。
- `advance_deadline` 已接入四段 canonical plan。下注超时 fold 会派生 SeatUpdate，终局/当前轮完成会
  派生 BetCollection、RoundAdvance、WithoutShowdown/Showdown/ResetOnly Settlement，并由 restart
  verifier 重建后重验 tagged package 或 legacy component bundle。schema v15 已删除仅启动 timer 的
  状态分支，且 WAITING 不允许 deadline 推进隐式
  start-hand；shuffle/reconstruct/reveal timeout 等 lifecycle 分支仍主要依赖 canonical native replay
  与 plan/table digest；若要求这些分支在
  恶意 host 下也能由 STARK 独立执行验证，需要新增专门 lifecycle component，而不能把 inactive
  四段 header 当作 start-hand/shuffle 执行证明。
- production precompile 已新增 canonical `advance_deadline` selector，legacy `tick` 已从 fresh 与
  archive 解码面删除；专用 `auto_fold` 与普通 public `reset_for_next_hand` 已从 active selector 集移除。
  所有 retired source selector 均在 strict archive decoder fail-closed；`auto_fold`/普通 reset 的
  MethodKind、独立 AIR 与 orchestrator route 也已物理删除。proving service 现在也在进入 VM 前使用 active
  `CanonicalCommand` 集过滤请求，不能再绕过 precompile 直接调用 retired reset/tick/auto-fold。
- 普通玩家命令的 actor 已改为从 authenticated caller 和 canonical pre-state 唯一派生。
  legacy `seat_index` 与 join `player` 只做相等断言；L1/AIR prove-task 在反序列化和消费时
  也执行同一 lowering。canonical table 拒绝同一地址占用多个 seat，避免后续
  method batch 仍把 caller 与 seat 当成两份可错配事实。管理员 target seat 仍保留显式输入。
- proof-bearing Mental Poker command 也已改为 actor-less canonical payload；完整密码学 statement/proof
  不做摘要替代或删减，只有可由 authenticated caller 唯一恢复的 player/seat 字段被删除。
  reveal command 还删除了 caller 自报的 `assignment_indices`：每次必须覆盖该 seat 的全部 pending
  assignment，index 与 ciphertext statement 由 authenticated pre-state 按 canonical 顺序派生；
  token/proof 少交、多交或旧含索引 payload 均 fail-closed。
- 内部 `reset_for_next_hand` 的完整座位/资金重置语义由触发 settlement/normalize 的 canonical
  Stage plan 承担；hand stream 使用 tagged Stage proof，孤立 single-task archive 使用四段 component
  bundle，不再存在可单独提交的 reset method STARK。旧 `join_and_shuffle` / `leave_with_proof` package
  路由已删除：加入与 fresh-deck shuffle 分别由 `join_table`、`start_hand`、`submit_shuffle_v2`
  证明，WAITING 离场走 `leave_table`，active layer removal 走 `fold_with_proof`。
- `start_hand` 的零参数 ABI 在 L1 dispatch 边界拒绝任意尾随 bytes；退休 reset selector 则在参数
  解码前直接按 unknown method 拒绝。
- showdown settlement binding 现在要求唯一 `HandSettled` marker，且其 table、gross pot 和
  固定升序 winners 列表必须与 `WinnerAwarded` 聚合一致；`RakeCollected` 也必须按
  `gross_pot/rake/total_awards` 恰好出现一次或在零 rake 时完全缺失。截断、重复或错配的
  结算事件会在生成 component plan 前 fail-closed。
- consensus anchor 的 tx-root 是 order-independent SMT；某 table/hand 的完整有序调用范围仍
  依赖 `call_seq`、端点 snapshot 和 Bullshark projection 一致性。
- 当前没有 sound recursive/succinct aggregate proof；descriptor-only Aggregator 生产入口仍拒绝。
- `TexasPokerTable` resolved Borsh ABI 已破坏性升级为 v29，ObjectDb hot ABI 为 v30；runtime 与
  persisted seat 共用同一个 tagged union，reveal 使用无 `None` 的 typed purpose，missing-seat
  统一为 4-bit `0x0f`；owner-readable hole partial 使用固定 `(seat, slot)` ledger，showdown
  密文只能按 exact assignment target 取得。旧 flat-seat、numeric-reveal、`0xff` sentinel 和
  `decrypted_cards Vec` bytes 在 schema 检查处直接拒绝。
  当前明确不提供历史 production 数据迁移，部署升级必须重建 table state。
- 多 validator `CommitVote` 已接入 P2P 签名校验、按 signer 去重、2/3 quorum 收集、
  certificate 组装与成功提交后的清理；它不再属于“消息结构存在但未收集”的缺口。
- PEX 目前会校验、去重并传播发现地址，但尚无针对新地址的后台主动拨号、失败退避与
  peer 生命周期管理；VRF proposer gossip 和 background proof repair 也仍是节点/网络/运维
  缺口，不由当前 method AIR 修复覆盖。

## 结论

当前主线适合“不追求链上压缩”的目标：host-native crypto/Stwo 验证性能最高，digest 与
canonical context 防止 proof、receipt、table 或 call scope 被替换。它提供可信 host acceptance，
但不声称递归压缩；剩余产品功能缺口仍需后续独立设计。

## Tagged-union Stage proof 前的 Texas 源码重构

字段删除/合并、Seat bit/status、phase tagged union、`normalize_until_blocked`、tick/auto-fold
归一化和 heterogeneous method batch 的实施边界，见
`TEXAS_SOURCE_SLIMMING_AND_BATCH_DESIGN.md`（已删除，见 git 历史）。
