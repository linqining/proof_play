> ⚠️ **历史存档(2026-09-05 归档)**:双状态机改造方案已被 TODO(原 #20)Phase 2 取代——
> 常驻 mirror 整体删除,结算改为 prove_log 记录 + settle 时一次性重建
> (`texas/src/starknet/prove_log.rs` + `mirror::build_from_log`)。
> B4 Sepolia e2e 证据与生产 bug 复盘仍有史料价值。

# 牌局状态机统一改造清单

> 背景：当前存在**两套平行的德扑状态机**，一致性靠"事件转发 + 追赶补丁"维持，
> 是 Sepolia e2e 结算链路反复出 bug 的结构性根源。本文给出两阶段改造：
> 方案 B（过渡，小改动，先打通结算）与方案 A（目标架构，单一事实源）。
> 建议先做 B 立即解锁结算验证，再做 A 根治；B 的对拍工具直接被 A 复用。

---

## 实施状态（2026-08-31：方案A 已落地）

方案A 以**「终局 deck 注入」**形态实现（比 B1/B2 更彻底地满足"deck 同源"）：

- **VM 侧**（poker_l1）：
  - `PartialHoleCard` 新增 `full_ciphertext`，摊牌 reveal 改用完整密文验证
    （客户端证明绑定完整密文，challenge 含 c2；ledger 自包含，reconstruct 后仍可验证）；
  - `normalize_until_blocked` 由 mirror 开局调用（武装 deadline + 规范化推进）。
- **镜像侧**（texas/src/starknet/mirror.rs）：
  - 删除 `autonomous_initial_shuffle` / `set_deck` / `begin_hand` / `with_fresh_mirror`；
  - 新增 `begin_reveal_hand(deck, plan, button_rank, hand_id)`：按游戏座位升序
    重放 join → 提升 Waiting 座位 → 对齐 button → 注入终局 deck（逐字节）→
    `normalize_until_blocked` 直接进入 DealHole；
  - 新增 `pending_reveal_ciphertexts`（canonical 顺序目标密文）供 token 重排。
- **单点同步**（hooks.rs 重写 + betting.rs / seat_mgmt.rs / socket 接受点）：
  - reveal（`mirror_sync_reveal`，按 VM canonical 顺序重排 token）、
    betting（`mirror_betting`，所有 handle_* 成功点）、kick（`mirror_force_fold`）、
    开局（`mirror_begin_reveal`，advance_shuffle BeforePreflop 完成点 = deck 终局点）。
- **删除追赶补丁**：`mirror_fill_pending_reveals`、`mirror_autoplay_betting`、
  `PENDING_BETS`/replay、`with_fresh_mirror` 全部移除；game_loop tick 收缩为
  `mirror_advance_showdown_display` + 有界结算重试（重试是链上投递保障，不是状态同步）。
- **deck 同源的最后一环**：poker_protocol `new_plain_text` 的 DST 对齐 VM 的
  `generate_plaintext_cards`（`POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_`）——
  两侧规范明文域一致，注入 deck 才能通过 VM 的 canonical-match。
- **发牌顺序对齐**：`deal_preflop` 改为升序座位发牌（VM DealHole 规范），
  保证 deck index → 玩家映射与 VM 一致。
- **手牌/公共牌不限修复**：`MentalPokerGame::deal_to_player` 硬上限
  `cards_per_player`(2)、`deal_community_cards_encrypted` 截断到 `community_cards`(5)；
  客户端 `useCryptoOperations.ts` 对 HAND/COMMUNITY_REVEAL_RESULT 载荷分别做 2/5 上限。
- **结算上链**：`on_hand_complete` 在 ShowdownDisplay 同步打 pre_settlement 快照后
  构建 settlement；phase-2 用镜像快照（Clone）构建 dual，不再借用注册表；
  hand_id 以 unix 秒为种子的每桌单调计数（服务器重启后仍满足链上 hand_id 严格递增）。
  链上已核对：`settlement.is_prover(operator)=1`、`settlement.vault()=配置 vault`。
- **DAPV 上链 + 翻后抽水 + 跨手显示（2026-09-01 第二轮实证）**：
  - PokerDualSettlement 裁剪（移除 per-proof 验证器/BLS 变体/proved 路径，
    casm 81,175 → 23,816 felts）后 Sepolia 部署成功：
    `0x4d8e1f155aec13d43d3e7b1bce739412ddb8d3a85a51d3378db22f62bd88308`
    （class 0x44c425ff…，vault.settlement_contract 已重绑定）；
  - 服务器 `STARKNET_SETTLEMENT_MODE=dapv`：`register_hand` +
    `verify_and_settle_dapv_stark` 两笔 **ACCEPTED_ON_L2 / SUCCEEDED**
    （hand 1788186794，settle=0x2e9f165b…），链上 ρ 折叠校验通过；
  - 翻后抽水：争夺底池 5%（cap 1000 chips），翻前结束不抽（VM 硬性不变量
    `uncontested pot must not be raked`）；calldata 实测 bot +90 / user −90
    （treasury 抽水 10 已并入输家条目，零和成立）；
  - DAPV 认可链路：浏览器端修复 serde_wasm_bindgen Map 序列化兼容
    （endorsementClient `asPlainObject`）+ wasm pkg 同步（含 endorsement 导出）；
    dev_bot 认可私钥服务器托管、进程内铸造（`register_bot_endorsement_key`）；
  - 结算重投：PENDING_SETTLE 按桌保留构建时快照（settlement+binding+mirror 克隆），
    tick 重投同一快照，绝不读已被新手替换的 mirror 活状态；
  - 系统性阻塞修复：finish_showdown 在 state 写锁 + mirror 注册表锁内做证明
    （数十秒），阻塞 bot 与全部 WS 处理器 → on_hand_complete 改为锁内克隆、
    锁外重活；
  - 自动行动闸门：handle_auto_fold 增加 5 秒延迟（此前每 500ms tick 直接替
    当前行动者行动，整手牌数秒内被自动推完，客户端/mirror 全部相位错开）；
  - 跨手显示根因修复：reset() 初始牌组预置聚合层 (G, m+agg)——SHUFFLE_SUBMIT
    路径无 mask，shuffle-only 手牌的 deck = m + (s−1)·agg，token 和消不掉
    聚合层导致第二手起全部无法解密；预置后恒等式 m + s·agg 成立
    （离线对拍 `rejoin_after_kick_materializes` 复现并验证修复）。
- **B4 Sepolia 端到端实证（2026-09-01）**：真实浏览器买入（Cartridge 钱包
  `0x6e37…c782`，deposit tx `0x6f6dd876…`）+ dev_bot（`0xba7f00d`）双人整手到摊牌，
  `register_aggregate` 与 `settle_hand` 两笔交易 **ACCEPTED_ON_L2 / SUCCEEDED**
  （settle=`0x36aaf8241792…`，手 1788170046），`hand_settled=1`；
  settle calldata deltas ±100 chips = ±1e16 wei，`vault.chip_balance` 变化与
  净胜额精确一致（bot 1000→1100，user −100）。实跑中修复的三个生产 bug：
  1. 发牌顺序错位——游戏层轮转发牌 vs VM 每座连发 2 张，deck index → 玩家映射
     不一致（`deal_preflop` 改为升序座位每座连发 2 张，与 VM DealHole canonical 序一致）；
  2. 单挑 postflop 行动顺序——VM 让 button(SB) 先行动，真实规则为 BB 先
     （VM `start_betting_round` 对齐 button 之后第一个座位）；
  3. 结算单位/时序——vault 以 wei 记账而 calldata 用 chips（差 1e14），
     digest+calldata 统一放大为 wei；register 与 settle 的包含时差导致
     "Aggregate not registered"、register 幂等错误被误判为已结算——
     `submit_settlement` 改为 register → 轮询注册可见 → settle，
     错误分类拆分（register 重放放行、仅 "Hand already settled" 视为完成）。
- **验收（对拍测试全绿）**：`texas/src/starknet/e2e_tests.rs` 重写为注入流——
  游戏层客户端真实 join_game_and_shuffle → 发底牌 → 注入 → 断言 deck 逐字节一致 →
  DealHole/Board/ShowdownOwner 全窗口客户端 token 验证 → 下注到 river(board=5) →
  settle calldata + DAPV dual。`cargo test -p texas e2e_starknet` 2/2 通过。

---

## 0. 现状（已核实的代码事实）

### 两套状态机

| | 权威游戏层 | mirror |
|---|---|---|
| 位置 | `texas/src/pokergame/table/` | `texas/src/starknet/mirror.rs`（包 `poker_l1` 的 `TexasPokerTable` VM） |
| 职责 | 驱动 WS 广播、前端可见牌局 | 收集 `ProveTask` 供 AIR 证明与结算 calldata |
| deck 来源 | 前端真实洗牌链（`mental_poker_game` 逐个验证 ShuffleRound） | **自治初始洗牌**（`autonomous_initial_shuffle`，mirror.rs:288） |

- mirror.rs:1-10 注释自述"从动副本：权威状态仍由 pokergame/ 维护"。
- hooks.rs:386-390 注释明确承认 deck 分叉：zgame 客户端 `join_and_shuffle` 与
  poker_l1 `join_table + submit_shuffle_v2` 洗牌语义不同，"deck 链无法逐字节同步，
  因此 mirror 走自治链"。
- **关键**：注入真实 deck 的管道其实已存在——`mirror.start_hand(deck, …)`（mirror.rs:123）
  与 `set_deck`（mirror.rs:178）都接受外部 deck，只是 `mirror_begin_hand`
  （hooks.rs:406）选择了自治洗牌路线。

### 本会话为维持同步加的全部补丁（改造后应删除）

| 补丁 | 位置 | 性质 |
|---|---|---|
| `mirror_fill_pending_reveals` | hooks.rs | 服务端用钱包派生 sk 代算 mirror 层 reveal 份额（**airness 缺口**） |
| `mirror_autoplay_betting` | hooks.rs | 服务端代打 mirror 下注轮 |
| `mirror_replay_buffered_bets` + `PENDING_BETS` | hooks.rs | 下注动作缓冲重放 |
| `with_fresh_mirror` 复位自愈 | mirror.rs | 卡死时整块丢弃重建 |
| `SETTLE_OK` / `SETTLE_ATTEMPTS` / `retry_pending_settlement` | hooks.rs + game_loop tick | 结算失败重试 |

这些补丁的共同模式：**游戏层事件到达时 mirror 还没就绪 → 缓冲/代算/重试**。
补丁数量随事件类型线性增长，这正是双写架构的固有成本。

### poker_l1 VM 已具备的命令面（dispatch.rs:80-190）

`create_table / join_table / leave_table / start_hand / advance_deadline /
force_fold / kick_player_v2 / submit_player_reveal_tokens /
submit_reconstruct_deck / fold / check / call / raise / bet / addon / rebuy /
set_leave_after_hand / fold_with_proof`

覆盖完整，具备成为唯一状态机的表面能力。

---

## 方案 B（过渡）：同 deck 重放，收敛同步面

**核心思想**：砍掉自治洗牌，把游戏层**已验证**的同一批密文与证明喂给 mirror，
使两条 deck 链逐字节一致。一致后：

- 玩家的 reveal token 对 mirror deck 直接有效 → 删除 `mirror_fill_pending_reveals`
  （服务端代算份额的 airness 缺口随之消失）；
- 下注状态机同步推进 → 删除 autoplay/缓冲重放；
- mirror 不再卡死 → 删除 fresh-reset 与结算重试。

### B0：对拍测试基建（keystone，先于一切改动）

- [ ] 录制一场完整双人手牌的 WS 流量（SIT_DOWN_V2 / SHUFFLE_SUBMIT /
      REVEAL_SUBMIT / 动作序列），落为 fixture（JSON）。
- [ ] 写 `texas/tests/mirror_parity.rs`：fixture 重放到 `TableMirror`，
      每个事件后断言：
  - deck 逐 felt 相等（52 张密文 c1/c2 逐字节）；
  - board 张数、每座位 bet/total_bet/stack、round_state 与 fixture 中的
    游戏层快照一致。
- [ ] **验收**：当前代码跑该测试必然失败（自治 deck）——失败输出即改造前基线。

### B1：真实 deck 注入 + join 顺序重放

- [ ] `mirror_begin_hand`（hooks.rs）改为 `mirror.start_hand(游戏层验证后的
      deck, pending_mask, contributor_mask)`，删除 `autonomous_initial_shuffle`
      调用（函数本体与 mirror.rs:286 一并删除）。
- [ ] join 缓冲去重：`mirror_buffer_join_pk` / `mirror_buffer_join_raw`
      （socket/mod.rs:661、dev_bot.rs:129）按 addr **替换**而非追加，
      消除 "pk already registered"。
- [ ] join 按客户端实际入座顺序重放（poker_l1 的聚合 pk 派生对顺序敏感）。
- [ ] **验收**：B0 对拍测试的 deck 断言转绿。

已知风险：`submit_shuffle_v2` 对客户端 ShuffleRound 的验证若因聚合 pk 推导
差异失败，在 B1 内修 mirror 的 join 重放顺序，**不改证明格式**。

### B2：验证动作的单点同步派发

- [ ] 把 mirror 派发移进游戏层**接受动作的同一代码路径**（同一把锁内）：
  - `submit_verified_shuffle_for_pk`（socket/mod.rs:725）成功 → 同步调
    `mirror.submit_shuffle(output_cards, proof)`；
  - `submit_reveal_tokens_for_pk`（socket/mod.rs:770）成功 → 同步调
    `mirror_sync_reveal`（客户端 token 直接可用，无需 fill）；
  - `handle_fold/check/call/raise` 接受点 → 同步派发对应 selector。
- [ ] 删除事后 hooks 调用点（handlers.rs 中散落的 mirror_* 调用合并到上述单点）。
- [ ] **验收**：对拍测试全绿；grep 确认 `mirror_fill_pending_reveals` /
  `mirror_autoplay_betting` / `mirror_replay_buffered_bets` 无调用方。

### B3：删除追赶机制

- [ ] 删 `mirror_fill_pending_reveals`、`mirror_autoplay_betting`、
      `PENDING_BETS` 队列、`with_fresh_mirror`、
      `SETTLE_OK/SETTLE_ATTEMPTS/retry_pending_settlement`。
- [ ] game_loop tick 里的 mirror 驱动块（game_loop.rs）收缩为仅
      `mirror_advance_deadline`（超时语义仍需服务端 tick）。
- [ ] **验收**：`cargo build` 无引用残留；对拍测试仍全绿。

### B4：结算上链端到端

- [ ] 一手完整打到 showdown → `on_hand_complete` → `derive_settlement_plan`
      （board=5 断言应自然满足）→ `register_aggregate` + `settle_hand` 上链。
- [ ] **验收（硬性）**：
  - Sepolia 上出现两笔 ACCEPTED 交易（register + settle）；
  - `vault.chip_balance(赢家)` 链上变化 = 本手净胜额（snops 链上核对）；
  - 浏览器手牌/公共牌正常显示（`HAND_REVEAL_RESULT` / `COMMUNITY_REVEAL_RESULT`
    到达路径未被本次改动破坏）。

---

## 方案 A（目标架构）：poker_l1 VM 成为唯一状态机

**核心思想**：反转主从。`TexasPokerTable` VM 是唯一演进状态的实现；
`pokergame/table/` 降级为**投影层**（序列化 DTO + WS payload 映射），
mirror 概念消失（`DispatchOutput.prove_task` 天然产出证明任务）。

### A0：能力差集审计

- [ ] 逐特性比对 `pokergame/table/` 与 VM：盲注 posting、行动轮转、边池
      （`poker_l1/…/settlement.rs` 的 side-pot 逻辑）、摊牌比牌、超时/踢人、
      rebuy/addon、WS payload 所需全部字段。
- [ ] 产出差集表：VM 缺什么（预估：WS DTO 映射、若干糖方法）。

### A1：VM 服务化封装

- [ ] 写 `texas/src/pokergame/vm_table.rs`：实现游戏层现有公开 API
  （socket 层的调用面：`start_shuffle` / `submit_player_reveal_tokens` /
  `handle_fold/check/call/raise` / `advance_deadline` …），
  内部 dispatch 到 VM，返回值映射为现有 `Table` DTO。
- [ ] 前端 WS payload 形状**零变化**（客户端不动）。

### A2：影子模式对拍（复用 B0 工具）

- [ ] 双实现并行跑真实流量，每个事件后断言状态一致；
- [ ] 不一致即修映射层，直到连续 N 手零分歧。

### A3：切换权威

- [ ] socket 层改读 VM 状态出 WS 广播；
- [ ] 删除 `pokergame/table/` 的自有状态字段与迁移逻辑（保留 DTO 结构体）；
- [ ] 删除 mirror.rs 整个文件与 starknet/hooks.rs 的全部同步函数。

### A4：结算链路收口

- [ ] `on_hand_complete` 直接从 VM 的 prove_task 链构建 calldata；
- [ ] DUAL_PROOF_PROTOCOL §5.3 标注的"客户端协议对齐"在此架构下自动满足
  （deck 同源 = 玩家实际参与的那副）。

---

## 执行顺序建议

1. **先 B**（B0→B4，预计一个工作包）：解锁 Sepolia 结算端到端验证，
   同时消灭服务端代算份额的 airness 缺口。
2. **后 A**（独立排期）：B 的对拍 harness 是 A2 的现成工具，B 删掉的补丁
   在 A 下也不会复活（同步面已收敛为单点）。

## 禁止事项（防止回到老路）

- ❌ 不再新增任何"事后追赶"型同步补丁（fill/replay/retry 家族）；
- ❌ 不在 mirror 与游戏层之间引入第二套密文派生（deck 必须同源）；
- ❌ 不为绕过验证失败而放宽 VM 的证明校验（修 join 顺序，不修验证器）。

## 涉及文件速查

| 文件 | 改动 |
|---|---|
| `texas/src/starknet/mirror.rs` | B1 删自治洗牌；B3 删 with_fresh_mirror；A3 整体删除 |
| `texas/src/starknet/hooks.rs` | B2 收敛为单点派发；B3 删 fill/autoplay/replay/retry |
| `texas/src/socket/mod.rs` | B2 派发并入接受路径；join 去重 |
| `texas/src/socket/game_loop.rs` | B3 tick 收缩；A3 改读 VM |
| `texas/src/pokergame/table/` | A0/A1/A3 降级为投影 |
| `texas/tests/mirror_parity.rs` | B0 新建（A2 复用） |
