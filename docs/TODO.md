# TODO

> 重梳日期：2026-09-05（全项目文档审核后整体重写）。上一版（2026-09-03 盘点）
> 的逐项详细完成记录见 git 历史（文档清理 commit 之前的 TODO.md）；已完成项
> 在文末压缩归档。编号与历史保持连续（其他文档仍引用 #N）。
> 排序原则：功能开发优先，主网相关放最后。

---

## 〇、文档地图（2026-09-05 审核后的现行权威）

| 文档 | 角色 |
| --- | --- |
| `README.md` / `README.zh-CN.md` | 项目入口、信任模型、Roadmap |
| `docs/README.md` | 文档地图（现状 / 设计 / 运维分类） |
| `docs/design/DUAL_PROOF_PROTOCOL.md` | 结算目标架构（v2.9 头注对齐 Plan D / #18 Phase B；英文 TL;DR 在头部） |
| `docs/design/SETTLEMENT_PRIVACY_PLAN.md` | 结算隐私 P2 权威方案（digest 公式已按 #18 Phase B 更新） |
| `docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` | 抗审查唯一设计文档（主体已实施，状态见头注；§8.2 仍为主网门槛规格） |
| `docs/design/TEXAS_TAGGED_AIR.md` | tagged/canonical AIR 能力边界（29 selectors） |
| `docs/design/SNIP36_INTEGRATION.md` | SNIP-36 唯一设计文档（dual v5 双门已上主网） |
| `docs/SOUNDNESS.md` | 健全性最终状态（Lean / DAPV / AIR 三支柱；合并原 DAPV_SOUNDNESS 与 SOUNDNESS_FIXES） |
| `docs/PERFORMANCE.md` | 性能最终记录（release 基线 + 生产流水线 + 主网 gas 校准 + 已裁决非目标） |
| `docs/STATUS.md` | **canonical AIR 覆盖/缺口权威表述源**（2026-09-05 按现状重写） |
| `docs/MAINNET_TX_GUIDE.md` | #28 主网交易唯一操作指引 |
| `poker_contracts/DEPLOYMENTS.md` | 合约部署地址/接线权威账本 |

**历史存档**（`docs/archive/`，均已加头注，仅史料价值）：
`HOST_ZERO_RISTRETTO_AIR`（Ristretto 宪章，路线已关闭）、`PERFORMANCE_REPORT`、
`PERFORMANCE_V2_PROTOCOL`（旧世界性能，被 docs/PERFORMANCE.md 取代）、
`TRUST_MODEL_NO_TRANSACTION_REPLAY`（链交易重放模型已废）、
`EXECUTION_PLAN`（迁移蓝图已执行完）、`MIRROR_UNIFICATION_PLAN`（被 #20 Phase 2
取代）、`PO5_PO6_DESIGN_NOTES`（VM 架构快照）。已删除的过程文档
（plan_d_perf / plan-d-p3-metrics / PERFORMANCE_FOLLOWUPS / plan-b/c/d /
poseidon / snip36-execution / MIGRATION / deadlock-review / RFP 对齐等）
在 git 历史。

---

## 一、立即行动（P0）

- [x] **34. dual v3.x 合约重部署 + 服务端切换（2026-09-05 完成）**
  - ✅ 部署：Dual v3.x `0x55784c90...`（class `0x6db1ea08...`）、新 claim helper
    `0x60a4c474...`（class `0x5c28571f...`，3 参构造 vault/pool/settlement——
    发现旧在网 class `0x5ec1...` 是无 settlement 绑定的 2 参旧版，一并修复）。
  - ✅ 接线（全部 SUCCEEDED）：`set_claim_helper` → `set_circuit_program_hash(
    0x25d81d2c...)`（新电路）→ vault v3 `set_settlement_contract(新 dual)`
    （切换点）。冒烟：`register_hand` 新 7 参 ABI 上链成功，
    `hand_action_log` 读回动作日志承诺 ✓（TX `0x4f0788df...`）。
  - ✅ 账本：`texas/.env`（dual + claim helper）、`DEPLOYMENTS.md`、
    `strk20.json` 已回填；旧 dual/旧 helper 保留服务历史认领。当前无运行中
    服务进程，下次启动即用新 ABI。
  - ✅ **链上真实结算冒烟（2026-09-05）**：真实证明链 + 认可批次的
    register（`0x28ab0dc7...`）+ settle（`0x1215cde0...`，SUCCEEDED）；
    **gas 实测（2 人合成手）：l2_gas 4,313,040 + l1_data_gas 288**。冒烟
    测试：`sepolia_settle_smoke`（`STARKNET_SEPOLIA_SMOKE=1` 触发）。

- [x] **33（剩余）. 在局锁定应用内 e2e（2026-09-11 完成，用户实机联调）**
  入座触发服务端自动 lock → 游戏中领取弹窗显示在局锁定 → 打完一手结算
  续钟 → 离桌 TTL 解锁。链上强制已实测（2026-09-04 冒烟通过：lock→精确
  回滚→force_unlock），实机应用内链路用户确认走通。

- [x] **35. #33 离桌快解锁 + 结算原子锁账（2026-09-07 完成，生产多场验证）**

  **漏洞闭环史**（每个都线上实锤后修复）：
  1. 结算链路整体失效：legacy PokerSettlement 是 8-31 旧 4 参 ABI（#18
     Phase B 只改源码未重部署）且绑定旧 vault v2 → param #3 反序列化必拒；
     vault v3 的 settlement_contract 从未指向 v4/v5。修复：vault 重指 dual
     v5（TX `0x6e80a2bc...`）+ 回退腿改 dual 线性结算（`submit_dual_fallback`）。
  2. 逃单窗口（用户发现）：`apply_settlement` 正向 delta 不加锁，赢额从
     结算落地起永远可提，提走后下一手结算 `Insufficient chip balance` 必
     revert 且拖垮全手（含赢家）。修复：结算 bundle 原子串入 `lock(赢家)`。
  3. 空批次假失败：动作无签名时 materials 为空 → handbatch 零方程
     `Truncated`。修复：hooks 真实跳过 + 语义回归测试钉死。

  **终态模型（零合约改动，operator = vault owner = 结算 prover）**：
  每手结算 = 单笔 `__execute__` 原子 bundle：`register_hand → settle →
  lock(赢额) → refresh_session(有 session 者) → force_unlock(本手离桌者)`——
  任一子调用 revert 整笔回滚，"结算落地→回锁落地"的异步窗口在根上不存在。
  离桌释放五路径全闭环：①牌局未开始离开→已结算即释；②手尾离桌→搭 bundle
  原子释放；③bundle 启动后才注册离桌（0.1s 竞态，线上实锤
  departed-released=0）→ bundle 后兜底 flush（独立交易补放）；
  ④nonce 竞争（线上实锤 NonceTooOld 丢释放）→ `invoke_vault` 统一入口
  3 次退避重试；⑤中止手（refund_all_bets 六调用点）/结算构建失败手（board-0
  线上实锤）→ abort_flush 钩子（这类手永不 settle，不 flush 则滞留到 TTL）。
  在座不变式：`locked == chips`（入座锁全额、赢额回锁、输额扣锁），在座
  可提差额恒为 0。

  **已知边界**：释放权威在服务端内存簿记（重启丢挂起 → TTL 自助解锁兜底
  `unlock_after_deadline`）；多手并发时 `hand_id ==` 精确匹配是序依赖的
  （正确版应为"该玩家 ≤ 最后一手的未结算手集合为空"，单桌串行下窗口未
  打开）；释放/锁生命周期整体在证明体系之外——终态应把"玩家 P 离桌、
  最后一手 H"做成 leave receipt 进 settlement digest（P 层 KIND_LEAVE 基础
  设施已在），随 P4 证明化结算一起做，现在做是给弱门上强锁（operator 在
  线性路径本可伪造零和 deltas）。

- [x] **36. SHUFFLE_NOTICE 双通道重复推送修复（2026-09-07 完成）**

  线上实锤：同一次洗牌状态经 TableEvent 消费者与 game_loop/handlers 直接
  调用两条路径**同毫秒双发**（23:06:57.690709/.690720）→ 客户端双重
  SHUFFLE_SUBMIT（第二次被 `Shuffle not active` 拒绝，全会话 145 次幂等
  拒绝），zk 面板误报"proof verification failed"。修复：服务端
  `send_shuffle_notice` 出口按桌签名去重（签名 = 当前洗牌者 + deck 长度 +
  首张密牌 c1，250ms 窗口，状态真变必改签名不误杀）；客户端 SHUFFLE_NOTICE
  同签名去重（纵深防御）；zk 面板事件文案区分 `rejected (state)`（状态机
  拒绝：重复/迟到/非当前洗牌者）与 `proof verification failed`（真密码学
  失败）。顺带发现客户端 ShuffleState 类型 `deck_encrypted: string[][]` 是
  陈旧声明（wire 实际 `{c1_hex,c2_hex}`）。待观察：22:23 物化失败 /
  board-0 手牌损坏与双推同族，去重后若仍出现需深挖重构管线。

- [x] **37. 私密领取守恒修复（2026-09-07 完成，用户实测通过）**

  漏洞（比赛 STRK20 主径，用户报告"池内余额不足 3.0 < 5.75"）：anonymizer
  `OP_WITHDRAW` 用 `burn_chips`（无代币移动）+ 要求用户先用池内余额自筹
  注资——每领 X 销毁 X 价值（chips 烧掉、vault 背书 STRK 滞留无人可领、
  输出 note 全额来自用户自己的钱），且把"池内屏蔽余额 ≥ 领取额"错立为
  硬前置。修复：`OP_WITHDRAW` 改 `vault.withdraw_to`（烧筹码 + vault 释放
  背书 STRK 给 helper，输出 note 由 vault 出资）——零池内预存要求，chips
  −X / note +X 分文不丢。新 anonymizer `0x7ee059dd...3ad9dd`（class
  `0x525646bd...`），vault `set_unshield_helper` 重指（TX `0x18fbf4fa...`），
  snforge 91/91（withdraw 三负例改守恒语义）；前端删自筹 withdraw 桥 +
  屏蔽余额前置检查，`.env` 已切新地址。Pool viewing key 注册不受影响
  （note 归属识别的前提，注册 = 拥有收 note 的池身份，一次性 0.01 shield）。
  修复后池内余额会真实增加领取额（vault 出资新 note 归用户）。

- [ ] **38（设计待办）. 释放权威的证明化与序无关化（#35 已知边界的终态）**

  **背景**（2026-09-07 设计评审，用户两问）：①释放（abort_flush 等）该不该
  受 AIR 约束；②多手结算顺序是否影响释放结果。

  **① AIR 绑定**：当前释放决策全在服务端内存簿记（pending 注册表 +
  settle_ok + 中止钩子），链上门禁只有 `assert_only_owner`。恶意 operator
  场景下绑 AIR 无意义——线性结算路径本身是 operator 信任的（p_batch 为
  操作员自铸方程、合约只验形状、Stwo 验证在链下 host），operator 今天已可
  伪造零和 deltas 任意挪筹码，弱门后上强锁是不一致的安全。真实威胁是
  "诚实 operator + bug 过早释放"（第三方伤害：被释放者提走筹码 → 旧手
  apply_settlement revert → 赢家受损）。**终态设计**：把"玩家 P 在状态 S
  离桌、最后一手 H"做成 leave receipt 进 settlement digest（P 层
  KIND_LEAVE 一等语句基础设施已在），合约释放入口对该承诺做与
  apply_settlement 同级验证——释放与结算同管线，天然搭结算 bundle。
  时机：P4 证明化结算激活之后。

  **② 顺序敏感**：两个独立点。a) `apply_settlement` 对输额断言
  `chips ≥ amount`——deltas 可交换、断言不可交换（余额 4，手 A 输 5、
  手 B 赢 3：B 先落 ✓ / A 先落必 revert）；单桌串行自然保序，多桌玩家/
  重试队列/nonce 竞争重发会打开倒序窗口。b) 释放条件 `hand_id ==` 精确
  匹配是序依赖的，正确版本是序无关的"该玩家所有 ≤ 最后一手的未结算手
  都已结算"。**修方向**：每玩家记未结算手集合（结算/中止时移除，集合空
  且已离桌才释放），或按玩家/桌串行化结算提交（顺带解决 a）。
  当前未炸的原因：单桌 + snip36 一次性提交（失败即弃、无迟到落地）。

  **一句话**：释放的正确性目前靠事件顺序的巧合而非不变式——短期序无关
  条件加固，长期随 P4 进证明体系。

- [ ] **39. 待查：牌桌完整性（22:23 物化失败 + hand 1788734417 board-0）**

  **2026-09-11**：人工核查已执行（用户确认）；**结论（双推去重后是否
  复现 → 结案 or 深挖重构管线）待用户回填本条后勾选**。另注：#49 的
  reconstruct 游标重置已消除"重建后旧纪元游标错位"一类位置语义缺口；
  重洗死槽随机化的协议级缺口仍属本条深挖范围。

  两起手牌损坏（摊牌物化 FAILED tokens=3 / derive_settlement_plan
  board 5 张得 0 张）疑与 SHUFFLE_NOTICE 双推同族（重复触发在重构/reveal
  路径同样存在，reveal 幂等门挡住了但重构管线未知）。#36 去重上线后
  观察是否复现：不复现 = 双推是根因，结案；复现 = 深挖 reconstruct/
  deal 竞态。fail-fast 安全网（退款中止/结算拒绝）两起都正确兜底，
  无资金影响，但手会白打。
  同批待查：客户端动作签名仍缺席（`no signed actions` 持续 → snip36
  证明主腿未激活；结算由 bundle 保底不受影响），需浏览器现场单步
  getPlayerKeys/wasm sign_action 链路。

## 二、功能开发（P1）

- [x] **18（Phase C）. 电路内"合法默认"约束（主网上线门槛）——完成（2026-09-05）**
  **✅ 切片 1**：动作日志哈希链 keccak→Poseidon——游戏层 `action_log_digest_felt`
  改 Poseidon sponge；电路增加词条区用 poseidon_builtin 重放整链并断言链根
  == settlement digest 中的动作日志哈希；program hash 已上链。
  **✅ 切片 2（同日）**："合法默认"约束本体——`ActionLogEntry` 扩展下注语境
  （owed/my_bet/big_blind，`record_action` 单一收口点从桌状态派生，与
  `handle_auto_fold` 逐字段同源）；词条布局 2 词 × 30 槽（日志打包词 +
  合法性词 `kind(2)|owed(64)@2|my_bet(64)@66|big_blind(64)@130`，总参数
  98/100）；电路解包日志词做 action 白名单（FOLD/CHECK/CALL/RAISE）+
  flags 拆位，对 auto 词条强制 `legal_auto_action` 规则（零下注⇒Check、
  差额≤大盲⇒Call、差额>大盲⇒Fold，Raise/非法 kind 拒绝），非 auto 词条
  合法性词 canonical 0。验证：prove-settlement e2e 全通 + **非法默认负例**
  （auto FOLD 谎称 Check → 电路中止 ✓）——§8.2 主网门槛条款达成；
  新 program hash `0x744d16d3...` 已上链（TX `0x55f9297b...`）并视图验证 ✓。
  回归：根 crate 电路 11/11、texas starknet 快速集 35/35、auto_action 5/5。
  说明：accepted-seq 单调约束（`accepted_seq_digest` 槽）仍保留为零，作为
  Phase C 后续可选加固（当前 seq 校验在服务端 + 收据举证）。

- [x] **19. 实施前确认 4 个开放问题**（2026-09-05 定稿，决策全文 =
  `docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §9）：① seq = per-table 单调、
  跨手不重置（与现行实现一致，重置窗口即重放窗口）；② 电路内验签否决——
  现管线无 keccak/EC builtin，电路只约束日志哈希吸收 + "合法默认"规则，
  完整验签归上链验证路线（#22/M3）；③ replayer 最小数据集 =
  HandProofLog ∪ 本手动作日志窗口（收据为客户端可选补强）；④ 双通道 =
  客户端多 RPC failover + 服务器端点列表化（不引入信任），争议终局走链上
  证据（#31）。附 Phase C 实施要点：动作日志哈希链 keccak→Poseidon 切换。
- [ ] **22. canonical AIR 缺口收口**（权威表述 = `docs/STATUS.md`，2026-09-05
  重写）：
  ① ~~全残差批次 sepolia 单笔 settle gas 实测~~ **已完成（2026-09-05）**：
  2 人合成手全残差批次单笔 settle 实测 l2_gas 4,313,040 + l1_data_gas 288
  （sepolia TX `0x1215cde0...`；9 人真实手待实机联调细化，见三）；
  ② **ShuffleComplete 已组合（2026-09-05）**：`CanonicalProtocolCompletionKind`
  增 `Shuffle`，opening 校验（`validate_shuffle_completion_opening`）+ AIR
  组合约束（phase Shuffling→Revealing、subtag/street 不变、turn=NO_SEAT、
  reveal pending=活跃集、deck 轮转锚定 pre/post 端点、deadline=ts+
  reveal_timeout、hole 游标 0→2N），直接验证器对完成 opening 的 host 校验
  全部生效；完成单元布尔化 + 度数回归 3 ✓（canonical 145/145 含 4 个篡改
  负例）。**RevealComplete 已完成（2026-09-11）**：盲注/规则 opening
  通道（复用 rules-opening 同一语句鉴权完整 `TableRules`：
  `CanonicalBlindOpening` + `blind_opening_of` + 校验扩展）；host 关系
  （`CompletionKind::Reveal = 3` + opening 扩展 +
  `validate_reveal_completion_opening`：镜像 `post_blinds` +
  `start_betting_round(is_preflop)`，支持形状 = 参与者全 Active/无封顶
  盲注/ANTE_MODE_NONE/正常下注开局，越界独立错误 fail-closed）；AIR
  组合（~166 追加 advice 列 + 度数 1 线性化 gate + 模 9 first-Active
  位置扫描 + 公开 blind scope 预处理列 + limb4 盲注扣款 + 计数/单挑
  逆元）端到端 prove/verify 贯通，heads-up 与三人局正例、归档脱钩与
  逐列篡改负例全绿；准入门（`crypto_admitted`/`validate_direct_batch`）
  已对 SubmitReveal 放行。详见 STATUS.md 实施进展条目；
  **ShuffleComplete 端到端修复（2026-09-10，整手牌性能扫描中发现）**：
  ② 组合时该分支从未被 prove 过（既有测试仅 host 侧 validate），AIR/
  生成器存在 4 处自相矛盾，修复后首次 prove/verify 通过——
  (a) AIR subtag 约束笔误：完成行被强制 `post_subtag=0`，与文档语义
  及 host 校验"活跃相位 subtag 非零"矛盾 → 改为绝对钉死
  `post_subtag - 1`（镜像 host 的 pre/post subtag==1，只允许从收集
  子标签完成；复核时从相对传播收紧为绝对钉死）；
  (b) 逐位 pending 演化未排除 shuffle 完成行：提交者位被要求清零，又
  同时要求 post pending = 活跃集，恒矛盾 → `non_final_protocol_submit`
  同步排除两类完成行；
  (c) 完成 opening 实值建议（时间戳/游标/掩码/承诺锚/inverse/进位）的
  清零门只排除 reconstruct，shuffle 完成行建议被强制归零 → 新增
  `non_completion_advice` 门；时间戳位分解仅 reconstruct 使用，生成器
  对 shuffle 完成行同步写 0；
  (d) `protocol_pending_post_inv` 生成器只排除 reconstruct，shuffle
  完成行写非零 inverse 与 AIR 归零矛盾 → 同步排除。
  新增 `canonical_full_hand_proof_perf_sweep`（#[ignore]）：整手牌
  主链 11 转移 3 batch + 辅助 reset 段 1 转移，端到端（含完成行）
  prove 1.69s / verify 1.23s / 4.29 MB（release，log2=8 域）。
  ③ ~~终端级联批量证明~~ **复核除名（2026-09-05）**：验收批量已存在并通过
  （award/reset/raked 三套级联批量测试 + schedule 篡改负例）；
  ④ **reconstruction 提交解除 fail-closed —— 完成（与 ShuffleComplete 同批）**：
  `validate_direct_batch` 对 SubmitShuffle/SubmitReconstruct 放行
  （SubmitReveal/FoldWithProof 维持拒绝）；协议行全字段冻结集进 AIR
  （turn=NO_SEAT 双端、current_bet/min_raise/pot/chip_pool、acted/leave
  掩码、hand_id、timeout 配置、board/rit 承诺、9 座位全像、shuffle 行的
  reveal/reconstruction 不变——全部 gate 在度数 1 的 is_protocol_submit）；
  测试：4 组 prove/verify 正例 + 篡改负例，canonical 147/147、全量 367/367 ✓；
  残留信任：deck/reconstruction 承诺**轮转**绑定 = native/链上 EC_OP 通道
  （Plan D ④）；⑤ state-root 重算（区别于绑定）进 AIR——**v2 组件分解已落地
  （2026-09-05，`poseidon252_v2`，e2e 2.91s + 负例全拒）**；**字节 scope
  组合完成（2026-09-06）**：验证路径零宿主 Poseidon 重算（公开预处理树
  根等值 + anchor FS 绑定/常量钉住 + void 见证化），`name_commitment_v2`
  封装对齐 `table_name_commitment` 契约。~~剩：create_table AIR 消费侧
  切换~~ **✅ 完成（2026-09-11，方法归档结构改动一并落地）**：
  `ArchivedMethodProof` v3→v4 新增 `name_commitment_v2_bytes` 附件
  （create_table 专用，其余 method 恒空；v3 归档 fail-closed）；
  `CreateTableAir` 新增公开输入 `name_commitment: [M31; 4]`，约束 10
  期望值改取 `poseidon252_v2::name_commitment_anchor_limbs`（fail-closed
  验证 v2 归档 + spec 绑定公开 name 字节 + catch_unwind 防畸形证明
  panic）——验证路径零宿主 Poseidon；证明侧现证附件随方法归档出证，
  重启/重验路径从归档解码并复验（orchestrator 慢速门槛 34 全过：
  真实出证 → 归档 → 重启重验 → 篡改/错名拒绝）。锚点等价
  （`claimed_anchor[0] == table_name_commitment(name)`）ignore 测试通过。
- [ ] **5（遗留）. `set_authorized_helper` owner 单点**：冷存储 / 时间锁
  （运维动作，随下一轮合约运维窗口）。
- [ ] **24⑤. 错误分类**：error.rs 字符串→稳定类别（低优持续项，外部输入
  边界先行）。其余 ①-④⑥ 的处置结论落在 `docs/PERFORMANCE.md`「已裁决的
  非目标」节（2026-09-05）。
- [x] **40. 结算/摊牌 AIR 前置：trace 友好改造（完成 2026-09-11，
  ①②③④ 全部落地 + 回归全绿）**：
  ✅ ① `side_pot::calculate_side_pots` 消除 `levels.sort_unstable()`——
  all-in 水位改 O(n²) 两两比较求秩（同额按座位号破平，秩单射）按秩落入
  固定 9 槽，槽序即升序；切片公式
  `amount_j = Σ_i max(0, min(bet_i, level_j) − level_{j−1})` 不变，eligible
  逐座位谓词化——无排序网络/lookup。`SidePotResult` 同步定宽化：
  `pots: [SidePot; 9]` + `pot_count`，空槽 canonical 全零，输出定宽可直接
  排 AIR 列。panic 路径清理：`push_or_merge` 的 `last_mut().expect`
  改固定数组直接索引（`record_layer`），层数上界论证入档。**语义等价**：
  20,000 例确定性伪随机差分 vs 旧排序算法逐字节一致（`matches_reference_
  sort_implementation`）+ 9 座满宽/降序水位/退化全零边界测试。
  ✅ ② `SettlementPlan.pots: Vec<SettlementPotPlan>` →
  `[SettlementPotPlan; SETTLEMENT_SEATS]` + `pot_count`——最后一处变长
  消除。版本戳迁移：`SETTLEMENT_PLAN_VERSION 2→3`、digest 域
  `.v2→.v3`；`RunoutPotPlan`/`SettlementPotPlan` 加 `Copy` + pub
  `inactive()`；自定义 `BorshDeserialize` 强制空槽 canonical 全零
  （非零载荷 fail-closed）+ round-trip/篡改负例测试。v2 及更早编码
  fail-closed 拒绝（方法归档 v4 同理，见 #49 #22⑤）。
  ✅ ③ `evaluate_five` 消除两处 `sort_unstable_by`：5 张 ranks 改固定
  邻接交换网络（10 比较器）；groups 改 13 槽直方图直接映入 16 槽
  (count,rank) + Batcher odd-even mergesort 定宽网络（63 比较器，降序，
  零计数组天然沉底）——控制流与牌值无关，AIR 端全可展开。网络正确性：
  5 元素全排列穷举 + 16 槽 4,000 例伪随机对照参照排序。
  ✅ ④ 清理：`utils::u64_to_ascii`（仅测试引用死代码）删除。
  回归：poker_l1 358、根 crate 214、texas 114 全绿；clippy 与基线持平。
  说明：`find_winners`/`split_among_winners` 的 Vec 保持宿主侧无害不改
  （AIR 侧对应 52-bit 旗标/位置余数，原判定不变）。
- [x] **49. z_poker 内联 todo 三项收口（完成 2026-09-11）**：
  ✅ `rounds.rs` ShuffleRound 用户洗牌——`execute` 改为调用方传入
  `permute: [usize; N_CARDS]`（非双射 fail-closed 拒绝，
  `InvalidPermutation`）；新增 `execute_random` 仅限服务端受托流程
  （`proxy_shuffle_for`）。洗牌决定权上移到用户侧：client-wasm
  `shuffle`/`join_game_and_shuffle` 绑定加 permute 入参（JSON 数组），
  React 客户端本地 Fisher-Yates + CSPRNG 生成后传入
  （`useCryptoOperations.generatePermutation`）；texas 内嵌 bot/e2e
  模拟用户走 `pokergame::random_user_permute`。**wasm pkg 需重打包**
  （wasm-pack build）后前端生效。
  ✅ `game.rs` reconstruct 后 deal index 重置——`MentalPokerGame` 新增
  `deal_cursor_offset` + `note_deck_reconstructed()`（texas
  `on_complete_reconstruct` 重建 deck 后调用）：reconstruct 重建 + 全员
  重洗后的 deck 是全新发牌序列，旧纪元已发计数不再对应任何位置，游标
  归零、deal/redeal 从新 deck 位置 0 起步；reveal 记录与位置计数解耦
  不受影响。**已知边界**（入档）：重洗会把换出死槽随机打散进新 deck，
  任何位置抽取都可能命中死槽——协议级缺口随 #39 重构管线深挖处理。
  ✅ `types.rs` PlayerState 新增 `is_leave`——被驱逐玩家保留在 players
  表但标记离场，发牌/公共牌/重发三处 reveal pending 构建排除 is_leave
  （修真实缺陷：驱逐玩家的 token 永不到来 → reveal 死锁）。
  回归：poker_protocol 66（+用户置换语义/非双射拒绝 2 例）、texas 114
  全绿。

- [x] **50. 批量上链 rollup 程序（op-batcher 形态）（2026-10-01 立项）**：
  立项依据 = 2026-09-30 业界调研（StarkEx/SHARP、OP Stack、Arbitrum、
  zkSync、Polygon zkEVM、Linea、Scroll 七体系的批量提交器形态比对）：
  共性结论是独立 crate + 持久化队列（先落库再发交易、重启对账续投）+
  专门交易管理层（nonce 保序/加价重发/失败熔断）+ cadence 攒批节奏 +
  监控最小集（pending 数/最老年龄/in-flight/余额）+ 手动逃生口；
  调研结论另确认现状短板——结算+calldata+提交内嵌 texas、
  `prove_log.rs` 只是结算输入雏形、出证（prove-batch.sh 手动）与上链
  之间无常驻组件。
  **poker 侧三子项（2026-10-01 骨架已落地）**：
  ① `settle-queue/`——结算任务持久化投递队列（正式状态表）：单手键
  `(table_id, hand_id)` 去重 + `SettleRoute{Legacy,Dual}` 判别绑
  `STARKNET_SETTLEMENT_MODE`（texas config.rs:136-149；DAPV_SETTLE_ENTRY
  只作 Dual 路内入口参数）+ 投递状态机（Enqueued→Picked→Submitted→
  Receipted|DeadLetter，Dual→Legacy 单向降级迁移）+ 单写者文件归属协议
  （texas 独写 queue WAL / poster 独写 sidecar，DeadLetter 双源归属）；
  ② `starknet-txmgr/`——Starknet 交易管理层（参照 op-service/txmgr +
  zkSync eth_tx_manager）：`StarknetSend` 注入接缝（生产实现包 texas
  已依赖的 starknet 0.17 Provider，测试内存 mock）、nonce 租约与链上
  推断、每轮只推进第一笔保序、v3 资源上限与 RBF 加价重发、在途交易表
  （SendState 多 gas 变体）、wait_call_visible（吸收 submit.rs
  wait_register_visible 语义）、幂等重放分类（is_register_replay/
  is_settle_replay 文案匹配）、有界重试 + 失败熔断（fail-closed）；
  ③ `batch-poster/`——常驻批量上链 daemon（参照 op-batcher +
  Arbitrum batch_poster）：Legacy 两笔 / Dual 双笔 / 降级驱动契约、fold
  攒批（K≤64 且 2 的幂、batch_key=keccak_root 批级幂等键、
  ProofSource 出证含 prove-batch.sh 两阶段腿包装与 program_hash 钉扎
  对拍、MonadProofEnvelope 工件落盘 `TEXAS_MONAD_SPOOL_DIR`）、status
  JSON 端点 + 手动 drain 逃生口。
  待办（本项剩余）✅ 已完成（2026-10-01 勾选，见文末收口注）：texas 侧接线——入队源接 `prove_log::take_settle_input`
  （消除 hooks.rs 进程内 PENDING_SETTLE/SETTLE_OK/SETTLE_ATTEMPTS 的
  重启即丢）、submit_settlement/submit_dual_settlement 发送面换走
  txmgr（calldata 构建不动）、settle_receipt 读 sidecar 回填。
  **zchain 侧四子项（对端，另仓落地）**：SettleDispatcher trait 族
  （settlement-adapter；其 SettleDispatchTask 键域带 `"settle:"` 前缀，
  幂等键 = 本侧 batch_key/keccak_root）、`--mode settle` 常驻模式
  （monad_settlementd，经 `--settle-inbox` 拾取 TEXAS_MONAD_SPOOL_DIR
  工件）、EvmTxManager（L1 发送面）、FactQueue（zchain 自家 L1 proof
  分块 fact 通道：Spooled→ChunkSent→ChunkConfirmed→Finalized，幂等键为
  裸 fact hash——不消费 Monad 工件，勿与 settle 通道混同）。
  （调研文件已入库：`out/rollup-batch-submitter-survey.md`，随 cba99b68
  入库——原尾注「入库后补注出处」就此闭环。）
  ✅ 收口注（2026-10-01，M1 仓务收口）：poker 待办三项已由代码覆盖——
  `texas/src/starknet/settle_wiring.rs`（queue WAL 入队/构建期死信/
  Dual→Legacy 降级 + sidecar 回执回读 settle_receipt，文件头自锚
  follow-up 条目 1）、`submit.rs`（2026-10-01 起发送面换 txmgr，
  calldata 构建不动）、`hooks.rs`（进程内
  PENDING_SETTLE/SETTLE_OK/SETTLE_ATTEMPTS 已删除，投递状态持久化在
  队列/sidecar）；zchain 四子项（SettleDispatcher/monad_settlementd
  `--mode settle`/EvmTxManager/FactQueue）随 zchain 8b1826f/cef45e5
  入库。逐条完成纪要见 `out/rollup-components-followup.md` 条目 1-9。

## 三、结算隐私（实机项——2026-09-11 用户确认完成）

- [x] 一笔真实零明文结算联调（原 #11 剩余；2026-09-11 用户实机对局完成）。
- [x] C5 Ready 实机端到端：登录→买入→对局→私密领取（2026-09-11 用户
  实机完成，人工钱包弹窗一步走通）。
- [ ] **12-15. sidecar 链**：维持推迟——官方 STRK20 Privacy SDK 未上 npm
  （#26 持续跟踪）；v2 escrow 输家扣款/现金出口修复启用前无消费方。解锁后
  按 `client/src/starknet/privacyBuyIn.ts`（Plan B 通道，wallet-api/SDK 双后端
  已实现）续接：M2 赔付路由 →
  M3 通知 UX → M4 合规加固。C5「池费运行时读取」随 #12 一并交付（非独立任务）。
- [ ] **26. STRK20 官方 SDK 跟踪**（持续）：上 npm 后核对 `tryComposeInvoke`。

## 四、长期项（条件触发）

- [ ] **21. 独立 prover 服务**：暂不动；上链验证路线（#22/M3）需要第三方
  可复现证明时再做。
- [ ] **23. Layer 3 递归协议**：长期演进；前置 = #22 缺口收口 + #21。
  范围/验收标准见 git 历史旧 TODO #23 与 `docs/archive/PO5_PO6_DESIGN_NOTES.md`。
- [ ] **31. 债券/罚没合约**：主网化前提（Phase 3）。
- [x] **46. 金额表示评估：u64 改 u31（M31 原生单列、免 limb）——否决**
  （2026-09-10）。理由：`MAX_TOTAL_BET = 10^18`（≈2^60，与 Move 端逐字节
  一致），u31 需下调协议上限 9 个数量级，属产品面额决策而非性能优化；
  且破坏 borsh 布局 / canonical ABI 版本 / state-root / 链端类型。AIR 侧
  单 M31 列表示需全部金额 < 2^30 才能排除域回绕（9 座位求和需 < 2^28），
  同样被上限否定。实测画像（`docs/PERFORMANCE.md`）中下注 AIR 宽度非
  瓶颈（瓶颈 = Cairo 编译 15–17s、Poseidon state-root 2.9s），limb 后端
  维持 PERFORMANCE.md "deferred, no current pressure" 裁决。**条件触发
  再评估**：若面额上限降至 < 2^28 且 limb 成本进入画像 → 优先
  a) 16-bit range check 换 logUp lookup（省 16 bit 列 + booleanity）；
  b) 金额单 M31 列。
- [x] **41. 状态编码布局改造：定长化**（**完成 2026-09-10/09-11**，
  ①②③④ 全部落地 + 版本戳迁移；②③ 详情见 #47 完成记录）：
  ✅ ① `seats: Vec<Seat>` → **`[Seat; 9]`**（`core/types.rs`）——槽位数
  恒 9，`max_players` 之外 Vacant 填充（`validate_state_schema` +
  `padding_seats_are_vacant` 强制；不再新增 seat_count 字段，`max_players`
  即权威）。`find_next_active_seat`/`find_next_participating_seat` 改用
  max 参数、dispatch 双守卫改 padding 检查、state_codec 持久化保持变长
  （外部存储格式不变）恢复时 Vacant 填充。整表 borsh preimage 长度不再
  随桌型配置漂移。
  ✅ ④ `OccupiedSeat.tx_pk` → 定宽 **`StarkTxPubkey { tag, raw: [u8;32] }`**
  （新类型，`signature/tagged_pubkey.rs`；多方案 `TaggedPubkey` 保留在
  join args 与验签分发边界，`from_tagged`/`to_tagged` 桥接）。
  ✅ 版本戳迁移一次完成：preimage `v11→v12`（`state_root.rs`）、
  resolved schema `30→32`、hot `31→33`（`texas_poker/mod.rs`）。
  回归：poker_l1 338、根 crate 211、texas 108 全绿。
  ⏸ ② `Seat`/`HandPhase` 枚举均匀定宽编码 与 ③ 重材料出热态 → **#47**
  （②为跨加密类型的手写 Borsh 工程；③ canonical ABI 已承诺投影、
  canonical trace 成本本为零，收益仅热 preimage 字节——按实测
  （Blake2b 端点语句 3.7-6.4s）风险收益比不支持同窗实施）。
- [x] **42. 状态根 Poseidon252 化（双编码合一）**（#22⑤ 的延伸；**条件：
  root 域版本迁移窗口 + DEPLOYMENTS.md 链端协同**）：`compute_state_root`
  从 BLAKE3（hot-v30 字节，`state_root.rs:228`）切到
  **Poseidon252(canonical preimage felts)**（`poseidon_borsh` 已存在；
  `poseidon252_v2` 已 host-hash-free 可证，2.91s e2e）。收益不在信任
  （哈希都有 STARK 后端），而在：消灭 borsh preimage / hot-v30 字节两套
  序列化的同步负担；状态根从 flock 配套证明升级为转换 AIR 的**内嵌组件**
  （同 `prove_name_commitment_v2` 模式）。
  **实测基线（2026-09-10，同机 release、两侧 PCS 配置逐字相同
  pow10/30q；测试 `v2_perf_sweep_scaling_curve` /
  `blake2b_perf_sweep_vs_poseidon_scale` 可复跑）**：48 felts 轻桌
  preimage → Poseidon 5.2s/556KB；等价 1488B → Blake2b 3.7s/953KB；
  13888B 满牌组规模 → Poseidon 30.8s/628KB vs Blake2b 6.4s/2.4MB。
  **结论修正：纯证明速度 Blake2b lookup 后端反而快 3-5×（≥1.5KB 规模，
  G+scheduler 并行、查找表摊销好），仅证明体积 Poseidon 占优（平坦
  556-628KB vs 线性涨至 2.4MB）**。故 #42 的性能论据不成立，价值收敛为
  编码统一 + 可内嵌主证明（组合性）；"Blake2b 换 Poseidon 提速"这条
  路线**数据否决**。
- [x] **43. 输入真实性锚定（no-replay 信任模型收尾，完成
  2026-09-10/09-11）**：✅ 新增 `src/state_image_admission.rs` 接纳门——组合
  「SMT inclusion STARK（257 compression，`verify_blake2b_lookup_smt_fixed_value_path`
  零宿主哈希）+ 绑定等式（expected_root/object_key/image_commitment
  三对）」，把 canonical 状态镜像从 host-attested 锚到共识根下的 SMT
  叶子；字节→承诺段由既有 `canonical_state_hash`（Blake2b STARK）覆盖。
  ✅ 原语盘点确认：flock SMT path statement、Blake2b 镜像/rules 语句、
  `VerifiedChain::ExpectedChainAnchor`（自带 trust-anchor 警示注释）均已在位。
  **残留（转 #48）**：① finalized 高度公共 root 的取数通道（RPC/合约
  视图，纯运维接线，无代码缺口）；② canonical transition AIR 内部重算
  Blake2b 的单一 statement 合成（`texas_canonical_air.rs:2733`）——AIR
  工程量独立，维持 fail-closed 组合验证直到该项完成。
- [x] **44. rake 除法语义重设计（完成 2026-09-10，产品已确认
  "固定费率+上限"）**：✅ `allocate_rake` → `allocate_rake_fixed_rate`
  （`core/settlement.rs`）：逐层独立 `floor(amount × bps / 10_000)`
  常数除法 + 全局 cap 按 pot_index 升序消耗，未跟注层（eligible<2）恒
  不抽；**witness 除数已从 rake 语义永久移除**，总抽水 ≤ cap 与
  ≤ contested_gross 不变式保持。函数 doc 落了 AIR 纪律（常数除数
  gadget、product < 2^74 = 5×16-bit limb、≤9 层前缀扫描）+ "未来
  rake mode 禁止 witness 除数"红线。✅ 新增 4 个单元测试（层独立计提/
  cap 层序消耗/未跟注跳过/边界）；settlement 30/30、全仓 338/338 通过。
  odd-chip 分配复核：`split_among_winners` 本就是 button 起常数除数 +
  位置余数的 AIR 友好形状，无需改。
- [x] **45. events 定宽化（完成 2026-09-10）**：✅ 座位列表 → `SeatMask`
  （u16）：HandStarted.participants / PotCollected.collected_from_seats /
  HandSettled.winners / RevealTimeout.pending_players /
  ReconstructInitiated.expected_players / ReconstructTimeout.pending_players；
  ✅ 牌负载 → 定宽数组：CommunityCardRevealed `[u8;6]×3 + card_count`
  （对齐 MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS）、ShowdownHoleCardsRevealed
  `[u8;2]×3`；✅ TableCreated `name: String` → `name_commitment: [u8;32]`
  （生产零 emit 点，展示名归 metadata 对象）。AIR 侧只 `matches!` 判别
  变体不受影响；`plan.rs`/`settlement_binding.rs` 两处期望值构造同步
  mask 化。回归：poker_l1 338、根 crate 211、texas 108 全绿。
- [x] **47.（#41 延后子项→完成 2026-09-11）枚举定宽编码 + 材料出
  HandPhase**：
  ✅ ② `Seat`/`HandPhase` 手写固定宽度 Borsh（`core/types.rs`）：记录 =
  `payload_len(u32) || tag || 派生载荷 || 零填充到定宽`（Seat=512B、
  HandPhase=4096B，常量超宽即序列化失败）；单射性由「填充必须全零」
  强制（非规范编码拒绝，含测试）。所有变体/所有阶段序列化恒等长，
  native borsh preimage 长度完全由 schema 版本决定（与 canonical ABI
  固定宽度语义合一）。
  ✅ ③-slice `accumulated_deck`（52 密文 ≈3KB）迁出 `ReconstructState`
  → `DeckState::reconstruct_accumulated`（deck 载体统一承载材料，
  PersistedDeckStateV30 同步扩展；`start_reconstruct` 清空、
  `submit_reconstruct` 写入、`rebuild_deck`/normalize 读取全链路适配）。
  `HandPhase` 从此不内嵌变长大对象。
  ✅ ③-slice `reveal_tokens`/`assignments`：由 HandPhase 定宽记录的
  零填充承载（≤18 条揭示分配），序列化宽度恒定。
  **裁定记录**：「材料出共识 + 冷对象持全量」的原方案**不采用**——
  legacy replay 信任模型下验证器需从 preimage 解码材料做 reveal/reconstruct
  重放，材料出共识即破坏健全性；该约束随 no-replay 模型收尾（#43 完成、
  #48 接线）自然消解，届时材料可安全下沉冷对象。
- [x] **48.（#43 残留→完成 2026-09-11）认证锚定收尾**：
  ✅ ① finalized root 取数通道：`FinalizedRootSource` trait（
  `src/state_image_admission.rs`）+ `StarknetChain::finalized_state_root`
  （texas 合约视图读取，key 拆 hi/lo 双 felt calldata，空返回
  fail-closed；含 calldata/解码单测）。`admit_state_image_from_source`
  完成接入：取数失败即拒绝接纳（fail-closed，不回退 prover 根）。
  ✅ ② `verify_canonical_batch_authenticated` 单一入口：转换批次 STARK
  + 两端点镜像哈希语句 + pre/post SMT inclusion 接纳按序组合、一次
  调用完成（任一步失败整体失败），调用方不再手工拼装有序语句表。
  **前瞻记录**：转换 AIR 内部重算 Blake2b 的「单 STARK」内嵌形态属
  独立 AIR 工程，不阻塞 no-replay 收尾——当前组合验证已 fail-closed
  且每一语句均零宿主哈希。

## 五、主网相关（最后，需用户操作）

- [x] **28. 主网 ≥1 笔 STRK20 交易**（黑客松硬性要求；2026-09-11 用户
  完成操作，操作指引 `docs/MAINNET_TX_GUIDE.md`）：tx 哈希由用户侧回填
  strk20.json。
- [x] **29. strk20.json 收尾**（2026-09-11 随 #28 收口；mainnet tx 哈希 /
  demo_video / demo_url 由用户侧按实际凭据回填，sepolia 地址已回填）。
- [x] **32. Demo 视频**（2026-09-11 用户完成，配合 #28 主网交易展示）。

---

## 已完成项归档（2026-09-05 重梳压缩；详情见 git 历史与各文档头注）

| # | 条目 | 完成时间 |
| --- | --- | --- |
| 1 | 牌局抽水显示 + "no flop, no drop" 对齐 + WEI 10 倍/fold-win 未上链两 bug | 2026-09-03/04 |
| 2 | 牌局记录看板（history_store + HandHistoryPanel + 亮牌隐私一致） | 2026-09-03 |
| 3 | 领取奖励 UI 重设计 | 2026-09-03 |
| 4 | time_bank 跨手恢复（核实已修，无需动） | 2026-09-03 |
| 5 | NOT_REGISTERED 修复 + DAPV 认可键 canonical 化 + 重播/等待窗（剩 owner 单点运维 → 二） | 2026-09-04 |
| 6 | API 速率限制（`ratelimit.rs`，10s/200 per-IP） | 2026-09-03 |
| 7 | 全局 panic 审计 Top-10 修复（遗留低风险项在案） | 2026-09-03 |
| 8 | P2-M1 结算隐私电路骨架（§8.2 预留列位冻结） | 2026-09-03 |
| 9 | P2-M2 证明端（prove-hand 管线，实测 8.6-15s） | 2026-09-03 |
| 10 | P2-M3 合约 v2（fact-registry 过渡，零明文 calldata） | 2026-09-03 |
| 11 | P2-M4 sepolia 部署 + 环境切换（vault v3 / dual v3 / anonymizer v3） | 2026-09-04 |
| 16 | 动作签名（客户端 wasm 签名 + 服务器验签 + seq 单调） | 2026-09-03 |
| 17 | 回签收据（ACTION_RECEIPT，operator 游戏域密钥） | 2026-09-03 |
| 18A | auto 默认动作规则收敛 + 审计日志哈希（服务端 Phase A） | 2026-09-04 |
| 18B | **action_log_digest 进 settlement_private 电路第 37 入参 / 公开段 15 felt / 合约 SETTLEMENT_SEGMENT_LEN=15 / register_hand+settle 新参 / 服务端全链 digest 接线**；回归：根 crate 电路 11✓、legacy DTO 14✓、snforge 88✓、prove-settlement e2e（15 felt 跨语言对齐 + 负例拒绝）✓、texas starknet 集见 commit；**部署收尾 → #34** | 2026-09-05 |
| 20 | poker_l1 收缩 -77k 行（Phase 1）+ 常驻 mirror 删除、prove_log 重建（Phase 2）+ Plan D（blst/BLS12-381 全量移除，Stark 唯一世界） | 2026-09-05 |
| 25 | 全链路私密提现（vault `withdraw_to` + CashoutUnshieldHelper，已部署） | 2026-09-03 |
| 27 | hooks 结算参数 TODO 注释清理（STARKNET_TREASURY_ADDRESS 已实现） | 2026-09-04 |
| 30 | paymaster 生产加固（SNIP-12 本地验签，`STARKNET_PAYMASTER_SIG_REQUIRED`） | 2026-09-03 |
| 33 | 在局锁定：vault v3（locked/session/TTL/force_unlock）+ 服务端接线 + 链上强制实测（剩应用内 e2e → 一） | 2026-09-03/04 |
| 35 | **#33 离桌快解锁 + 结算原子锁账**：结算 bundle 原子串 lock(赢额)/refresh/force_unlock(离桌)；释放五路径闭环（bundle 搭车/兜底 flush/nonce 重试/中止钩子/构建失败钩子）；回退腿 dual 线性结算 + vault 重指 dual v5；赢额回锁关闭逃单窗口 | 2026-09-07 |
| 36 | **SHUFFLE_NOTICE 双通道去重**：服务端出口签名去重（250ms）+ 客户端同签名去重；zk 面板区分 state-rejected 与 proof-failed | 2026-09-07 |
| 37 | **私密领取守恒修复**（STRK20 比赛主径）：anonymizer OP_WITHDRAW 改 withdraw_to（vault 出资，零池内预存），v4 `0x7ee059dd...` 上线，用户实测通过；前端删自筹桥与余额前置 | 2026-09-07 |
| 38 | 设计待办：释放权威证明化（leave receipt 进 settlement digest，随 P4）+ 序无关释放条件/结算串行化（多桌/重试窗口） | 2026-09-07 |
| 39 | 待查：牌桌完整性（物化失败/board-0，去重后观察）；客户端动作签名缺席（snip36 主腿未激活） | 2026-09-07 |
| 48 | **PotCollected 投影分歧（AIR 层缺口，根因链已修至可观测）**：①dev_bot 买入 100→1000 绕开触发（2026-09-13）；②mirror 拒绝视图同步 `sync_rejected_view`/`last_rejected_view` 落地，recursion_e2e 活锁修复——根因是 harness 在权威模式（live_mirror）下复刻了旧版本地兜底的**无条件 turn 轮转**，把 `sync_rejected_view` 的权威 turn 又盲转过一位（双重推进活锁，2026-09-14 对齐生产 `handle_turn_advance` 语义后修复）；③**✅ 2026-09-15 结构性消除（单一状态重构 + canonical AIR）**：连跳收注以多个单街 canonical 行呈现（`canonical_dispatch_trace.rs` 行链生产者；1BB 盲注 all-in 手五行链 `full_hand_control_trace_proves_through_showdown_display` 全通）——Starknet 结算出口的 dual settlement 走 `submit_dual_settlement`（SNIP-36 接线保留其上），归档证明走 `build_appchain_hand_proof`；`derive_bet_collection` 单街规约仅约束遗留 per-dispatch 投影面（fact-registry 降级腿 proving-tool 路径），主径不再触及 | 2026-09-15 |
| — | 文档治理：8 份历史文档归档 docs/archive/、10+ 份头注/内容修订、STATUS.md 重写、本 TODO 重梳 | 2026-09-05 |
| 35 | 旧测试清理：删除根 `tests/`（11 个 BLS precompile/链机制时代集成测试，Phase 1 起编译不过、拖红 CI `cargo test -p poker_texas_air --tests`）；fuzz/ 两个死 target（proof_wire/tx_decode 引用已删模块）重写为 settlement_statement/digest_felts 现役解析面，fuzz.yml 同步 | 2026-09-05 |
