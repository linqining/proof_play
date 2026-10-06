# 动作签名与抗审查设计（Phase 2 hand_proved 前置分析）

> **Summary (EN).** Censorship-resistance design via signed actions
> (#16/#17/#18): the hand's action log is hashed into the settlement digest
> (Phase B — wired), legal-default constraints are enforced in-circuit
> (#18 Phase C — the mainnet gate), and `hand_proved` is the Phase 2
> precondition analysis. Mostly implemented; live status in the Chinese header
> note below and in `../TODO.md`.

> 状态：**主体已实施（2026-09-05 更新）**——动作签名 #16（客户端 wasm sign_action + 服务器验签/seq 单调）、回签收据 #17（ACTION_RECEIPT）、accepted-seq 广播、auto 代打标记 + 审计日志哈希均已在代码落地；#18 Phase B 已把动作日志哈希接进结算隐私电路（第 37 入参/公开段尾词/合约注册承诺）。**仍未落**：电路内逐条验签与"合法默认"约束（§8.2，主网上线门槛）、accepted-seq 上链事件、债券/罚没（§7.3，P3）。本文保留为该主题唯一设计文档，实施状态以 ../TODO.md 为准。
> 关联：`SETTLEMENT_PRIVACY_PLAN.md`（Part A Phase 2 / Part B 密钥层）、`DUAL_PROOF_PROTOCOL.md` §6 绑定不变量、`../archive/TRUST_MODEL_NO_TRANSACTION_REPLAY.md`(已被取代)。

## 1. 问题陈述

Phase 2（hand_proved）要求：牌局动作序列可被证明、可被任何一方独立验证——服务器不能伪造、篡改玩家动作，审查（丢弃/延迟动作）可被检测与举证。

**当前缺口**：牌局动作（fold/check/call/raise、reveal token、shuffle 提交）是**无签名的 socket 消息**，归属仅靠"token → socket_id → pk_hex"的会话绑定。这意味着：

- 服务器可凭空捏造"玩家 X 弃牌"、改写加注额度、重排动作顺序——消息本身没有可验证的出处；
- hand_proved 的 Stwo 电路若直接消费这些动作，结论只是"服务器这么说"，抗审查为空；
- 实证：牌组竞态的 join 被拒（Invalid remask proof）时，玩家没有任何可仲裁的凭证，只有一句服务器日志。

**若完全没有任何签名**：动作归属在密码学上不可能保证。唯一能做的是信任服务器 + 客户端无法举证——这正是 hand_proved 要消除的信任面。

## 2. 方案：动作级 game-SK 签名（复用牌局身份，零钱包交互）

**签名者 = 玩家的牌局身份 SK**（Part B：随机生成、本地持有、与钱包零派生关系）。它已经是链下域的签名身份：sit-down 时 pk ownership proof 已把 `pk ↔ 座位 ↔ 玩家` 绑定并进入 ProveTask。不使用钱包私钥（高频动作会弹窗且暴露钱包链接）、不使用 Cartridge/Ready session key（那是链上交易免弹窗的 UX 工具，解决不了链下消息归属）。

### 消息格式

```
action_msg = {
  table_id, hand_id,
  seq,             ← 玩家内单调递增（防重排/防重放）
  action, payload, ← fold/check/call/raise/reveal/shuffle 提交…
  ts,              ← 客户端时间戳（仅供参考，不参与安全判定）
}
sig = Sign_sk( poseidon(table_id, hand_id, seq, H(action‖payload)) )
```

- 签名域与现有管线一致：FiatShamirTranscript / StarkCurve 哈希（与 `hand_transcript_domain`、`hand_binding` 同族）；
- **防重放**：`(hand_id, seq)` 单调 + hand_binding 域分离（与认可/绑定的既有做法一致）；
- 服务器验签（seat pk）通过才接受动作，写入手内动作日志（ProveTask 输入）。

## 3. hand_proved 下的抗审查论证

| 攻击 | 结果 | 原因 |
| --- | --- | --- |
| 服务器伪造动作 | ✗ | 伪造需玩家 SK；电路验证每条动作签名对 seat pk 成立 |
| 服务器篡改动作（改额度/换动作） | ✗ | 签名覆盖 (action, payload)；改动即验签失败。即使电路只看聚合 digest，诚实客户端本地重放可发现 digest 不一致 |
| 服务器重排动作 | ✗ 可检测 | seq 在签名域内，乱序使后续状态根对不上 |
| 服务器审查（丢弃动作） | ⚠️ 可检测可举证；强制入块需备用通道 | 见下方分级 |

审查的分级保障（成本递增）：

1. **Phase 2 内建（零成本）**：hand_proved 电路验证"含所有玩家动作的完整序列"——服务器剔除动作后其自身给出的 settle digest 与 register 的不一致，**该手结算直接失败**。审查的代价是结算不可用，服务器没有动机；且诚实客户端本地重放可发现不一致（争议证据）。
2. **双通道提交**：动作签名副本同步发往第二提交端（备用中继/直接 L1 端点）。签名使动作"可携带"——任何通道提交都等价，主通道拒收可走备用。
3. **L1 仲裁锚点**（主网/Phase 3）：争议时把签名动作发到 L1 轻量锚合约（存 digest + 签名），结算合约在时间窗内接受挑战。

## 4. 与 session key / 钱包签名的关系

| 方案 | 解决的问题 | 不解决的问题 |
| --- | --- | --- |
| Cartridge Session Keys | 链上交易免弹窗（UX） | 链下动作归属；且引入覆盖层/弹窗/账户混淆（本项目已移除，见 SETTLEMENT_PRIVACY_PLAN.md Part C） |
| Ready Smart Sessions | 同上（仅 Ready Smart Account；需 @argent 系 SDK + Ready 后端 co-sign；主网需合约白名单） | 链下动作归属 |
| 钱包（Ready）每动作签名 | 归属 + UX 皆有 | 高频动作弹窗 + gas + 暴露钱包链接（隐私主张冲突） |
| **牌局 SK 动作签名（本方案）** | 归属、防伪造、防篡改、可举证 | 恢复/托管（可后续用 Ready signMessage 一次性认证解决） |

设计原则：**钱包域（Ready）管资金与链上身份，牌局 SK 域管游戏身份与动作签名，两域无密码学链接**（Part B 隐私主张）。结算时两域通过 payout commitment / 承诺链衔接，不做地址直连。

## 5. 落地成本（Phase 2-M2 排期内）

| 端 | 改动 | 量级 |
| --- | --- | --- |
| client-wasm | `sign_action(sk, msg)` 导出（域分离 + 既有签名原语） | ~20 行 + 单测 |
| 客户端 | 动作发送前附 `(seq, sig)`；seq 持久化（localStorage per table/hand） | 小 |
| 服务器 | 验签（seat pk）+ seq 单调检查 + 动作日志入 ProveTask | 小 |
| Phase 2 电路 | 每动作签名验证纳入约束（或预验签 + 电路只锁 digest，M3 定） | P2-M2 主体 |

## 6. 开放问题（实施前确认）

1. seq 的持久化粒度：per-table 或 per-hand（断线重连后的连续性 vs 重放窗口）；
2. 电路内验签 vs 链下预验签 + 电路锁 digest 的取舍（gas/证明规模）；
3. 观战者/回放器（replayer）需要的最小数据集（动作日志 + 初态 deck 承诺即可完整重放）；
4. 双通道提交的备用端点选型（第二中继 vs 直连 L1 端点）。

## 7. 牌局动作（check/call/fold）的抗审查处理

动作分两类，受害程度不同，防御形态也不同：

| 动作 | 被审查的后果 | 有界性 |
| --- | --- | --- |
| check（免费） | 失去过牌机会 | 有限——turn timer 兜底机制已存在 |
| call/fold（有投入决策） | 可能被折叠掉强手牌 | 损失 = 本手潜在赢率，不可精确量化但**有界**（上限 = 本手底池） |
| 买入后的存量筹码 | 不受影响 | 筹码在 vault（链上、玩家地址名下），随时 withdraw——**审查动作动不了存量** |

结论：审查的最大危害是"本手公平性"，不是"资金"。防御形态 = **损失有界 + 审查可证明 + 事后可追责**，而非现阶段不可能的"强制服务器接受"。

### 7.1 第一层：签名回执——把"没接受"变成可证明命题

- 客户端发签名动作后，服务器**必须回签收据**：`Sig_operator(player, hand_id, seq, 决定)`，决定 ∈ {accepted, rejected(reason)}；
- 服务器每手结算时在 settle 事件发布每玩家 **accepted-seq 向量**（"本手我接受了你到第几号动作"）——仅在现有 settle 事件加几个 felt；
- censorship 由此成为**可判定命题**：
  - 持有 `seq=5` 动作 + 收据 `rejected` → 服务器明确拒绝（看理由是否合规）；
  - 持有 `seq=5` 动作 + settle 事件 accepted-seq 只有 3 → **密码学证明动作被丢弃**（事件在链上，无法抵赖）。

没有回执机制时，"服务器没接受"不可证明（证明否定命题需要对方先承诺命题空间）——accepted-seq 向量就是那个承诺。

### 7.2 第二层：止损——有界危害由既有 timer 兜底 + 默认动作签名化

- 轮到玩家且窗口内无被接受动作 → 服务器按**合法默认动作**推进：可免费 check 则 check，需跟注则 fold（真实牌桌计时器规则，game_loop 的 turn timer 已实现）；
- 关键改进：**默认动作也入签名日志**——服务器代打时以玩家的 seq 追加 `(auto, server_sig)` 标记动作。于是"被审查"成为可举证命题：`seq=5` 签名动作存在 + 随后 `auto` 动作存在，两者均在手内日志，Phase 2 电路可验证；
- 存量筹码不受影响（vault 在链上、玩家地址名下），随时 Leave Table——**审查者留不住你的钱**。

### 7.3 第三层：追责——让审查有代价

- **运营方债券**：operator 链上质押债券；被证明的审查（签名动作 + accepted-seq 缺口，合约可验证：ECDSA 验签 + seq 比较）触发罚没、赔付受害者。合约要素全为既有原语，无新密码学；
- **单服务器架构的诚实边界**：运营商可通过审查赢家作弊获利——债券罚没必须 > 最大可窃取价值（底池上限 × 手数）。这是中心化编排的固有成本，透明规则 + 博弈约束；
- **声望/多期博弈**：运营商靠持续抽水盈利，一次被证的审查损失远超收益。

### 7.4 为什么"强制入块"往后放

真正的无审查（服务器**必须**接受动作）需要编排权去中心化：

- **多编排者**：动作日志多服务器复制 + quorum 接受——需要编排状态共识协议（大工程）；
- **L1 强制入块**（rollup forced-inclusion 模式）：L1 提交签名动作，编排者下一手必须纳入，否则其证明作废——settle 合约在 L1 侧，技术可行，但改变编排模型；
- 两者都改变信任模型本身，属 Phase 3/主网阶段的架构决策。

## 8. 设计原则：后实现项的架构预留（本节为硬约束）

原则：**功能可以后实现，但消息格式、事件字段、电路约束必须现在预留**——否则后补会破坏签名域或触发电路重写。

### 8.1 必须现在预留的字段/行为

| 预留项 | 位置 | 成本 | 不预留的后果 |
| --- | --- | --- | --- |
| 动作签名 + seq | action_msg（P2-M2 客户端/服务器） | 零（本来就要做） | hand_proved 无法消费动作 |
| 服务器收据 | 服务器对每动作回签 | 小 | 无法证明"被拒绝/被忽略" |
| accepted-seq 向量 | settle 事件（追加几个 felt） | 零 | 审查不可检测 |
| `auto` 默认动作标记 | 动作日志条目 + 电路约束 | 小 | 服务器可借"代打"任意折叠玩家（griefing 攻击面） |
| 债券/罚没合约位 | settlement/vault 部署不预斥迁移路径 | 零 | 追责需二次重部署 |

### 8.2 必须现在写进电路规格的约束（P2-M1 规格 §约束 追加）

- 电路接受的每条动作必须带签名（玩家 pk 或 server pk 的 auto 动作）；
- **auto 动作必须满足"合法默认"规则**：`auto-check` 仅当面对零下注；`auto-fold` 仅当面对下注——否则服务器（或被攻破的服务器）可借代打折叠任意玩家，这是最大的新增攻击面；
- seq 全桌单调（跨玩家按 action 顺序、玩家内按 seq）。

### 8.3 显式接受的残余攻击面（写进 README 信任模型）

| 攻击面 | 窗口 | 缓解 |
| --- | --- | --- |
| 服务器拒绝合法动作并拒发收据 | 手内动作窗口 | 客户端持有签名动作 + 他人可比对 accepted-seq；债券罚没（P3） |
| 服务器滥用 auto-fold 折叠玩家 | 有 auto 约束前 | M2 电路必须实现"合法默认"校验后才可上线 |
| 运营商跑路（携浮存） | 随时 | 与传统棋牌同级；主网化需债券（Phase 3） |
| 多钱包/多身份女巫进桌 | Session 层 | 与本方案正交；Ready 账户级准入（P3 评估） |

### 8.4 结论重申

- 抗审查 = **动作签名（game SK）+ seq 绑定 + 收据/accepted-seq 上链 + 电路消费签名序列**；
- session key（Cartridge/Ready）与钱包每动作签名都不是本问题的解——前者是 UX 工具且引入覆盖层/依赖问题，后者高频动作不可行且暴露钱包链接；
- 所有"后实现"项，只要按本节的字段预留与电路约束编写，后续启用都不需要破坏性变更。

---

## 9. 实施决策定稿（2026-09-05，原"实施前确认的 4 个开放问题"，TODO #19）

> 逐项给出决策、依据（现行代码事实）与影响面。Phase C（TODO #18 电路内
> "合法默认"约束）按本节执行，不再重新讨论。

### 9.1 seq 持久化粒度：**per-table 单调、跨手不重置**

- 现状即此口径：客户端 seq 按桌持久化（`actionSigning.ts` localStorage 单调），
  服务端 `accepted_seq: HashMap<seat, u64>` 桌级单调，跨手不重置；动作日志用
  `hand_log_start` 截窗，不回退 seq。
- 理由：① 重置窗口 = 重放窗口——per-hand 重置会让"上一手末尾的高 seq"在
  新手变合法，需要额外边界证明；② 证据向量按手截窗（每手 accepted-seq
  子序列）即可满足 settle 举证，不需要重置；③ 与现行实现零迁移。
- 代价：seq 增长跨手累积（u64，实际不可耗尽）；服务器快照持久化需包含
  accepted_seq（重启不得回退，回退即拒绝有效动作）。

### 9.2 电路内验签 vs 链下预验签：**链下预验签（现行）+ 电路只约束日志哈希吸收与"合法默认"规则**

- 依据：settlement_private 证明管线（prove-hand → Stwo）当前 builtin 只有
  Poseidon/range-check/bitwise/output，**无 keccak/EC**——电路内逐条
  StarkCurve 验签需要换管线（加 EC 组件或走 #22 上链验证路线），成本与
  主网门槛不成比例。
- 玩家自签动作的可举证性已由两层承载：客户端留存 (seq, r, s) + operator
  回签收据（ACTION_RECEIPT）；电路只把 `action_log_digest` 吸收进结算
  （#18 Phase B 已落地），Phase C 在此之上加"合法默认"规则约束（见 9.5）。
- 完整电路内验签归入上链验证路线（#22/M3，EC_OP 或递归），不在 Phase C。

### 9.3 replayer 最小数据集：**HandProofLog ∪ 本手动作日志窗口（+可选客户端留存的收据）**

- 最小集 = `HandProofLog`（join 所有权证明缓冲 → HandStart 快照
  [参与者/盲注前 stack/button/deck] → reveal 令牌 → 下注命令 → 强制弃牌）
  ∪ `action_log[hand_log_start..]`（seat/seq/action/amount/auto/sig_ok）。
  前者重建牌面与派奖，后者重建决策序列与代打审计。
- ACTION_RECEIPT 回执是客户端侧**可选补强**证据（服务器作恶场景），不进
  replayer 必需集——replayer 只需要确定性重放所需的服务器已接受输入。

### 9.4 双通道备用端点选型：**客户端多 RPC failover（已有）+ 服务器主/备端点列表；最终出路是链上证据而非第二台可信服务器**

- 执行层已有 `VITE_STARKNET_RPC_URLS` 多 RPC failover（plan-c）——保留为
  通道 1（提交/读取）。
- 通道 2：socket/HTTP 服务器端点列表化（客户端按序重连备用部署），仅解决
  可用性，**不引入信任**——备用服务器同样可能审查。
- 争议终局不依赖任何游戏服务器：签名动作 + 收据 + accepted-seq 向量由
  客户端留存，P3 债券/罚没合约（#31）落地后作为链上举证出口。

### 9.5 Phase C 实施要点（由 9.2 派生的规格补充）

- 动作日志哈希链需从 starknet_keccak 切到 **Poseidon sponge**（现管线无
  keccak builtin，切 Poseidon 后电路可用 poseidon_builtin 重算整链）——这是
  又一次 wire 变更（digest 公式/游戏层/game 层与电路对齐 + 合约重部署），
  与 #34 同批执行。
- 电路新增见证输入：每条 auto 动作一行 (owed, my_bet, big_blind, kind)，
  约束 `legal_auto_action` 规则（owed==0 ⇒ check；0 < owed−my_bet ≤
  big_blind ⇒ call；owed−my_bet > big_blind ⇒ fold），range-check 有界；
  非零变动参与者上限不变（8），动作条数上限固定（建议 64）并在语句里钉死。
- `action_flags` / `accepted_seq_digest` 两个 §8.2 预留槽位在 Phase C 启用：
  auto 标记位图进 flags，seq 连续性（单调 +1）由摘要吸收约束。
