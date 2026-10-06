# 结算隐私方案（STRK20 Private Settlement）

> **Summary (EN).** Authoritative plan for STRK20 private settlement:
> zero-plaintext dual-proof settlement, SNIP-36 settlement mode with legacy
> fallback, and the payout-anonymizer conservation fix. Status: P2-M1..M4
> done; the v5 contract lineage is live on Starknet mainnet (2026-09-07);
> remaining items (one live end-to-end rehearsal, server enablement bits) are
> tracked in `docs/TODO.md`. Chinese is the working language of this spec.

> 目标：**链上看不出一手牌结算给了谁、谁领走了钱**；牌桌密钥层
> （Part B）看不出玩家是哪个钱包。
> 买入已经走 STRK20 隐私池（`poker_vault_anonymizer.cairo` 的 `privacy_invoke`），
> 出金已经有 `privacy_withdraw`（burn_chips → open note）。本方案补上中间缺的
> 两环：**结算赔付本身的隐私**（Part A）与**游戏 ElGamal 密钥的隐私**（Part B）。
>
> 定位句（对外口径）：**Private by default, disclosable when required** ——
> 池内互转全部加密；充值/提现边缘与结算根承诺公开；监管走 FPI 门口筛查 +
> 注册时密钥托管（auditor escrow），无批量监控后门。

---

## 0. 现状：泄漏在哪

### Part A：结算腿

链上资金路径（方括号 = 公开可见）：

```
买入:  [用户钱包] ──shield──▶ [STRK20 池] ──privacy_invoke──▶ [PokerVault 记账到钱包 felt]
牌局:  服务器内存筹码（mental poker，牌面全程加密，无泄漏）
结算:  PokerDualSettlement.verify_and_settle_dapv_stark(
           hand_binding, hand_id,
           players: Span<ContractAddress>,   ← 明文：谁赢了
           deltas: Span<i128>,               ← 明文：赢/输多少
           p_batch)                          ← DAPV 认可批量
       └─▶ vault.apply_settlement(player, delta)   ← 每个钱包余额公开增减
出金:  vault.withdraw ──▶ [钱包]（或 privacy_withdraw ──▶ 池内 note，已隐匿）
```

三个泄漏点：
1. **结算 calldata/事件**：`(players, deltas)` 明文 → 谁赢多少直接可读；
2. **vault 余额账本**：`apply_settlement` 按钱包 felt 公开增减 → 与买入/出金
   事件做时间关联可反推玩家；
3. **出金边缘**：直接 `withdraw` 会把"这局赢了"链接到提现地址
   （`privacy_withdraw` 已切断这一段）。

## 1. 方案总览：把结算拆成「承诺」与「认领」两段

核心思路：结算合约**只发布承诺，不发地址**；赢家在 STRK20 池内用
`privacy_invoke` **私密认领**成 note（owner 隐藏）。复用协议两条既有规则：

- `register_hand` 已经把结算根做成 **Poseidon 承诺**（settlement_digest =
  `poseidon_hash_many(hand_id, (player, ±, |delta|)…, action_log_digest)`，
  尾词为本手动作日志哈希（#18 Phase B，见 `texas/src/starknet/submit.rs`））
  ——登记阶段本来就没人能读出明细；
- anonymizer 三明治模式：`池 withdraw → helper.privacy_invoke → approve →
  Span<OpenNoteDeposit>`（`poker_vault_anonymizer.cairo` 已验证了这套形状）。

```
                 ┌──────────────────────────────────────────────┐
                 │  PokerDualSettlement（结算腿）                │
                 │  verify_and_settle_dapv_stark_private(       │
                 │    hand_binding, claim_cms[], pot, proof)    │
                 │  · 验 DAPV 认可批量（不变，声名照旧）          │
                 │  · 验 Stwo 证明：明文 (players,deltas)        │
                 │    哈希 == 已登记 settlement_digest，零和      │
                 │  · 不再公开 (players, deltas)                 │
                 │  · 把 pot 从 vault 划入赔付托管，              │
                 │    存 claim_cms[seat] = P(pay_sk 承诺…)       │
                 └──────────────┬───────────────────────────────┘
                                │ (链上只有: 承诺 felts + pot 总额)
                                ▼
   赢家客户端（知道自己 seat 与 delta）      SettlementPayoutAnonymizer
   · pay_sk 本地生成，从未上链/上报          · privacy_invoke(
   · secret = poseidon(pay_sk, hand_binding)     hand_id, seat, secret,
   · 组装池内私密交易（Wallet API）:              amount, note_id)
     transfer(amount=OPEN) + invoke            · 验 P(secret…) == claim_cm
   · 经 relayer 提交 → 提交者=relayer           · vault 托管划款 + approve 池
                 │                              · 返回 OpenNoteDeposit
                 ▼                                     ▼
                 └──────────▶ [STRK20 池 note]（owner 隐藏，金额可见）
                                    │
                                    ▼ 用户随时 withdraw 到任意地址（边缘公开但不可链接）
```

> ⚠️ **本图右侧认领腿已被 Part C3.2 取代**：池的 InvokeExternal
> calldata 随交易公开提交，明文 secret 可被抢跑盗领；且 payout_sk 又是
> 一把裸 localStorage 密钥（丢钥问题重演）。新设计 = 运营方 SDK 私密
> 转账直接把赔付发进赢家 viewing key 的加密 note——赢家侧**没有认领
> 交易**，花费是钱包原生操作（详见 Part C3.2/C3.3）。结算腿（承诺/
> escrow/Phase 2 ZK 消 players/deltas）**不变**。

## 2. 隐藏 vs 可见（诚实清单）

| 项 | 现状 | 改后 |
| --- | --- | --- |
| 结算 calldata 里的玩家地址/增减 | **明文** | 消失（只有 claim 承诺 felts + pot 总额） |
| 谁赢得了哪一手 | 明文 | 隐藏（承诺不泄露 preimage） |
| 谁认领了赔付 | vault 余额变化 | 隐藏（认领在池内证明交易里，提交者=relayer；note owner 隐藏） |
| 赔付金额（单手/单 note） | 明文 | **公开**（open note 金额明文，池的边缘设计如此；可在出池后用池内互转继续遮蔽金额） |
| pot 总额 / 参与人数 | 明文 | 仍公开（风控与审计需要） |
| 买入边缘（depositor, amount） | 明文 | 仍公开（STRK20 门口 FPI 筛查即在此处，协议要求） |
| 认领时间 | — | 公开（可加延迟队列弱化，见 §6 局限） |
| 输家余额扣减 | 公开按钱包扣 | **残余泄漏**：Phase 1 结算腿只划 pot、不点名任何人（所有人的钱在买入时已进 vault/托管，手内输赢只体现在服务器内存筹码），链上余额不再逐手变动 |

关键结构收益：**改后 vault 余额在牌局期间完全不逐手变动**（结算只动
pot 托管），"盯余额猜输赢"这条链路被整体消除。

## 3. 信任边界（谁看得到什么）

| 角色 | 持有 | 可见 | 不可见 |
| --- | --- | --- | --- |
| 玩家（隐私钱包/Ready） | `pay_sk`（赔付私钥）、池 viewing key | 自己的 seat、delta、自己的 note | 他人的认领与 note 归属 |
| 游戏服务器（operator） | 牌局全量（本就中心化发牌/验证）、seat→钱包映射 | 结算根、claim_cms、pot | `pay_sk`（客户本地生成，**从不上报**——服务器无法替领） |
| STRK20 池合约 | 加密 note、nullifier 集 | 承诺、边缘（deposit/withdraw）、认领交易 envelope | note 明文归属、玩家身份 |
| Relayer | 提交账户私钥 | 交易 envelope（时间、gas） | 任何明文归属 |
| Prover（Stwo，服务器侧） | 结算明文（本来就是它算的） | 生成 π | —（它已知，不新增信任） |
| Auditor（治理公钥托管） | 注册时 escrow 的 viewing key | 依法定请求选择性披露 | 无批量模式 |

合规不变项：FPI 门口筛查照旧作用于 shield 存入；池注册时 viewing key 自动
托管到 auditor 公钥（选择性披露、非后门）；这些口径写进 README 与演示稿。

## 4. 分阶段落地

### Phase 1 — 赢家私密认领（hackathon 主交付，无需新电路）

链上改动（poker_contracts，均为**草稿接口**，需团队评审后才能上线）：

1. **`PokerSettlementClaim`（新合约，或并入 dual）**
   ```cairo
   // 登记：结算后写入，只存承诺
   claim_cms: Map<felt252 /*hand_binding*/, Array<felt252>>, // per-seat
   escrow: Map<felt252 /*hand_binding*/, u256>,              // pot 划入

   // claim_cm 由结算合约在 settle 时算：
   //   cm[seat] = poseidon(payout_pk_x, payout_pk_y, hand_binding, amount)
   //   （payout_pk 从 vault 注册表 storage 读出，calldata 不含它）
   ```
2. **vault 增量**（现有函数风格延续 `deposit_for`/`burn_chips`）：
   - `register_payout_key(pk_x, pk_y)`：坐下载入时登记，一次性、公开
     （只建立 钱包→payout_pk，与任何一手结算无关联）；
   - `escrow_debit_for_settlement(hand_binding, total)`：结算合约专属门，
     把 pot 从"全部玩家筹码池"划入 claim 托管。改后结算不再调用
     `apply_settlement(player, delta)`。
3. **`SettlementPayoutAnonymizer`**（新 helper，三明治规则全遵守：
   approve 不 transfer、余额差计量、空 span 合法、u128 守卫、只许池调用）：
   ```cairo
   fn privacy_claim(ref self, hand_binding: felt252, seat: u32,
                    secret: felt252, amount: u256, note_id: felt252)
       -> Span<OpenNoteDeposit> {
       // assert caller == pool
       // assert poseidon(secret…) == claim_cms[hand_binding][seat]
       // assert escrow[hand_binding] >= amount；扣减
       // approve(pool); 返回 OpenNoteDeposit { note_id, token, amount }
   }
   ```
4. **结算合约**：`verify_and_settle_dapv_stark` 的
   `apply_deltas_through_vault(players, deltas)` 替换为
   `escrow_debit_for_settlement(hand_binding, pot)`；DAPV 验证逻辑原样保留
   （**结算的正确性证明不放松**，只是不再公开明细）。Phase 1 里
   `(players, deltas)` 仍随 calldata 提交给合约做 digest 校验 ——
   **这是 Phase 1 的已知残余**：事件里有明细，Phase 2 用 ZK 消除
   （若 demo 需要立刻消除，可先把 settle 事件里的数组去掉、calldata
   无法隐藏，README 里如实标注）。

客户端 / 服务器改动：

5. **客户端**：登录后生成 `payout_sk`（本地，不上报），登记
   `payout_pk`；手牌结束从游戏消息得知自己的 delta；领奖时用 Wallet API
   组装池内私密交易（`transfer` amount=`"OPEN"` + `invoke`
   `SettlementPayoutAnonymizer.privacy_claim`，calldata 顺序与 helper
   签名一致），经 relayer 提交；note 用 viewing key 扫描发现。
6. **服务器**：结算提交路径切到新入口；claim_cms/pot 事件照常发出；
   可选：把 (hand_id, seat, amount) 加密投递到玩家的通知信道（玩家其实
   自己就知道，非必需）。

演示剧本（评委视角）：
`开一手牌 → 链上只出现 承诺+pot → 赢家在另一浏览器/隐私钱包里认领 →
explorer 全程看不到任何赢家地址 → note 在池内可继续私密转出`。

### Phase 2 — 结算腿 ZK 化（Stwo，消掉最后一块明文）

- 新增一个小 Stwo 电路：证明"知道 (players, deltas) 使
  `poseidon_hash_many(...)` == 已登记 settlement_digest ∧ 零和 ∧ 人数与
  expected buckets 一致"，输出 claim_cms 的正确性（cm 的输入从同一批明文
  取）。**本项目本就运行证明基建**（poker_l1 VM / outer aggregate），电路
  只是把"开根"搬进证明；STRK20 池自身就是 Stwo 管线，同族技术、评审友好。
- 合约换 `verify_and_settle_dapv_stark_private(hand_binding, claim_cms,
  pot, π_stwo)`：链上从此**没有任何明文 (players, deltas)**。
- 这正好呼应项目现有的 `proof_policy`（residual trust → Phase 2 on-chain
  verification）叙事。

### Phase 3 — 金额与余额全隐（可选加强）

- open note 金额公开是协议边缘；赢家领奖后立刻在**池内**把金额拆分/
  互转到常用面额再出池，弱化金额指纹（文档明示的局限对策）；
- 认领加最小延迟抖动（服务端 relayer 队列），弱化时间关联；
- 文档同时照抄协议局限：channel-open linkability、特征金额、边缘公开。

## 5. 安全清单（新 helper 的红线）

- `SettlementPayoutAnonymizer` **有状态**（托管跨交易持有 pot）→
  构造器钉死 pool/vault/settlement 三地址 + `privacy_claim` 断言
  `caller == pool`（照抄 `poker_vault_anonymizer` 的写法）；
- 认领防重放：`(hand_binding, seat)` 已领即置位（`claimed: Map`）；
- 金额用 u256→u128 显式转换守卫（WEI_PER_CHIP=1e14，实际量级远够）；
  零金额拒绝；
- 外部调用失败让它回滚（整笔池交易原子中止是安全方向）；
- commit 与 settle 的 `escrow` 守恒断言：`Σ 可领额 == pot`（零和不止
  在证明里，托管里再验一次）；
- Cairo 代码按技能红线标注为 **draft**：team review + `cairo-security`
  过一遍 + 审计后才可主网。

## 6. 已知局限（写进 README，别藏）

1. Phase 1 的 settle calldata 仍带 `(players, deltas)` 明文（digest 校验
   需要），Phase 2 才移除；事件可以先只发聚合；
2. payout_pk 注册是公开的一次性事件——它不与任何一手绑定，但"注册过
   payout key 的钱包参与了游戏"可推断（可用 shadow account 进一步切）；
3. pot 总额、人数、认领时刻公开（STRK20 边缘设计）；
4. 金额在 open note 上公开（Phase 3 缓解）；
5. 手机钱包能力前提：认领需要支持 STRK20 Wallet API 的钱包
   （读取连接钱包能力，不支持则回退现有 `privacy_withdraw` 出金路径）。

## 7. 验证清单（动手前逐项确认）

- [ ] 池合约地址 / `privacy_invoke` ABI / `OpenNoteDeposit` 形状与当前
      主网版本核对（`starkware-libs/starknet-privacy`）；
- [ ] 钱包支持面：哪些连接钱包支持 Wallet API 私密交易 + SetViewingKey
      自动注册；
- [ ] Stwo 证明锚定窗口（`proof_validity_blocks` ≈15 分钟）对认领流程
      无影响（认领在池交易内，天然满足）；
- [ ] FPI 筛查对"结算托管划入"路径的影响面（划入不是 deposit，确认
      合规边界描述准确）；
- [ ] snfuse/sepolia 上先跑 `SettlementPayoutAnonymizer` 单测
      （照 `poker_vault_anonymizer.cairo` 的 mock pool 测试骨架）。

## 8. 与比赛叙事的衔接

- 现有故事：mental poker（牌面隐私，DAPV 声名）+ 私密买入 + 私密出金；
- 本方案补齐：**结算隐私 = 谁赢钱不可见** —— "从买入到赢钱离场，
  全程钱包不可链接"的完整闭环；
- 一句话 pitch：*The cards are encrypted, the winners are invisible —
  settlement root is committed, payouts are claimed as STRK20 notes.*

---

# Part B — 密钥层隐私（游戏 ElGamal 密钥与牌桌身份）

> Part A 解决"谁赢了钱"；Part B 解决"坐在牌桌上的 pk 是哪个钱包"。
> 两者叠加才构成完整闭环：否则即使结算私密了，桌上明文 pk 仍把
> 每一手牌与公开钱包地址钉在一起。
>
> ⚠️ 这条密码学管线（洗牌/reveal/fold 证明、Merlin transcript、镜像
> join 证明）调试了很久才稳定。本 Part 的设计原则因此是
> **最小切面：只换 sk 的来源，不动任何证明、线格式与服务器索引**。

## B0. 现状与泄漏链（代码事实）

密钥生成（`poker_protocol/src/z_poker/protocol/client.rs:36`）：

```rust
pub fn new_with_wallet_address(wallet_address: &str) -> Self {
    let sk = hash_to_scalar(wallet_address.as_bytes());  // ← 从公开地址确定性派生
    let pk = *BASE_G * sk;
}
```

**sk 是公开钱包地址的确定性函数** —— 任何知道钱包地址 W 的人都能本地算出
pk(W)。这条派生被三处使用：客户端首次生成
（`client/src/context/player/PlayerContext.tsx:122,196`，localStorage 无 sk 时）、
钱包切换再生效（同文件）、服务器 bot（`texas/src/dev_bot.rs:119`）。

泄漏链（按危害排序）：

1. **对手去匿名**：牌桌广播全程以 pk 为玩家标识（REVEAL_NOTICE 的
   `player_assignments`/`pending_players`、completed 列表、reveal 结果、
   服务器日志）。对手拿任一已知钱包地址算 pk 对号入座即可识别你是谁；
   不需要任何链上数据。
2. **跨桌跨局行为追踪**：同一钱包永远同一 pk → 何时在线、在哪桌、和谁
   同桌、打多少手，全可聚合（服务端与对手双视角）。
3. **上链前瞻**：ElGamal pk 今天不直接上链（register 腿全是哈希承诺；
   settle 腿 p_batch 里的是 **StarkCurve endorsement pk，已经是随机
   生成存 localStorage，与钱包无关** ✅）。但 DAPV/证明型结算的演进
   方向一旦把牌桌 pk 或其承诺放进 calldata，钱包派生密钥会把泄漏直接
   固化到链上。规则：**牌桌密钥从今起必须与钱包零派生关系**。

一个重要事实（改动可行性的根据）：**下游管线从不依赖派生方式**。

- 所有证明（shuffle Bayer-Groth、reveal token DLEQ、fold 剥层、pk
  ownership proof）输入都是 `(sk, pk)` 数对，与 sk 怎么来的无关；
- 服务器一切索引按 pk_hex 字符串（SEAT_WALLETS 在 SIT_DOWN 时由会话
  注册 pk→wallet，`verify_socket_sender`、reveal 编排守卫同理）；
- `from_sk` 恢复路径（`WasmClientPlayer.from_sk`，PlayerContext.tsx:134）
  早已是生产路径——reload 后的玩家用的就是"服务器不知道派生来源"的钥匙；
- 客户端 endorsement 密钥（endorsementClient.ts）已经是"随机生成 +
  localStorage 持久化"模式并稳定运行，即本 Part 要复制到游戏密钥上的
  全部机制。

结论：把生成点从 `new_with_wallet_address` 换成随机，是**纯密钥来源
替换**，不触碰任何已调稳的密码学路径。

## B1. 设计：随机会话密钥（一次生成、本地持久、坐下可轮换）

```
现状:  pk = H(wallet)·G                ← 公开可计算，钱包指纹
目标:  sk ← CSPRNG（wasm OsRng）       ← 无任何派生关系
        pk = sk·G
        localStorage: {sk, pk}         ← 已有存储路径（setSk/setPk）
        reload: from_sk 恢复            ← 已有路径，不动
```

**改动清单（全部是小切面）**：

1. `client-wasm/src/lib.rs`：`WasmClientPlayer` 增加两个导出：
   `new_random()`（包 `ClientPlayer::new()`）与
   `new_with_passphrase(pass)`（B1.5 的 KDF 构造），各约 5 行。
   **不改任何现有导出**——`new_with_wallet_address` 保留为兼容回退。
2. `PlayerContext.tsx`：生成点（:122、:196 及首次逻辑）按 `keyMode`
   分发：默认 `new_random()`，口令模式走 `new_with_passphrase`；
   存储与恢复逻辑（setSk/setPk、from_sk、restoreSession）**逐字不动**。
   能力探测照 endorsement 的模式：`typeof new_random === 'function'`
   不满足时回退旧派生（旧 wasm pkg 在跑也不破坏牌局），迁移完成后删
   回退。
3. `dev_bot.rs:119`：bot 改 `ClientPlayer::new()`（随机），与客户端
   行为对齐；bot 无需确定性。
4. `poker_protocol`：零改动（`new()`/`new_with_sk_hex()` 已存在）。

**轮换策略**：

- v1（随本方案落地）：每 (浏览器, 钱包) 一把随机钥匙，localStorage
  持久。已消除钱包链接与跨钱包追踪；同会话内跨手同一 pk 仍在（协议
  需要：跨手 reveal/fold 义务、aggregate deck 连续性——不动它）。
- v1.5（可选增强）：**入座时轮换**（SIT_DOWN 前生成新钥匙，此刻对该
  桌无未决义务，是协议安全点）。代价是同时多桌需多把钥匙，UI 要管理；
  不作为 v1 交付。

**密钥丢失语义（唯一真实回归，必须写明）**：

- 现状：清掉 localStorage → 密钥按钱包重派生 → pk 不变 → "恢复"。
- 改后：清掉 localStorage → 新随机 pk → 旧 pk 的义务（该手 reveal/
  fold）无法履行 → 走**已有的**服务器超时/踢出/reconstruct 路径（无
  挂死，降级干净）。这等价于"换设备且无备份"的今天行为。
- 缓解：sk 已在 localStorage；**B1.5 的口令派生模式把"可恢复"变成
  用户可选**；后续可加钱包级恢复体系（STRK20 viewing-key 等）做
  备份（列为 future work，不阻塞 v1）。

## B1.5 口令派生密钥（用户可选的"可恢复身份"）

> 需求：用户可在前端设置一个**派生口令字符串**；只要记住口令，就能在
> 任何设备上重新派生出**同一个 pk**（牌桌身份不变），兼顾 Part B 的
> 隐私（与钱包零派生关系）与可恢复性（不再依赖 localStorage）。
>
> 形态：pk = KDF(用户口令)，KDF 参数全域固定 —— 口令即身份备份。

### B1.5.1 密码学设计

```
sk = KDF(passphrase):
      x0  = utf8("zgame:player-key:v1:" || passphrase)
      xi  = 32B-BE( hash_to_scalar(x(i-1)) )      // 迭代 KDF，抗离线爆破
      sk  = hash_to_scalar(xN)                     // N = 20_000（见下）
```

关键决策与理由：

1. **归约必须在 Rust 侧**。`from_sk` 要求 canonical scalar
   （`convert.rs:22` 直接拒绝非规范编码），而 curve 依赖 feature
   （client-wasm 现为默认 `legacy-bls381`，Plan D 全量切换后为
   `stark-curve`，两条曲线群阶不同）。`Curve::hash_to_scalar` 在两个
   后端都**内部 mod 群阶**（stark: `reduce_mod_n`；legacy:
   `from_bytes_mod_order_wide`），因此派生放 wasm 里天然合法且
   build-agnostic；放 JS 侧则要在前端硬编码曲线阶并跟随 feature 切换
   ——绝对不这么做。
2. **迭代次数写进域名，一经发布冻结**。KDF 参数（label "v1" + N + 曲线
   实现）任何一项变化都会让所有口令用户换身份。迭代次数只在带新版本
   号（"v2"）时才允许改，且 v1 永久保留兼容。N 定 20_000：stark 后端
   每次 `hash_to_scalar` 是一次 Poseidon，20k 次 ≈ 百毫秒级（发布前
   实测定标，legacy 后端 SHA 链更快）；口令强度是主防线，KDF 是减速带。
3. **低熵口令的离线爆破风险如实披露**：任何拿到 pk 的人（对手、日志
   泄露）可离线试候选口令。UI 必须给强度提示（建议 ≥12 字符/助记词组
   合），文档写明"口令强度 = 身份安全强度"。
4. **口令永不出浏览器**：与 endorsement sk 同等地位——只在本地派生
   sk；localStorage 只缓存派生结果 sk/pk 与模式标记，**不存口令本身**。

### B1.5.2 改动清单

| 层 | 改动 | 说明 |
| --- | --- | --- |
| client-wasm | 新增导出 `WasmClientPlayer.new_with_passphrase(pass: &str)` | 形状完全照 `new_with_wallet_address`（client.rs:36 的三行构造），仅 sk 来源换成上面的 KDF。其余导出一概不动 |
| 前端 | 新增 `keyDerivation` 模块调用之 + `PlayerStorage` 增加 `poker.keyMode`（`"random"` \| `"passphrase"` \| `"legacy"`） | 不存口令；`from_sk` 存储恢复路径照旧 |
| 前端 UI | 用户菜单新增「牌桌身份密钥」面板（见下） | 入口：Navbar 汉堡菜单（NavMenu.tsx）或用户下拉，随现有风格 |
| poker_protocol | 零改动（KDF 由 `hash_to_scalar` 组合而成） | |
| 服务器 | 零改动（pk 仍是普通 EC 点） | |

### B1.5.3 前端 UI（「牌桌身份密钥」面板）

```
牌桌身份密钥
当前模式：● 随机（本设备）   ○ 口令派生（可跨设备恢复）

[ 设置恢复口令 ]   [ 通过口令恢复身份 ]   [ 切换为随机密钥 ]

当前牌桌身份 pk：0xab3b…dc6c（复制）
```

三个动作的流程与守卫：

1. **设置恢复口令**（random/passphrase → 新 passphrase 身份）：
   输入 + 确认两次 + 强度提示（<12 字符弱提醒）。**警告文案**：
   "口令即你的牌桌身份。忘记口令 = 该身份永久丢失，无法找回。
   ⚠️ 不要使用钱包助记词/Ready 恢复短语作为口令（避免把钱包种子
   引入新的暴露面）。" 确认后：`new_with_passphrase` 派生 → 写
   sk/pk/keyMode → 提示"身份已切换，pk 已更新"。
2. **通过口令恢复身份**（新设备 / 清存储后）：输入口令 → 派生 →
   展示派生出的 pk 前缀请用户确认（防输错口令静默换身份）→ 确认后
   覆盖本地 sk/pk。**在座（seated）时禁用或强警告**：切换身份会使当前
   座位的 reveal/fold 义务失效（走已有超时/踢出路径），建议牌局间歇
   操作。
3. **切换为随机密钥**：`new_random()`（B1 的导出）→ 明确提示放弃可
   恢复性。

模式迁移：已有 localStorage sk 的存量用户默认标 `legacy`/`random` 并
照旧使用，不强制换钥；面板主动引导升级到 passphrase 模式。

### B1.5.4 三种模式对照（写进 UI 帮助文案）

| 模式 | pk 来源 | 跨设备恢复 | 抗对手链接 | 丢钥后果 |
| --- | --- | --- | --- | --- |
| 旧版钱包派生（存量） | H(钱包地址) | ✅（随时可重算，但公开可计算） | ❌ 无 | — |
| 随机（默认） | CSPRNG | ❌ | ✅ | 新身份 + 超时降级 |
| 口令派生（本节） | KDF(口令) | ✅（凭口令） | ✅（口令是秘密） | 忘记口令=身份永久丢失 |

## B2. 隐藏 vs 可见（密钥层）

| 项 | 现状 | 改后 |
| --- | --- | --- |
| pk ↔ 钱包链接（对手视角） | 可计算（pk=H(wallet)·G） | **切断**（随机 sk） |
| 跨桌/跨局同一玩家追踪 | 可（pk 恒定且=钱包指纹） | v1 同会话内仍可（同 pk）；跨会话/清存储后不可；v1.5 入座轮换后桌间不可 |
| 服务器知 pk↔wallet | 知（SIT_DOWN 会话注册） | 仍知（发牌/裁决角色必需，见信任边界） |
| ElGamal pk 上链 | 不上（全为承诺）；p_batch 上的是 endorsement pk（已随机） | 同左；且未来任何上链物不再携带钱包派生值 |
| localStorage 丢失后的恢复 | 密钥可从钱包重派生 | 随机模式：不可（新身份 + 已有超时降级路径）；口令模式（B1.5）：**凭口令跨设备恢复同一 pk** |

## B3. 信任边界（密钥层增量）

| 角色 | 现状可见 | 改后可见 |
| --- | --- | --- |
| 对手玩家 | 我的 pk + 我的钱包（可计算） | 仅我的（随机）pk |
| 游戏服务器 | pk↔wallet（会话内） | 同左——**服务器是发牌与裁决者，必然知道**；诚实披露，隐私主张限定为"对手与链上观察者不可链接" |
| 链上观察者 | 无 pk（只有承诺）；钱包派生意味着潜在固化风险 | 无 pk 且无派生关系（风险消除） |
| STRK20 池 | 与游戏 pk 无关 | 同左 |

## B4. 回归与验收清单（管线调过很久，逐项过）

密钥来源替换本身不触碰证明代码，但按"动了密钥就全量回归"执行：

- [ ] `cargo test -p poker_protocol`（client 轮次/证明往返）；
- [ ] `cargo test -p texas --bin texas`（full_hand / e2e_starknet 全套）；
- [ ] client-wasm 重构建后浏览器冒烟（全新 profile，无 localStorage）：
      keygen → SIT_DOWN → 洗牌 → reveal → 下注 → 完整一手到结算；
- [ ] **reload 恢复**：牌局中刷新 → from_sk 恢复 → reveal/reconstruct 继续
      （此路径今日已存在，验证未被波及）；
- [ ] **丢钥降级**：牌局中清 localStorage → 新 pk → 旧座位超时/踢出/
      reconstruct 正常走完，无挂死（这是新语义的验收点）；
- [ ] 钱包切换：再生效仍触发、生成走 new_random；
- [ ] 双浏览器双账号整手对局（配合前述钱包账号切换修复）；
- [ ] **口令模式（B1.5）确定性**：同一口令在两个浏览器/设备派生出相同
      pk hex（`get_pk_hex` 逐字节一致）；
- [ ] **口令恢复流**：设备 A 设口令打牌 → 设备 B（全新 profile）通过
      口令恢复 → pk 相同 → 以同一身份入座；
- [ ] **口令切换守卫**：在座时设置/恢复口令有禁用或强警告；牌局间歇
      切换后旧座位走超时路径不挂死；
- [ ] **KDF 定标**：wasm 内 20_000 次迭代实测耗时记录在案（stark 与
      legacy 两个 feature 各测一次），显著变慢（>2s）才调整 N 并升
      版本号；
- [ ] **口令不出境**：Network 面板确认口令字符串从未出现在任何请求；
      localStorage 只见 sk/pk/keyMode；
- [ ] 旧 wasm pkg 回退：无 new_random 导出时回退派生并打日志（迁移期
      行为），迁移完成后删除回退与 `new_with_wallet_address` 客户端
      调用（协议库函数保留，供测试）。

## B5. 与 Part A 的拼装（完整闭环）

```
钱包 W ──shield──▶ [STRK20 池]（FPI 门口筛查）                ← 边缘公开
        └─(池内 privacy_invoke)─▶ vault 记账（不逐手变动）
牌桌身份: 随机 ElGamal pk（Part B）——对手/链上不可链接到 W
结算:    承诺 + pot 托管（Part A）——链上无 players/deltas/pk
认领:    池内 privacy_claim → open note（owner 隐藏）
出金:    privacy_withdraw / withdraw —— 边缘公开但不可链接
```

对外一句话（更新 §8）：
*The cards are encrypted, the players are unlinkable, the winners are
invisible — commitments on-chain, payouts as STRK20 notes.*

---

# Part C — 钱包架构与 Ready Wallet 角色分工（gas / 买入 / 领取）

> 结论先行（2026-09 更新：Cartridge 已整体移除，Ready 为唯一钱包）：
> 1. **免 gas**：免的是"用户的 gas"，实际付费方按策略路由——买入关键
>    路径由**项目方 paymaster 赞助**（白名单+限额+频控），不做用户账户
>    无差别免 gas；
> 2. **买入**：是，用连接钱包（Ready）做资金源；approve/deposit 由
>    钱包逐笔弹窗确认（Cartridge 时代的 session-key 预授权免弹窗随其
>    移除而取消），paymaster 主路径下签名仍留在客户端；
> 3. **领取**：用户判断正确——game session key 领取不合理，改为
>    **钱包原生的 STRK20 note 领取**（viewing key 由钱包托管、钱包
>    自带恢复，密钥丢失在钱包层解决）；Ready 本就是 Wallet API 的
>    官方测试基线（C3.3 双路径仍保留能力探测）。
>
> 文档依据：STRK20 Wallet API（strk20-by-example.org，快照
> 2026-08，上线前复核版本）。

## C0. 现状盘点（代码事实）

- `client/src/context/Providers.tsx`：connector **只挂注入钱包**
  （`argentX`/`ready` 两个注入 id，覆盖 Ready 改版前后）；登录验证、
  买入扣款、swap、私密领取全部走连接的 Ready 账户，dev 直签账户仅作
  无钱包时兜底。
- **Cartridge 已整体移除**（历史：曾以 Controller 为唯一 connector，
  session policy 预授权 approve/deposit、feeSource=CREDITS；因
  #controller 覆盖层拦截全页点击、买入后强制弹初始化窗、与登录账户
  混淆而移除，见 `Providers.tsx` 注释）。`client/src/starknet/cartridge.ts`
  现为无引用的死代码（待删除），`@cartridge/*` 依赖待从 package.json
  清理。
- `client/src/starknet/paymaster.ts`（Plan C）：服务端
  `/api/starknet/paymaster` 中继（x-api-key 留服务端），OutsideExecution
  把"交易发送者"与用户解耦，失败回退连接钱包直签。
- 买入私密路径（Plan B）：shield（公开边）→ 池内 `privacy_invoke` →
  vault 记账（`poker_vault_anonymizer.cairo` 已实现并有测试）。

## C1. 免 gas 的账户语义（用户账户 vs 项目方账户）

先澄清语义：paymaster 不会"给用户账户充 gas"，而是**替某笔来自用户账
户的交易付 gas**。所以问题实为"每一类交易由谁付费"，按类路由：

| 交易类 | 提交/付费方 | 依据 |
| --- | --- | --- |
| 买入路径（token approve、vault deposit/withdraw、swap） | **项目方 paymaster 赞助**（现 paymaster.ts 中继 + feeMode=sponsored），策略白名单 + maxFee 上限 + 频控 | 获客关键路径、entrypoint 可枚举、成本可预算；回退 = 连接钱包（Ready）自付 gas 直签 |
| 用户自发的其它钱包交易 | 用户（credits / 自持 gas token） | 无差别赞助 = 滥用面（griefing），不提供 |
| 池内私密交易（shield/claim/transfer/unshield） | **relayer 提交**（链上 sender=relayer，所有用户同一发送者）；gas 由钱包流程赞助 | STRK20 文档：wallet 流程赞助 gas 但**不赞助 flat 池费** |
| 池费（flat，读 `get_fee_amount`，勿硬编码） | 被屏蔽余额内扣除 | 赞助方赔付发放的池费由运营方浮存承担（C3.2）；用户自己后续花费的池费由用户 note 余额承担，UI 需提示 |
| 运营方 payout 批量（C3.2 服务端 SDK 私密转账） | 项目方（relayer + 池费从运营浮存） | 运营成本，批量+延迟抖动摊薄 |

推荐组合：**买入路径项目赞助 + 私密交易 relayer/钱包赞助 + 池费各自
承担**。这也是现有代码的形态（paymaster.ts 中继 + CREDITS 回退），只需
把赞助范围明确限制在买入 entrypoint 白名单并加上限指标。

## C2. 买入 = 用连接钱包（是）

资金源必须是用户的钱包账户（Ready；钱是他的）；游戏密钥（Part B 的
ElGamal）**永远不碰资金**——它只是牌桌身份。两条买入路径都以钱包为源：

- 公开路径：钱包 → approve + deposit（钱包逐笔弹窗确认；paymaster
  主路径下 typed-data 签名留在客户端，交易由 paymaster 账户提交）。
- 私密路径（Plan B）：钱包 → shield（公开边，FPI 筛查）→ 池内
  `privacy_invoke` → vault 记账；钱包只需 approve 池的入口，后续在池内
  证明交易中完成，弹窗次数不增加（shield 本身是 approve+deposit 两步，
  UI 按 Wallet API 文档明确标注两步，避免被当成重复弹窗 bug）。

## C3. 领取改为钱包原生 STRK20 note（取代 Part A 的 payout_sk 设计）

### C3.1 为什么原设计要改

Part A 原设计：客户端本地铸 `payout_sk`，经自建 helper `privacy_claim`
认领。两个问题：

1. **密钥丢失**：payout_sk 是又一把裸 localStorage 密钥，重蹈 B1.5 讨
   论过的覆辙；
2. **授权面**：池的 `InvokeExternal` calldata 是随交易公开提交的——
   明文 secret 放 calldata 会被抢跑（复制 calldata 换自己的 note_id 即
   可盗领）。要堵这个洞需要"目的地绑定票据"等额外机制，复杂度不划算。

### C3.2 新设计：运营方私密转账，赢家钱包原生花费

```
结算(settle) ──▶ 结算合约只发布承诺（Part A 不变：无 players/deltas/pk）
     │
     └─(服务端, STRK20 Privacy SDK, 运营方自持池密钥)
        运营浮存（一次性大额 shield，打破逐手时间关联）
        ── 池内私密转账 ──▶ 赢家 viewing key 的加密 note（owner 隐藏）
                                │
赢家侧"领取" = 标准钱包花费（unshield / 池内 transfer）——
viewing key 与 note 由钱包托管，relayer 提交，链上不见赢家
```

- 运营方侧：服务器跑 SDK（后端自持密钥路线），把每手赔付从浮存以
  **加密 note** 发进赢家 channel。链上可见的只有：运营方某时屏蔽了一
  笔（批量+随机延迟弱化关联）、某 note 后来被花掉。
- 赢家侧：**没有任何"认领交易"**——钱已经私密地在他的 channel 里，
  花费（unshield/transfer）是钱包原生操作。`SettlementPayoutAnonymizer`
  helper 与 claim_cms 机制**整体取消**；`payout_sk` 取消。
- 前提：赢家注册过 viewing key（钱包首次使用时自动注册；App 在首次买
  入时引导"启用私密赔付"）。注册事件公开——但那只说明"该钱包用
  STRK20"，不绑定任何牌局（运营方 shield 不点名收款人）。
- 服务端成本：Stwo 证明（文档口径 ~29s/12 核，批量摊销；2026-09 更新：递归
  路线线上实测 **15–17s/手**，含 Cairo 编译，异步不阻塞对局——
  `texas/src/starknet/recursion_prover.rs`）+ 每笔 flat
  池费（从浮存扣，赔付前查 `get_fee_amount`）。

> **状态（2026-09-03）**：需求前提已按 strk20-by-example.org 官方文档复核——
> 「用户必须主动领取」不是 STRK20 属性（接收为推送制：扫描即得可花费余额，
> 无认领交易；详见 `../TODO.md` #12 引证）。「赢家认领」是当前 vault 筹码
> escrow 架构的产物，且粒度为每次出金而非每手。C3.2 协议层可行但**整体推迟**：
> SDK 未上 npm + v2 escrow 底座未修复前 sidecar 无消费方；现行赢家自主私密
> 领取（两动作）继续作为主路径，`privacy_withdraw` 并存（C3.4）。

### C3.3 现实门槛与双路径（必须做能力检测）

当前唯一钱包 **Ready 就是 Wallet API 0.10.3 的官方测试基线**
（privacy-enabled；Xverse 等进行中）——路径 W 对 Ready 用户是默认形态。
能力探测仍保留（其它注入钱包/旧版本存在），运行时用
`supportedWalletApi(wallet) >= 0.10.3` 探测（版本查询，**不要**用
`strk20Balances` 之类数据调用做探测——会触发钱包授权弹窗）：

- **路径 W（钱包原生，首选）**：连接钱包支持 Wallet API → viewing
  key、note 发现、证明、提交全部由钱包托管（Ready 钱包，钱包自带
  恢复）——**密钥丢失问题在钱包层消失**。
- **路径 S（App 内嵌 SDK，当下可用）**：钱包不支持 → App 用 STRK20
  Privacy SDK 自管 viewing key。托管回到 localStorage，因此 **viewing
  key 的生成并入 B1.5 口令派生**（域名
  `"zgame:strk20-viewing:v1"`）：
  一句口令同时恢复三个密钥（牌桌 ElGamal、池 viewing key、DAPV
  endorsement sk —— 第三个同样并入口令域
  `"zgame:endorsement:v1"`），备份语义统一。
- starknet.js 基线：STRK20 需 ≥10.4.0（仓库现 ~10.0.2，升级是独立
  任务）；升级前先跑版本矩阵再动接线。

### C3.4 Part A 相应修订

- §1 图与 Phase 1 第 3/5 条中的 `SettlementPayoutAnonymizer.privacy_claim`
  / `payout_sk` / claim_cms 认领流程**由 C3.2 取代**；
- 结算腿（承诺 + escrow + Phase 2 ZK 消 players/deltas）**不变**；
  escrow 的出向改为"运营方 shield + 私密转账"（escrow → 运营浮存的
  划转在结算合约内完成，公开可见但不点名）；
- `poker_vault_anonymizer.cairo` 的 `privacy_withdraw`（burn_chips 出
  金）保留，作为"赢家未启用法币化路径"时的自主出金方式，与 C3.2 并存。

## C4. 调整后的密钥/钱包分工总表

| 职责 | 密钥/账户 | 托管 | 丢失恢复 |
| --- | --- | --- | --- |
| 登录身份 + 买入资金 + gas | Ready 钱包账户（连接钱包） | 浏览器插件钱包 | 钱包恢复机制（助记等） |
| 池内 note 与赔付（路径 W） | STRK20 viewing key | 钱包（Ready） | 钱包恢复 ✓ |
| 池内 note 与赔付（路径 S） | STRK20 viewing key | App（SDK）+ localStorage | B1.5 口令（`strk20-viewing:v1` 域） |
| 牌桌身份（ElGamal） | 随机 / 口令派生（Part B） | localStorage | B1.5 口令（`player-key:v1` 域） |
| DAPV endorsement | 随机（现状）→ 并入口令域 | localStorage（现状） | `endorsement:v1` 域（升级项） |
| 运营方 payout 批量 | 运营方池密钥（SDK） | 服务器 KMS/密钥管理 | 运营方流程（备份+轮换，单独文档） |

原则：**资金身份跟钱包（钱包自带恢复），牌桌身份跟口令（B1.5），
二者永远解耦**——钱包不知道牌桌 pk，牌局观察者不知道钱包。

## C5. 落地与验证清单

- [ ] 能力探测：`supportedWalletApi` 版本查询 ≥0.10.3 → 路径 W，否则
      路径 S；探测失败按 S 处理并 UI 提示；
- [ ] starknet.js 升级 10.4.0+ 的版本矩阵（@starknet-react/starknetkit
      兼容性核对）——独立任务先行；
- [ ] 服务端 SDK 浮存流程：shield 一次 → 私密转账到赢家 vpk →
      `strk20PrepareInvoke`/dry-run 验证 calldata 形状；
- [ ] 池费不硬编码：`get_fee_amount` 运行时读取；赔付额 ≥ 池费的边界
      处理（不足池费的小赔付并入下次/累积到阈值再发）；
- [ ] viewing key 注册引导 UX（首次买入时"启用私密赔付"），注册前
      fallback：vault 记账 + privacy_withdraw 自主出金（现状）；
- [ ] B1.5 口令域扩展两个新域（viewing/endorsement），UI 帮助文案
      更新为"一句口令恢复全部游戏身份"；
- [ ] 时间关联缓解：运营浮存批量 shield + 赔付随机延迟（写进运营手册）；
- [ ] 钱包 STRK20 支持状态跟踪（Ready 为 0.10.3 官方基线已支持；
      Xverse 等进行中），新隐私钱包一旦可用即可加入路径 W 选项（note
      所有权 = viewing key，路径 S→W 迁移 = 把 vpk 导入钱包？
      **不可行——SK 不该离开生成处**；正确迁移 = 花掉旧 note 到新
      viewing key，写明"迁移即花费"）。

---

# 实现状态（2026-09-01 更新）

## ✅ 已落地（本轮）

| 项 | 位置 | 说明 |
| --- | --- | --- |
| Ready 钱包接入（唯一） | `client/src/context/Providers.tsx` + `LoginModal.tsx` | Ready（argentX/ready 两个注入 id）为唯一钱包：登录验证、买入扣款、swap、私密领取全部走 Ready；LoginModal 按 `available()` 过滤。**Cartridge 已整体移除**（覆盖层拦截点击/买入后强制弹窗/账户混淆，见 Providers.tsx 注释；cartridge.ts 成死代码待删）。重连 `lastUsedConnector`——首次在 Sign In 弹窗点一次 Ready，之后自动连 Ready |
| starknet.js ≥10.4 | `client/package.json` → 10.6.8 | STRK20 Wallet API（`strk20InvokeTransaction`/`STRK20_ACTION`/`WalletAccountV6`）就位 |
| 登录验证走连接钱包 | `client/src/hooks/useAuth.ts` | 连接的 Ready 账户签名 typed data；dev 直签仅兜底 |
| swap 兑换走连接钱包 | `client/src/starknet/starknetGameActions.ts` | `account ?? devSigner`，Ready 连接时用 Ready 签名 |
| 私密领取（领取奖励） | `client/src/starknet/strk20.ts` + `components/modals/ClaimRewardsModal.tsx` + Navbar「↓ 领取」 | 能力探测（版本查询 ≥0.10.3，绝不用数据调用探测）+ 两动作私密领取（transfer OPEN + privacy_withdraw，`${openNoteIds[0]}` 占位）+ 公开出金回退 + 池内余额展示 |
| Part B 随机密钥 | `poker_protocol/.../client.rs` + `client-wasm` `new_random` + `PlayerContext.generateRandomKeys` + dev_bot | 默认 CSPRNG，与钱包零派生关系；旧 pkg 自动回退 legacy |
| Part B1.5 口令派生 | `ClientPlayer::new_with_passphrase`（KDF v1 域名 + 20_000 迭代，4 个确定性单测）+ wasm `new_with_passphrase` + `PlayerKeyPanel`（NavMenu） | 一句口令跨设备恢复同一 pk；keyMode 存 `poker.keyMode` |
| wasm pkg 重建 | `client-wasm/pkg`（wasm32 release，CC=brew llvm） | 新导出进入客户端 bundle（vite build 绿） |
| PokerVaultAnonymizer 部署 | Sepolia `0x0462b57b...022e`（class 0x5ec1eef...，tx 0x44d04bae...） | 构造 (vault=0x6c8ac4...1321, pool=STRK20 Sepolia 池 0x254a6b...d91)；vault()/pool() 视图已验证；`vault.set_authorized_helper` 已授权（storage 读回确认）；`privacy_withdraw` 守卫（caller is not the pool）实测生效 |
| 客户端配置 | `client/.env.development` | `VITE_POKER_VAULT_ANONYMIZER_ADDRESS` + `VITE_STRK20_POOL_ADDRESS` 已配置，vite 已重启生效；`strk20.json` 已记录部署 |
| 端到端环境 | server（新二进制）+ vite:5174 + bot（0xba7f00d1，1000 筹码已入座） | 浏览器验证（Cartridge 移除前记录，时用 Cartridge 账户 0x0621...）：登录 → 进桌 → 买入弹窗（vault 筹码/汇率正确）；Ready 实机端到端见 C5 待办 |

## ⏳ 待办（按计划分阶段）

- Part A Phase 1 合约 ✅ 已完成并部署 Sepolia（2026-09-01）：vault v2 `0x3e73e6...e25f`（register_payout_commitment / settlement_fund_escrow，settlement 门控）；dual v2 `0x283008...98e4`（verify_and_settle_dapv_stark_private：认领承诺 cm=poseidon(commitment,hand_binding,amount) + escrow 划转 + 输家公开扣款残余 + consume_claim 单次门控）；SettlementPayoutAnonymizer（新，`0x4642cc...c1d5`）：privacy_claim 承诺原像验证 + escrow 支付 + Span<OpenNoteDeposit>。snforge 新增 10 测试全过（68/68），既有 dual 编译器崩溃模块已门控 dual_legacy_tests。配置同步：texas/.env（vault/dual v2 + STARKNET_SETTLE_PRIVATE=true + CLAIM_HELPER）与 client env（vault v2 + anonymizer v2 `0x600dd1...1db1`）完成；服务端赢家承诺齐备自动走私有入口、缺注册回退 legacy 不卡结算；客户端 ensurePayoutCommitment + 领取弹窗一键注册已接入。
  **实机对局验证（2026-09-01）**：三方对局（双 bot + operator），register/settle 连续上链全部 SUCCEEDED；`STARKNET_SETTLE_PRIVATE=true` 下未注册 payout commitment 的对局由 winners_registered 预检自动回退 legacy 入口，不卡结算；dev 联调钱包认可托管（`STARKNET_DEV_ENDORSEMENT_WALLETS`）补齐三方对局认可（生产不配置）。
  **私有结算入口已真实触发 ✅**：operator（已注册 payout commitment）赢手后，settle tx `0x13f9f319...196` 使用 `verify_and_settle_dapv_stark_private` 选择器，SUCCEEDED；回执含 `DualProofSettledPrivate` 事件 + vault EscrowFunded + ERC20 转账——赢家派奖进认领托管、输家公开扣款，全部按 Phase 1 设计执行。
- Part A Phase 2：Stwo 电路消 `(players, deltas)` 明文；
- Part C3.2 服务端：STRK20 Privacy SDK 运营浮存 + 赔付私密转账（需 SDK 依赖 + 服务器 KMS）；
- C5 清单：Ready 实机端到端（登录→买入→对局→私密领取）、starknet-react/starknetkit 与 10.6.8 的兼容矩阵、池费 `get_fee_amount` 运行时读取。

> 迁移期语义：存量 localStorage 密钥照旧可用（legacy 模式）；新密钥一律随机或口令派生。

## 实机端到端剩余一步（需人工点击）

钱包内的交易确认弹窗无法由脚本合成点击（安全设计使然）。人工完成（约 2 分钟）：

1. 打开 http://localhost:5174 → Sign In 选择 Ready 钱包；
2. Join a Table → JOIN TABLE → 空位 Sit Down → 买入弹窗确认（默认 1000 筹码）；
3. Ready 钱包对 approve/deposit 逐笔确认（Cartridge 时代的 session-key 免弹窗已随其移除取消）；
4. 打完一手（bot-2 已在座自动跟注/过牌）；
5. Navbar「↓ 领取」→ 私密领取（Ready 支持 STRK20 Wallet API ≥0.10.3，走两动作私密领取；旧钱包不支持时按钮按设计禁用，可用公开出金回退）。

## 房间围观者状态同步修复（2026-09-01 ✅ 已验证）

**问题**：中途进桌的围观者看不到公共牌（公共牌仅由 COMMUNITY_REVEAL_RESULT 事件驱动，进桌前错过的不会补）、winMessage 不更新、上一手亮牌不清理。

**修复**（`useGameSocket.ts` TABLE_UPDATED / TABLE_JOINED 处理器）：
- 公共牌以服务器 board 快照为准同步（错过 reveal 事件的围观者由此补上）；
- `handOver` 时清空已亮手牌（围观者不再看到上一手残影）；
- winMessage 保持显示直到新一手开始（waiting 之后的新手牌清空）；
- TABLE_JOINED 首次快照同样同步公共牌。

**验证**：IAB 围观者中途进桌，flop 阶段即可看到全部 5 张公共牌与消息流（截图确认）。

## 开发排期（Phase 2 / C3.2）

| 阶段 | 里程碑 | 内容 | 验收 |
| --- | --- | --- | --- |
| C3.2-M1 | 认领 sidecar | Node sidecar 封装 STRK20 私密转账（operator 浮存 → 赢家 vpk note），Rust 服务端 HTTP 调用 | sidecar 单测 + sepolia 转账成功 |
| C3.2-M2 | 赔付路由 | settle 后异步队列：延迟抖动 + 批量 shield 补浮存 + 失败重试 | 三方对局 10 手赔付全部私密到账 |
| C3.2-M3 | 通知与 UX | 加密赔付通知推送赢家客户端 + 领取入口 UX | 赢家无需任何额外操作即可看到 note |
| C3.2-M4 | 合规加固 | 限额/频控/审计日志 + 演练 | 运营手册成文 |
| P2-M1 | 电路规格 | 知识证明 (players, deltas)：digest 匹配 ∧ 零-sum ∧ 人数约束；Stwo component 骨架。**预留约束**：动作签名 + auto 默认动作合法性 + accepted-seq（见 ACTION_SIGNING_CENSORSHIP_RESISTANCE.md §8.2） | 电路单测通过 |

### P2-M1 电路规格（已定稿，开发即按此实施）

**语句（公开输入）**：`hand_binding, hand_id, registered_digest, n_participants`
** witness（私密）**：`players[8], deltas[8]`（i128 → (sign, |delta| u64) 对）

**约束（全为 Poseidon/算术，无 EC 运算）**：
1. `poseidon_hash_span([hand_id] ++ Σ(player, sign, |delta|)
   ++ [action_log_digest]) == registered_digest`——与合约
   `compute_settlement_digest` 及 Rust `submit.rs` 逐字段一致（尾词为
   #18 Phase B 接线的动作日志哈希）；
2. `Σ sign·|delta| == 0`（零和）；
3. `n_participants == registered_count`（expected buckets 沿用现约定）；
4. 每赢家派生认领承诺：`cm_i = poseidon(commitment_i, hand_binding, amount_i)`
   ——输出列表即 Phase 1 的 `claim_cms`（电路保证托管与承诺同源）。

** trace 布局**：每参与者一行 ×3 列（player_felt, sign, |delta|）+ 常数行；
Poseidon 用 Stwo 内置 component（16 列×8 行/轮，20_000 轮量级远低于池电路）。

**集成点**：证明由 server 生成（复用 orchestrator 的 prover 管线）；
合约 `verify_and_settle_dapv_stark_private_v2` 以 Stwo verifier（官方 Cairo
verifier 移植或 fact-registry 模式二选一，M3 定）替换明文 digest 断言。
| P2-M2 | 证明端 | server 从明文生成 trace + proof（复用 orchestrator）+ **动作级 SK 签名纳入动作日志**（见 `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`） | 真实手牌证明生成 < 30s |
| P2-M3 | 合约验证端 | Stwo Cairo verifier（官方 verifier 移植或 fact-registry）+ `verify_and_settle_dapv_stark_private_v2` 接入 π | calldata 零明文 |
| P2-M4 | 联调部署 | sepolia 部署 + gas/size 测量 + 文档 | 演示手牌零明文结算 |

