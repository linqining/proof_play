# Poker 合约部署清单

> ⚡ **下一次主网部署的执行手册：[MAINNET_RUNBOOK.md](MAINNET_RUNBOOK.md)**
> （2026-09-19 整理：现状盘点、P1-2 类漂移说明、一键脚本
> `scripts/deploy_mainnet_v6.sh`、切换/验证/迁移/回退与开放门槛）。
>
> ⚠️⚠️ **高隐蔽性前置（2026-09-19 主网实测踩坑）**：SNIP-36 v3 / proved / private
> 等一切**隐私结算入口**要求"所有正 delta 地址"都注册 payout commitment——
> **包括 treasury（抽水接收方）**：rake 是正 delta，会被当作赢家校验。
> 漏注册 treasury 的症状极其隐蔽：每手仅一条
> `[settlement-private] request build failed (non-fatal): winner 0x<treasury> has no payout commitment`
> WARN，随后**自动回退公开线性结算、玩家侧一切正常**——私密腿静默失效。
> **已执行**：给主网 treasury/operator `0x412e4d43…` 注册了**测试占位
> commitment `0x7e57c0de7e57c0de`**（TX `0x46e3778e…`）——该占位无已知
> preimage，其名下 escrow 的抽水**无法私密领取**；生产修复=钱包内用正式
> secret 重新 `register_payout_commitment` 覆盖（latest-wins）。
> 玩家侧：`0x00cbd16d…` / `0x05eb38f6…` 已注册真 commitment（UI Claim 弹窗）。
> **2026-09-19 SNIP-36 首次在线实测**：接线后首次真实结算（hand 1789786774）
> 走到 `register_hand`（tx `0x545dddc8…`）→ prover 接受请求形状并开始出证
> （`Starting transaction proving`）→ **证明期 ~40s 进程内存死亡** → 自动回退
> 公开线性（tx `0x18a1e38a…` SUCCEEDED，departed-released=2）。结论：链路
> 代码正确，瓶颈 = **transaction-prover 证明期内存超出 7.3GB 主机**（需升配
> 16G 或独立主机）。入口已暂回 **v2**（2026-09-19），重新启用清单见
> MAINNET_RUNBOOK.md 开放门槛表。
>
> ✅ **2026-09-19 主网 v6 批次已执行**（`deploy_mainnet_v6.sh`，deployer
> 204.81 STRK 起跑）：declare×4（类与 sepolia 同哈希：vault `0x6de64f9a…` /
> anonymizer `0x6dbb1f82…` / dual v6 `0x255cafe3…` / registry `0x7cc910b5…`）
> → 新 vault `0x3821e794…e2502`、新 anonymizer `0x6149b13d…000d0`、
> 新 dual v6 实例 `0x268df800…40a57`（绑新 vault）、registry
> `0x234b4dfc…7a62b`（table_count 0）；接线 7 笔全 SUCCEEDED，回读核验 ✓
> （`session_tx_pk` 入口在、token=canonical STRK、claim_helper=payout、
> 两个 program hash + 虚拟 OS 占位 `0x602b02cf…`）。服务器
> （ssh stark）同步切新地址 + snip36 入口 + 自托管 transaction-prover。
> 旧 vault `0x3f4ef706…` 存量 9.47 STRK 等待玩家自提迁移。
>
> 上主网前的部署参考。所有地址以 `strk20.json`（Sepolia）与本文档为准，
> 部署新环境后**必须**回填本文档与 `strk20.json`。

## 合约清单

| 合约 | 作用 | 构造参数 |
|---|---|---|
| `PokerToken` (pSTRK) | 游戏筹码 STRK20 代币（owner-only mint/burn） | `owner, name, symbol, initial_supply` |
| `PokerVault` | 1:1 pSTRK 存取 + 玩家筹码账本 | `owner, token_address, settlement_contract` |
| `PokerSettlement` | legacy 线性结算：aggregate digest 注册 + settle_hand | `owner, vault_address, initial_prover` |
| `PokerDualSettlement` | Phase 2 双证明结算（当前提交未启用） | `owner, vault_address, initial_prover` |
| `PokerSwap` | 双向固定汇率兑换：**1 STRK ⇄ 1000 pSTRK** | `owner, pstrk_address` |

### PokerSwap 细节（双向）

- 规范 STRK 地址硬编码：`0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`
  （mainnet/Sepolia/devnet 一致）。
- 汇率存储在合约 `rate`（当前 1000）。双向固定汇率（非 AMM 定价）：
  - 正向 `swap_strk_to_pstrk(strk_amount)`：approve STRK → 得 `×1000` pSTRK；
  - 反向 `swap_pstrk_to_strk(pstrk_amount)`：approve pSTRK → 得 `÷1000` STRK，
    **数量必须整除 1000 wei**（即 0.001 pSTRK 的整数倍）。
  - `swap(...)` 保留为正向旧入口。
- 双侧储备：正向兑换的 STRK 自动留在合约作为反向储备；反向兑换的 pSTRK 自动留作正向储备。
- owner 运维：
  - `fund_pstrk(amount)` / `fund_strk(amount)`：注入双侧初始流动性（先 approve）。
  - `sweep_strk(recipient, amount)` / `sweep_pstrk(recipient, amount)`：提取盈余。
  - 视图：`pstrk_liquidity()` / `strk_balance()` / `rate()`。
- 前端：`VITE_POKER_SWAP_ADDRESS` 配置后导航栏显示"⇄ 兑换"入口（弹窗内可切换方向），未配置自动隐藏。

## 部署顺序

```bash
cd poker_contracts && scarb build

# 部署工具：snops（zgame 仓库）或 sncast；deploy_sepolia.sh 为参考脚本
OWNER=<owner 地址> OPKEY=<owner 私钥> URL=<rpc> ./scripts/local_deploy.sh  # devnet
# Sepolia 全量部署（含 PokerSwap，源 .env.dev）：
URL=https://starknet-sepolia-rpc.publicnode.com ./scripts/deploy_sepolia_full.sh
```

1. `PokerToken(owner, "PokerSTRK", "pSTRK", 0)` — 初始供应走 owner mint，便于审计。
2. `PokerVault(owner, pstrk, 0)` — settlement 先占位 0。
3. `PokerSettlement(owner, vault, prover)` — prover 即 operator。
4. `vault.set_settlement_contract(settlement)` — 绑定结算合约。
5. `token.mint(owner, 初始流动性)`。
6. `PokerSwap(owner, pstrk)`：
   - `token.mint(owner, SWAP_LIQUIDITY)`（如 10_000e18）；
   - `token.approve(swap, SWAP_LIQUIDITY)`；
   - `swap.fund_pstrk(SWAP_LIQUIDITY)`。
7. 回填 `strk20.json` + 本文档 + server `.env` + client `.env`：

```
server .env:  STARKNET_STRK_ADDRESS / STARKNET_VAULT_ADDRESS /
              STARKNET_SETTLEMENT_ADDRESS / STARKNET_OPERATOR_*
client .env:  VITE_STRK_TOKEN_ADDRESS / VITE_POKER_VAULT_ADDRESS /
              VITE_POKER_SETTLEMENT_ADDRESS / VITE_POKER_SWAP_ADDRESS
```

## 当前部署：Starknet Sepolia 测试网（2026-08-31，deploy_sepolia_full.sh）

chain id `SN_SEPOLIA`，RPC `https://starknet-sepolia-rpc.publicnode.com`。
部署者/owner/operator = `.env.dev` 账户 `0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782`。

| 合约 | 地址 | class hash |
|---|---|---|
| PokerToken (pSTRK) | `0x4bfad561733ba5bef162be3606cada13bc85a8a69fd6a52dae2b844d431f9db` | `0x5d745b518295d8ffede689e51f4ec26b020e831b19d2b50546206e5037efe8d` |
| PokerVault | `0x6c8ac4202222a9bcf1f69cc213a2570a393bb83ca64666c7a5cd4a5894c1321` | `0x2bf5d0dc6d58cf64eedad5a5747e3d8a7e426028ecf73263a7558162fdf46c9` |
| PokerSettlement (legacy) | `0x76a0b49a40c706d438c5f8675165d462de5a0a7d5183183e8b4746b955b5194` | `0x6cc6ff2c1753f8ab5ff9dc155b461cb0d8650332f648888751ae31adc520d9c` |
| PokerSwap（双向 1:1000） | `0x45a5d045fad8ba092e7919e26b34fa9e901b3ebc93b42120262dbade6cbcee9` | `0x682e15685f0b336e88b4b2d067bff95ebf6d5c296ecd1a7d8a5ca596745a592` |
| PokerDualSettlement | —（见下） | —（见下） |

- Token 复用上一轮（2026-08-29）UDC salt=0 部署；Vault/Settlement/Swap 为本轮全新部署
  （本轮起 vault lib 类已在链上声明，UDC 确定性地址不再与 unittest 旧类冲突）。
- 链上验证：`vault.token` ✓、`settle.vault` ✓、`swap.rate = 1000` ✓、
  swap 双侧储备 100,000 pSTRK + 15 STRK ✓。
- vault.settlement_contract → legacy PokerSettlement（服务端 `STARKNET_SETTLEMENT_MODE=legacy`）。
- **PokerDualSettlement 无法在 Sepolia 部署**：casm 字节码 81,175 felts 超过链上 80,000
  上限（节点拒绝声明；devnet 无此限制故本地 e2e 可跑 DAPV）。Phase 2 需先瘦身
  （当前超出约 1,175 felts）再走 on-chain DAPV。
- snops 补丁（zgame/texas/src/bin/snops.rs）：`SNOPS_GAS_AMOUNT_MULT` /
  `SNOPS_GAS_PRICE_MULT` 可收紧默认 1.5× 估价系数（低余额账户 declare 用）。
- 浏览器直签联调：`client/.env.development` 的 `VITE_DEV_ACCOUNT_*` 指向同一
  `.env.dev` 账户，登录签名/兑换/买入/提现全部直签（生产删除即回退钱包）。

## 当前部署：本地 devnet（starknet-devnet --seed 0，端口 5051）

> 2026-09-10 起 `scripts/local_deploy.sh` 已切现代接线（与主网/Sepolia 一致）：
> 不再部署 PokerToken/pSTRK，vault 直接绑定规范 STRK（devnet 费用代币同址）。
> 一键流程（devnet + 部署 + 服务器本地 prover 启动）：`scripts/dev.sh`；
> Sepolia 测试网：`scripts/test.sh` + `texas/.env.test`。
>
> 真实钱包（Ready/Argent）联调：dev.sh 会把 Argent 账户类 v0.4.0
> （`0x036078…927f`，官方产物在 `scripts/assets/argent/`）预声明进 devnet
> ——katana 内置该类而 starknet-devnet 没有，缺了它钱包首连部署账户报
> "Class ... is not declared"。钱包部署费从反事实地址自身余额扣，先充值：
> `scripts/dev.sh fund <钱包地址> [STRK数量]`（devnet 重建后余额清零，需重充）。

chain id `SN_SEPOLIA`。地址随 devnet 重启 + 重新部署而变化（当前快照）：

| 合约 | 地址 |
|---|---|
| PokerToken | `0x508ab1bc518227bc444ced3b720f3e4f36309f53a32303fd2498ab26c5acb57` |
| PokerVault | `0x2409cd58b021c49d0a68522afbf3338fc3a1bb49d5f53ecaef70a990ea9116c` |
| PokerSettlement | `0x2106e927320e49be067890853c3b2a693dfe9c2fb81665aaf71ca344cc5a53b` |
| PokerDualSettlement | `0x70b4b8e19426a264a2da0cc3651cca137ebb374c61cc3a6e965f7ad1a86f9b2` |
| **PokerSwap**（双向） | `0x44185be81c5671147abd228b859e4af07b732880265cf85b90bbc61df579234` |

- owner/operator = devnet 预充值账户 #0（`--seed 0` 固定）。
- 双向储备：10_000 pSTRK + 10 STRK。
- 已验证：正向 1 STRK → 1000 pSTRK（tx `0x7d608be2…b506`）；
  反向 1000 pSTRK → 1 STRK（tx `0x7c82a228…538b`）。
- 单测：`snforge test poker_swap --max-n-steps 20000000`（3 个全过）。

## devnet 浏览器端到端兑换

浏览器钱包（Ready 等注入钱包）签的是 Sepolia，无法给 devnet 合约签交易。为让兑换在
浏览器里真实跑通，`client/.env.development` 配置了 dev 直签账户（devnet
预充值账户 #1）：

```
VITE_DEV_ACCOUNT_ADDRESS=0x78662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1
VITE_DEV_ACCOUNT_PRIVATE_KEY=0x0e1406455b7d66b1690803be066cbe5e
```

配置后 `swapTokens` 用该账户直签（provider 用 `BlockTag.PRE_CONFIRMED` 读
nonce——devnet 交易停留在 pre-confirmed，默认 latest 会拿到过期 nonce，
报 `52: Invalid transaction nonce`）。**生产环境必须删除这两个变量**，兑换
自动回退到连接的钱包签名。已实测：浏览器输入 1 STRK → 确认 → 弹窗显示
"兑换成功 ✓"，链上余额变动精确（-1 STRK / +1000 pSTRK）。

## 上 Sepolia / 主网时

1. 用有 gas 的账户按上面顺序部署（`scripts/deploy_sepolia.sh` 参考；
   主网前把 `JWT_SECRET`/operator key 换成生产密钥，`SNCAST_URL` 换主网 RPC）。
2. `PokerSwap` 无需改动：规范 STRK 地址在各网络一致。
3. swap 流动性建议 ≥ 目标玩家峰值买入总量（1:1000 全额储备 pSTRK）。
4. 回填 `strk20.json`、本文档、server/client env；navbar 兑换入口自动出现。
5. 建议加：swap 合约 owner 转多签、`rate` 紧急可调（当前为固定常量写入 storage）。

## Sepolia E2E 状态（2026-08-31）

| 环节 | 状态 | 证据 |
| --- | --- | --- |
| 兑换 STRK→pSTRK | ✅ 浏览器跑通 | tx `0x7e5132dc…`，+1000 pSTRK 精确 |
| 买入（vault.deposit） | ✅ 浏览器跑通 | 服务端验证 `amount=1000`，tx `0x712c41dc…` |
| 手牌流程（发牌/reveal/下注/摊牌） | ✅ 浏览器+bot 打完 | showdown 触发 `on_hand_complete` |
| 链上结算（register_aggregate + settle_hand） | ⛔ 阻断 | mirror 证明层缺浏览器玩家份额（见下） |

### 结算阻断点（遗留）

mirror（poker_l1 证明层）走自治 deck 链，与游戏 deck 不同步（代码注释
"deck 链无法逐字节同步…生产需客户端协议对齐，见 docs/design/DUAL_PROOF_PROTOCOL.md
§5.3"）。浏览器玩家无法产出 mirror 层的 reveal 份额（sk·c1_mirror），
mirror DealHole 永远等不到人类份额 → `mirror has no provable activity`
→ settle 跳过。已尝试/已修的相关项：transcript 统一（Merlin→FiatShamir，
poker_l1 + client.rs + dev_bot）、game_loop 每 tick 驱动 mirror
deadline + 缺失份额服务端补齐（`mirror_fill_pending_reveals`，利用
钱包确定性派生 sk）、mirror 下注缓冲重放。完整修复需按
docs/design/DUAL_PROOF_PROTOCOL.md §5.3 做客户端协议对齐（独立工作量）。

### 本次修复的其他 bug（影响 e2e 的真实缺陷）

1. client `WEI_PER_CHIP` 1e5 ≠ server 1e14（买入金额差 9 个数量级）
2. `availableChips` 只用服务端结余，挡死首次链上买入
3. 钱包登录 `signature/messageHash` bigint 序列化崩溃（"闪退"根因）
4. LoginModal 在 dev 直签模式下开窗即自关
5. StrictMode 下 `isUnmountingRef` 永久 true → TABLE_UPDATED 每次广播
   都触发 STAND_UP（玩家被反复移座）
6. `broadcast_to_table` / `broadcast_player_reveal_result` 同钱包多
   socket 时取任意一条（陈旧 socket → 广播丢失）
7. reveal token 双重提交竞态（REVEAL_NOTICE 与 TABLE_UPDATED fallback
   并发）→ "already submitted" 报错
8. dev_bot 循环 mirror 分支 `continue` 饿死游戏层动作
9. snops 估价系数不可调（低余额 declare 被拒）→
   `SNOPS_GAS_AMOUNT_MULT` / `SNOPS_GAS_PRICE_MULT`

## Dual settlement v3（P2-M3 零明文结算，2026-09-03 待部署）

代码已就绪（`verify_and_settle_dapv_stark_private_v2`：calldata 零明文，消费
settlement_private 电路公开段），**链上部署被 gas 预算阻塞**：

| 项 | 值 |
| --- | --- |
| class 产物 | sierra 859 KB / casm 737 KB / 32,901 bytecode words |
| declare 资源需求（sepolia 实时报价） | l2_gas 2.86e9 单位 × 4.95e10 wei ≈ **142 STRK** |
| 部署账户（poker-deployer）余额 | ≈ 65 STRK → **缺 ≈77 STRK** |
| 已知坑 | sepolia 当前版本的 compiled-class hash 方案与本地 cairo 2.11.4 不一致——declare 报 `Mismatch compiled class hash ... Actual: 0x55387af9...`；脚本自动以 `--compiled-hash <Actual>` 重试 |
| 电路 program hash（set_circuit_program_hash 用） | `0x2ad181fc357c19c7e7d8a626314605436f6e5c24594d436b0e50af088977478`（prove 实测 14s / 2021 步） |

一键部署（补足 STRK 后）：`HELPER=0x393f... VAULT=0x1e9f... PROGRAM_HASH=0x2ad1... ./scripts/deploy_sepolia_v3.sh`
（自动：declare（含 hash 方案重试）→ deploy(owner, vault, prover) → set_claim_helper → set_circuit_program_hash → 回填 texas/.env。）

## Vault v3（#33 在局锁定，与 dual v3 同批，2026-09-03 代码就绪待部署）

`poker_vault.cairo` 新增（#33 逃单/砖死修复，snforge 8/8 ✅）：
- `locked` / `session_last_activity` / `session_active` / `lock_ttl` 存储；
- `lock`（owner=operator）：入座锁额度；`refresh_session`：结算/续局续时钟；
- `unlock_after_deadline`（无许可）：`timestamp >= last_activity + lock_ttl`
  后任何人可解锁（后端失联保护；TTL=0 禁用，constructor 默认 12h，
  `set_lock_ttl` owner 可调）；`force_unlock`（owner 应急）；
- `withdraw` / `withdraw_to` / `burn_chips` 统一 `assert_spendable`
  （只可花未锁定余额）；`apply_settlement` 负 delta **优先消耗锁定额度**
  （修"输家提款 → 结算砖死"）。

部署（脚本 `DEPLOY_VAULT_V3=1` 段自动完成）：declare vault v3 → deploy
(owner, token, settlement=旧 dual) → `set_unshield_helper(CashoutUnshieldHelper)`
→ `set_settlement_contract(DUAL_OLD)` → dual v3 以新 vault 地址构造。
迁移：旧 vault 玩家余额经公开 `withdraw` 提取后在新 vault 重新 deposit
（或运营 `deposit_for`）。

### ✅ 已部署（2026-09-04，sepolia）

| 合约 | 地址 | 说明 |
| --- | --- | --- |
| Vault v3 | `0x0629385f1e3b43684828cf46488fbd0ef2b1ec0dc27c7827ecbe6b2f15c7fa13` | class `0x2c829f5c...`；#33 在局锁定 + withdraw_to + unshield 门 |
| Dual v3 | `0x516b8289a8b154644b5098e4d4301f2f0c9cf1fd67cdac0516b439094d35f61` | class `0x2e039e95...`；#16/#17 动作签名预留 + `verify_and_settle_dapv_stark_private_v2` 零明文结算 |
| CashoutUnshieldHelper | `0x1c35d8083e25c166bfa033d77009541a2a3a79a5beeca58e7a0a9134a06aaf1` | #25 unshield 提现通道；已在 vault v3 `set_unshield_helper` 授权 |

接线完成：vault v3 `set_settlement_contract(Dual v3)`、`set_unshield_helper(CashoutUnshieldHelper)`；
dual v3 `set_claim_helper(0x393f...)` + `set_circuit_program_hash(0x2ad1...)`。

**迁移步骤（切换 texas/.env 前，玩家先从旧 vault 提走/花掉余额）**：
1. `texas/.env`：`STARKNET_VAULT_ADDRESS` → vault v3、`STARKNET_DUAL_SETTLEMENT_ADDRESS` → dual v3，重启服务器；
2. 旧 vault 余款：`0x1e9f4a93...` 上的剩余 STRK 由 owner `withdraw` 收回。

**✅ 已切换（2026-09-04，测试网不做余额迁移）**：`texas/.env`（vault v3 + dual v3）与
`client/.env.development`（vault v3 + anonymizer v3）均已指向 v3，texas 服务器已重启生效。
旧 vault v2 `0x1e9f4a93...` 上遗留的玩家筹码余额留在原地（筹码读数跟随
`vault.chip_balance`，切后即从 v3 起算；旧余额玩家可随时自行 `withdraw` 取回 STRK）。

相关 TX：vault declare `0x14fb018a...`、dual declare `0x1d5aa149...`（类 `0x2e039e95`）、
helper declare `0x5d751a8e...`、接线 TX 均 ACCEPTED_ON_L2（见各 `set_*` 调用）。

## Dual v3.x + 新 claim helper（#18 Phase B，2026-09-05 已部署 sepolia）

digest 尾词绑定动作日志哈希后的新 ABI 批次：

| 合约 | 地址 | class hash |
| --- | --- | --- |
| Dual v3.x | `0x55784c90b20b2727baec6482192d4600808e9c40c61bc31281350dd5c4de63f` | `0x6db1ea08f1e6759cc5c70e07ed6845ad7d756b226ecd9686c55acb1045b85f0`（declare TX `0x6039a54b...`） |
| SettlementPayoutAnonymizer（新） | `0x60a4c47416de31056cdca968001df0c199d663842c9372e0409d4c60b397871` | `0x5c28571f61d0ff937208e94b6e948a8b93367766a18b6cd448b701300f0d0ee`（declare TX `0x33f765a5...`） |

- **wire 变化**（与 #18 Phase B 代码一致，服务端源码 `8481aa6` 起匹配本 ABI）：
  `register_hand(hand_binding, settlement_digest, g_attestation, action_log_digest,
  exp_reveal, exp_leave, exp_recon)`；`verify_and_settle_dapv_stark[_private]`
  在 `hand_id` 后 +`action_log_digest` 标量；`SETTLEMENT_SEGMENT_LEN=15`
  （公开段尾词 = 动作日志哈希，对注册承诺逐 felt 比对）；legacy
  `settle_hand` 同步 +1 标量。新增 `hand_action_log(binding)` 视图。
- **接线**（全部 SUCCEEDED/ACCEPTED_ON_L2）：dual deploy TX `0x420fccb7...` →
  `set_claim_helper(0x60a4c474...)` TX `0x7a9e0eac...` →
  `set_circuit_program_hash(0x25d81d2c...)`（Phase B 电路，15.5s/2048 步）
  TX `0x70bf41c8...` → vault v3 `set_settlement_contract(0x55784c90...)` TX
  `0x4f9d87f0...`（切换点）。
- **冒烟**：`register_hand(0x736d6f6b652d3334/"smoke-34", 0xdeadbeef, 0, 0xa11c3d, 0,0,0)`
  TX `0x4f0788df...` → `hand_action_log` 读回 `0xa11c3d` ✓、registered flag=1 ✓。
- **✅ 真实 DAPV 全链路结算冒烟（2026-09-05，TODO #22①/#34④）**：
  游戏层真实流程 → prove_log 重建 → 真实证明链 → 认可批次 → 链上
  `register_hand`（TX `0x28ab0dc7...`）+ `verify_and_settle_dapv_stark`
  （TX `0x1215cde0...`，SUCCEEDED）。**gas 实测（2 人合成手）：l2_gas
  4,313,040 + l1_data_gas 288**。复现：
  `STARKNET_SEPOLIA_SMOKE=1 cargo test -p texas --bin texas sepolia_settle_smoke -- --ignored --nocapture`。
- **发现并修复**：此前在网的 claim helper class `0x5ec1...` 是**加 settlement
  绑定之前**的旧 2 参版（`settlement()` EntrypointNotFound、vault 还指向
  vault v2 `0x1e9f4a93...`）——本次随 v3.x 重部署为现役 3 参 class。旧 helper
  `0x393fb6f9...` 的历史托管原地保留，服务旧 dual 的历史认领。
- **env 切换**：`texas/.env` 已指向 dual v3.x + 新 helper（当前无运行中的
  服务进程，下次 `cargo run` 即生效）。

### ✅ #18 Phase C 切片 2："合法默认"约束（2026-09-05）

电路词条区改 2 词 × 30 槽（日志打包词 + 合法性词），解包校验 action 白名单
与 flags，对 auto 词条强制 `legal_auto_action` 规则（§8.2 主网门槛达成）；
e2e 含非法默认负例（auto FOLD 谎称 Check → 中止 ✓）。新 program hash
`0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4`
（prove 7.8s）已上链 `set_circuit_program_hash` TX `0x55f9297b...` 并视图验证 ✓。
无合约 ABI / 公开段变化（仍 15 felt），仅电路内部 + hash 指针。

### ✅ #18 Phase C 切片 1：动作日志哈希链 keccak→Poseidon（2026-09-05）

电路 main 增加动作日志词条区（1 计数 + 60×1 打包词，`action(40)|flags(2)@40|
amount(64)@42|seq(64)@106|seat(32)@170`，202 位），用 poseidon_builtin 重放
整链并断言链根 == 吸收进 settlement digest 的动作日志哈希；补零槽 canonical。
游戏层 `action_log_digest_felt` 从 starknet_keccak 链切到同一 Poseidon sponge。
新 program hash `0x5b993db5...`（prove 实测 7.5s），已 owner 上链
`set_circuit_program_hash` TX `0x31401a6e...` 并视图验证 ✓。
为切片 2（"合法默认"约束：解包 flags/action + owed/my_bet/big_blind 见证）铺路。

## PokerVaultAnonymizer v3（2026-09-04，绑定 vault v3 + set_vault 维护口）

随 v3 切换重部署的私密买入/领取 helper（`privacy_invoke` operation 分流：0=买入
approve+deposit_for、1=领取 burn_chips+回池）。新增内容：

- **`set_vault(owner 门控)`**：vault 升级不再需要重部署 helper（此前 vault 地址
  构造器写死，切 v3 必须重部署）。
- **owner 改为显式构造参数**（`constructor(owner, vault, pool)`）：不能在构造器里
  用 `get_caller_address()` 取部署者——starknet-rs `deploy_v3` 经 UDC 部署，构造期
  caller 是 UDC 合约地址，用它当 owner 会让 `set_vault` 永远无人可调（实测踩坑）。

| 项 | 值 |
| --- | --- |
| class | `0x405327310fad98fc864d63282a97495fd9373e28987577ad4c54e8d900ec561` |
| 地址 | `0x6fd4be6e7af47f15b5c801623f49801e00610673fb42f6d7519d9119991b8f5` |
| 部署 TX | `0x228575a24d52d0c59db804ab6a21af4826a5b8c6f10631241bb406adf4b2527` |
| 构造参数 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) pool=`0x254a6b...d91` |
| vault 授权 | vault v3 `set_authorized_helper(本合约)` TX `0x286ae4f39f68...` SUCCEEDED |

（中途一次部署 `0x3854d580...` 因 owner=UDC 缺陷作废，未授权、不可用。）


## PokerDualSettlement v4 — P2-M4 双证明私密结算（2026-09-06）

新增 `verify_and_settle_dapv_proved_private(hand_binding, hand_id, segment, p_batch_commitment, p_batch_len)`
（hand_verify + stark verify 双 fact 认证）与 `register_hand_proved`（钉住
p_batch 承诺/长度）、`set_hand_verify_program_hash`；双 fact：
`poseidon([hand_verify_program_hash, p_batch_commitment])` +
`poseidon([circuit_program_hash, segment])`。派奖与 v2 private 相同
（金额藏 cm，escrow 按公开段 total_winnings 划转）。snforge 92/92。

| 项 | 值 |
| --- | --- |
| class | `0x02c73f48a7b6e1f615e972525fc25c677aa1937234b5fe7aa9fe7c402072cf6b` |
| 地址 | `0xbfc7046b6a855a2c6a144441370e9cee27caf57a9aaf4708d8b48fa8640eb8` |
| declare TX | `0x12499773ffb7d3f416e6d9381bb597b2b7bf0960e9b8a4e6b2f7760e3677082`（casm Actual `0x74e1aadc...` 重试后落地） |
| deploy TX | `0x3a9610e5aeaee41caff5a6910fb76397074047a12562515748722aa4530b06a` |
| 构造参数 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) initial_prover=deployer |
| set_claim_helper | `0x37d9a110...` → `0x60a4c474...`（SettlementPayoutAnonymizer） |
| set_circuit_program_hash | `0x4d46cb37...` → `0x744d16d3...`（#18 Phase C 切片 2 电路） |
| set_hand_verify_program_hash | `0x21cfd7c4...` → `0x303029d8...`（hand-verify-native form-② composed） |
| 回执 | 四笔均 SUCCEEDED；`circuit_program_hash` 视图已验证 |

（部署脚本 `scripts/deploy_sepolia_v4.sh`；旧 dual v3.x `0x55784c90...` 保留服务
历史已结算手的认领，`.env` 已切换指向 v4。）

## PokerDualSettlement v5 — cairo 2.19.4 迁移 + SNIP-36 v3 双门入口（2026-09-07）

P1+P2 落地：合约工具链 scarb 2.11.4 → **2.19.4**（与证明侧 vendored corelib
2.19.4 完全同版，双工具链合一）；snforge 0.39.0 → **0.63.0**（原生
`cheat_proof_facts` mock）。新增 `verify_and_settle_dapv_stark_private_v3`
（SNIP-36 `proof_facts` 协议内验证优先 + fact-registry 降级双门）+
`DualProofSettledSnip36` 事件。`poker_swap.cairo` 删除（pSTRK 已下线，
其 5 个测试随之移除）。测试 91/91（含 v3 四例：SNIP-36 门结算 /
fact 降级 / 错 program hash 拒 / 错消息哈希拒）。

**意外利好**：2.19.4 编译器产物 casm **36,508 felts**（2.11.4 时代为
81,175 贴近 81,226 上限）——余量 55%，后续入口扩容空间充足。

| 项 | 值 |
| --- | --- |
| 工具链 | scarb 2.19.4 + snforge 0.63.0（`~/.local/opt/toolchains/` 并行安装，PATH 前缀使用） |
| class | `0x047e91d54d171401a314a591ab1b67d3259e09b9f90c0036675829f533884cf8` |
| 地址 | `0x29bdc970330f545c8be2d78fdcd8a92cc0378dff4b6d7464257df9b4fdd47d6` |
| 配置 | claim_helper=`0x60a4c474...`、circuit_program_hash=`0x744d16d3...`（视图已验证）、hand_verify_program_hash=`0x303029d8...` |
| 回退 | v4 `0xbfc7046b...` 保留（v2/proved_private 入口）；`.env` 已切 v5 |

⚠️ 槽位冻结待办：v3 的 `facts[2]`/`facts[8]` 槽位与消息哈希公式以
SNIP-36 参考实现为口径——首个真实 SNIP-36 证明提交前需用 sepolia 真实
proof_facts 样本对拍一次（执行计划 G2 门）。

## 主网部署准备（2026-09-07，待执行）→ ✅ 已部署（同日）

在用合约 5 个（`strk20.json` 已同步清理：pSTRK/PokerSwap/CashoutUnshieldHelper 退役）：
PokerVault / PokerSettlement(legacy 兜底) / PokerDualSettlement(v5) /
PokerVaultAnonymizer(v4) / SettlementPayoutAnonymizer。

### 主网常量（已核对）

| 项 | 值 | 来源 |
| --- | --- | --- |
| canonical STRK | `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d` | mainnet=sepolia 同址 |
| STRK20 privacy pool | `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a` | strk20-by-example.org/contract-addresses（2026-09-03 验证） |
| chain id | `SN_MAIN`（client hex `0x534e5f4d41494e`） | — |
| 电路 program hash | `0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4` | #18 Phase C 切片 2（与 sepolia v5 同版） |
| hand-verify program hash | `0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f` | 同上 |

⚠️ anonymizer 的 pool 地址构造时写死（v4 只有 `set_vault` 无 `set_pool`；
SettlementPayoutAnonymizer 无任何 setter）——STRK20 池升级需重部署 helper。

### 费用估算（2026-09-07 主网 RPC 真实模拟，simulateTransactions pre_confirmed）

方法：`starknet_simulateTransactions` 捆绑 [DECLARE + UDC deployContract INVOKE]
逐合约模拟，SKIP_VALIDATE/SKIP_FEE_CHARGE，gas 价快照 l2=2.76e10 fri、
l1_data=2.77e10 fri（Starknet 0.14.3，block ≈14,478,000）。declare 费用
以 l2_gas 为主（节点只对 declare 计 192 l1_data 单位）。

| 合约 | sierra / casm | declare | deploy(UDC) | 小计 |
| --- | --- | --- | --- | --- |
| PokerVault | 9,868 KB / 17,682 felts | 28.19 STRK | 0.016 | 28.21 |
| PokerSettlement | 4,726 KB / 8,559 felts | 14.11 STRK | 0.016 | 14.12 |
| PokerDualSettlement | 18,192 KB / 36,508 felts | 59.07 STRK | 0.016 | 59.09 |
| PokerVaultAnonymizer | 1,982 KB / 3,230 felts | 6.31 STRK | 0.016 | 6.32 |
| SettlementPayoutAnonymizer | 1,975 KB / 4,017 felts | 7.16 STRK | 0.016 | 7.18 |
| **合计** | | **114.84** | **0.08** | **114.92 STRK** |

- 接线 5 笔 owner invoke（set_settlement_contract / set_unshield_helper /
  set_claim_helper / 两个 program hash）合计 < 0.1 STRK。
- deployer 账户若未部署（OZ account declare+deploy）另需 ≈0.5 STRK。
- **建议部署账户充值 ≥ 130 STRK**（估算 115 + gas 价波动缓冲）。

已知坑（模拟时确认，主网 publicnode/Juno 同样存在）：节点重算的
compiled-class-hash 与本地 cairo 2.19.4 可能不一致（报
`Mismatch compiled class hash … Expected: 0x…`）——`deploy_mainnet.sh`
沿用了 snops 的 `--compiled-hash <Expected>` 自动重试。模拟端点曾把
sierra abi 按字符串序列化重算出不同 sierra hash，不影响费用结论
（费用只随 calldata 大小变化）；真实 declare 由 snops/starknet-rs
发送原生格式，sepolia v5 实测无此问题。

### 执行

```bash
cd poker_contracts && PATH="$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH" scarb build
cargo build -p texas --bin snops
# .env.mainnet 写入 ADDRESS/PRIVATE_KEY（主网 deployer，≥130 STRK）
CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh
```

脚本顺序：declare×5 → vault(owner, STRK, settlement=0) → settlement(owner,
vault, prover) → dual(owner, vault, prover) → anonymizer(owner, vault, pool) →
payout(vault, pool, dual) → 接线（vault.settlement=dual、vault.unshield_helper=
anonymizer、dual.claim_helper=payout、dual 两个 program hash）→ 链上回读。
部署后回填 strk20.json / 本文档 / texas `.env` / client `.env.production`。

### ✅ 主网部署完成（2026-09-07）

deployer/owner/operator = `.env.mainnet` 账户 `0x412e4d43...46121a6`
（snops gen-key 离线生成，OZ class `0x05b4b537...`，充值 200 STRK）。
账户部署 TX `0x4512a29d...`；全量脚本 `CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh`。

| 合约 | 主网地址 | class hash |
| --- | --- | --- |
| PokerVault | `0x3f4ef706ae2dc00ac685afffc05e5f1e1e9ab5aacf99c3205d2067e061cbb45` | `0x7c74ca1a...` |
| PokerSettlement (legacy) | `0x2bf6a09c0aaea154de34745056e7534f58fa0805c12afe18cf22a9bc66ee7a8` | `0x6f2e01a6...` |
| PokerDualSettlement (v5) | `0x1d39b80b990038ceeeaf3d39e83cb83031be95c0d0ccca5d18c5faea29aef6d` | `0x047e91d5...`（与 sepolia v5 同 class） |
| PokerVaultAnonymizer (v4) | `0x88c1f843588d1498fcd3f780fa7cf86ada18cd416754c77149a8c14e492877` | `0x525646bd...`（与 sepolia v4 同 class） |
| SettlementPayoutAnonymizer | `0x402372930ea52cccbafa459169b3dae3d67051ed741e9af7da669a0f1fbb308` | `0x7c11073c...`（当前源码新 class） |

- 接线验证（链上回读）：vault.token=canonical STRK ✓、vault.unshield_helper=
  anonymizer ✓、settlement.vault=vault ✓、dual.claim_helper=payout ✓、
  dual.circuit_program_hash=`0x744d16d3...` ✓；hand_verify_program_hash 无
  getter——幂等重设一次 SUCCEEDED（TX `0x1ddcf414...`）确认为 `0x303029d8...`。
- 实际花费 **122.37 STRK**（200 − 77.63，含账户部署+15 笔部署/接线+1 笔幂等重设；
  对比估算 115.5，gas 价波动内）。
- 主网 STRK20 池 `0x040337b1...` 已绑入两个 anonymizer 构造。
- 服务端/前端切换（改 env 后重启生效）：

```
texas/.env: STARKNET_RPC_URL=https://starknet-rpc.publicnode.com
            STARKNET_CHAIN_ID=SN_MAIN
            STARKNET_STRK_ADDRESS=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
            STARKNET_VAULT_ADDRESS=0x3f4ef706...
            STARKNET_SETTLEMENT_ADDRESS=0x2bf6a09c...
            STARKNET_DUAL_SETTLEMENT_ADDRESS=0x1d39b80b...
            STARKNET_CLAIM_HELPER_ADDRESS=0x40237293...
client/.env.production: VITE_STARKNET_CHAIN_ID=0x534e5f4d41494e
            VITE_STRK_TOKEN_ADDRESS=<canonical STRK 同上>
            VITE_POKER_VAULT_ADDRESS=0x3f4ef706...
            VITE_POKER_SETTLEMENT_ADDRESS=0x2bf6a09c...
            VITE_POKER_VAULT_ANONYMIZER_ADDRESS=0x88c1f843...
            VITE_STRK20_POOL_ADDRESS=0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a
```

## PokerVaultAnonymizer v4 — 私密领取守恒修复（2026-09-07）

OP_WITHDRAW 从 `burn_chips`（无代币移动 + 用户池内自筹注资——每领 X 销毁
X 价值：chips 烧掉、背书 STRK 滞留 vault 无人可领、输出 note 全额来自用户
自己的钱）改为 `withdraw_to`：烧 player 等额筹码并由 vault 释放背书 STRK
给 helper，输出 open note 由 vault 出资——**无需任何池内预存余额**，用户
chips −X / note +X 分文不丢。前端两动作删去自筹 withdraw 桥与屏蔽余额
前置检查（strk20.ts claimRewardsPrivate）。

| 项 | 值 |
| --- | --- |
| class | `0x525646bdab97344307b3bd4cbb80344ee26415366743d181e52c61f1a250c81` |
| 地址 | `0x7ee059ddb3afaa1975d8ac73f273ba6033bfc6a2f3b7421b35a2364023ad9dd` |
| 构造 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) pool=`0x254a6b...d91`（STRK20 Sepolia 池，视图回读 ✓） |
| 接线 | vault `set_unshield_helper(0x7ee059dd...)` TX `0x18fbf4fa...`（旧 v3 `0x6fd4be6e...` 保留 authorized_helper 语义但 OP_WITHDRAW 已废弃） |
| 测试 | snforge 91/91（withdraw 三负例改守恒语义：unshield 门/超额/零 note） |
| env | client `VITE_POKER_VAULT_ANONYMIZER_ADDRESS` 已切新地址（vite 已重启） |

## Fiat–Shamir transcript Poseidon epoch 迁移（2026-09-11）

链下证明侧（不涉及合约部署，无新 class hash）：

- **生产 transcript**：Stark 曲线全部 sigma 证明（shuffle V2 / mask+shuffle /
  reveal-token / leave / fold / reconstruct V2+V3）从 SHA3-256
  （`FiatShamirTranscript`）与 Merlin（`MerlinTranscript`，leave 路径遗留）
  统一切换到 `PoseidonFeltTranscript`（felt 直通，Cairo 原生置换）。
  域标签见 `poker-protocol-core/src/transcript_domains.rs`，全部带 epoch
  后缀（如 `zk_shuffle_poseidon_v3`、`zk_leave_poseidon_v2`）。
- **语句摘要**：reconstruction V3 `context_digest` / `prior_state_digest`
  压缩函数 blake2b → `poseidon_hash_many`（域标签
  `...context.v2.poseidon` / `...prior_state.v4.poseidon`）。
- **明文牌常量承诺**（2026-09-11，prior_state v4）：52 张明文牌点为协议
  常量，prior-state 材料以 `poseidon_hash_many(52×(x,y))` 单 32B 承诺吸收
  （`plaintext_cards_commitment()`，进程级 OnceLock 缓存，KAT
  `00667136...85f7` 钉死），替代 len + 52×32B 逐点字节。每次 digest 重算
  从 ~5.98ms（52×hash_to_curve 开方）降到 ~16µs（暖缓存），重放路径不再
  依赖开方；材料 1.78KB → 309B。
- **ABI**：`TranscriptId::Poseidon252` 放行 `(StarkCurve, BayerGrothV2 /
  BayerGrothOrderedV2 / BayerGrothSlotOrV3)` 组合；`Merlin` /
  `FiatShamirSha3` 双收仅限 epoch 过渡窗口的在途证明。
- **Cairo 合约零改动**：dual settlement 链上验证走 handbatch foldable
  epoch 聚合挑战（`poseidon_hash_span` 直通），不重放 per-proof
  transcript；secp256k1 路线（Keccak-256）不受影响。
- **epoch 纪律**：一场 hand 内必须使用同一 epoch 的标签集合；切换只能
  发生在 hand 边界。跨端对拍锚点：
  `transcript_domains::tests::poseidon_epoch_challenge_kat`。

## PokerTableRegistry — 桌台注册表（2026-09-11 代码就绪，待部署）

"关桌后不开新手"的链上锚定层（设计讨论定稿：注册表只回答"这张桌承诺过
什么规则"与"还开着吗"两个问题；**不碰钱**、不进任何证明约束）。

| 项 | 值 |
| --- | --- |
| 合约 | `poker_table_registry.cairo` → `PokerTableRegistry` |
| 构造 | `owner, close_grace_secs`（owner = 运营兜底关闭主体；grace = 闲置后任何人可关的宽限秒数，建议生产 604800 = 7 天） |
| 接口 | `create_table(params_hash) -> table_id`（permissionless，**合约分配 id 从 1 递增**）/ `close_table(id)`（creator/owner 随时，他人需过 grace；**终态**）/ `is_open(id)` / `get_table(id)` / `table_count()` |
| params_hash | `poseidon_hash_many([max_players, small_blind, big_blind])`——字段顺序即跨端契约，Rust 锚点 `texas/src/starknet/table_registry.rs::compute_params_hash` 测试向量 |
| 生命周期 | `Vacant → Open → Closed`（只追加，无 update；规则变更 = 关旧桌 + 开新桌） |
| 语义边界 | 恶意宿主自报 table_id 可绕过链上检查——注册表是绊线与审计轨迹不是缰绳；真正防线 = 客户端只在 Open 桌玩 + mental poker 需在座玩家配合才能开局 + vault TTL 兜底 |

服务端接线（`STARKNET_TABLE_REGISTRY_ADDRESS` 配置即启用，留空行为不变）：

- 启动引导：初始桌台 `create_table` 上链拿 `registry_table_id`（登记后
  `is_open` 读回核验），失败降级纯链下并告警；
- 关桌：`POST /api/tables/:id/close`（`OPERATOR_ADMIN_TOKEN` bearer；未配
  置 token 仅 debug 构建放行）→ 本地 closed 标志（game_loop 跳过开局、
  SIT_DOWN 以 `TABLE_CLOSED` 拒绝）→ 广播终态 → 释放在座玩家 vault 会话
  锁 → 链上 `close_table`；
- 客户端：`closed` 快照字段 → 坐下按钮替换为"本桌已关闭"提示 + `sitDown`
  本地拦截。

部署：devnet `local_deploy.sh` 已加 PokerTableRegistry（`REGISTRY_GRACE` 可覆盖
宽限期，devnet 默认 3600）。

### ✅ Sepolia 部署（2026-09-19，随 dual v6 同批）

| 项 | 值 |
| --- | --- |
| class | `0x7cc910b5cf79132f02479b264a4a792d90f97508b8c76253557b752d405c0bb`（declare TX `0x7056bcff...`，compiled-hash 自动重试同坑） |
| 地址 | `0x39b3531d4a48245d56f6cec89a4434d688b01fa26f5b2a317efdcb99da6fdaf`（deploy TX `0x2f0ae628...`） |
| 构造 | `(owner=deployer 0x6e37...c782, close_grace_secs=604800)`（生产口径 7 天） |
| 引导 | 服务器 test 模式启动 `create_table` TX `0x43bbad03...` → registry id 1，`is_open(1)=true` 链上回读 ✓ |

env：`STARKNET_TABLE_REGISTRY_ADDRESS` 已写入 `texas/.env` / `texas/.env.test`。
主网部署随 v6 迁移批次一起执行（同脚本补一段 declare+deploy 即可）。

**本地 scarb 2.11.4 无法解析钉定的 starknet 2.19.4（既有环境
限制），合约需在 scarb ≥2.19 工具链 `scarb build && snforge test` 验证。**

## dual v6（SNIP-36 门修正 + create_proof 入口）——✅ 已部署 Sepolia（2026-09-19），主网待部署

源码 `poker_contracts/src/poker_dual_settlement.cairo`，snforge 112/112 全绿。
Sepolia 已部署并完成接线 + 真实结算冒烟；**主网仍运行 v5，待 sepolia 重测通过后迁移**。相对 v5 的差异：

1. **SNIP-36 门修正**：`facts[2]` 的绑定根从 `circuit_program_hash`
   （v5 误绑本方电路哈希——真实 proof_facts[2] 是 Starknet 虚拟 OS
   program hash）改为独立 owner 钉扎存储 `virtual_snos_program_hash`
   （`set_virtual_snos_program_hash`，owner 门控）；门 = `facts[1] ==
   "VIRTUAL_SNOS"` ∧ `facts[2] == virtual_snos_program_hash` ∧
   `facts[8] == snip36_message_hash`。**v5 上真实 SNIP-36 交易会被拒
   （只走 fact-registry 降级腿）——v6 部署前不要发真实 proved 交易。**
2. **`emit_settlement_proof_message`**：create_proof 第一笔交易入口
   （校验公开段 → 发 `to=0、payload=segment` 的 L2→L1 消息），与 v3
   第二笔共享 `validate_settlement_segment`。
3. **虚拟 SNOS 哈希参考值**：0.14.3 回归样本
   `0x602b02cff498684fae3d66016137978fdad45a5036878a57257689d4f3f6ccb`；
   **部署后须先 sepolia 实测真实 proof_facts 再钉扎**（`snops
   dump-proof-facts` 对拍）。

构建指纹（本机 scarb 2.19.4）：sierra_program 15,791 felts / 34 入口；
casm **37,411 felts**（v5 为 36,508，上限 81,226 余量充足）。

### ✅ Sepolia 部署（2026-09-19）

| 项 | 值 |
| --- | --- |
| class（sierra） | `0x255cafe369c7c9d496096ac07585df49f98a1b86eca70e1b66c634538a03041` |
| declare TX | `0x15e1d926...`（节点重算 compiled hash `Actual 0x5f0ea583...`，snops 自动以 Actual 重试落地，已知坑复现） |
| 地址 | `0x7481ddcd830c5e23f81a15db52774992c343be618d04f00366600efe7da2c94` |
| deploy TX | `0x70b8b9e7...`（构造 `[owner, vault v3, prover=owner]`，与 v5 同形） |
| set_claim_helper | `0x60a4c474...` TX `0x95d7bf5b...` |
| set_circuit_program_hash | `0x744d16d3...` TX `0x4929b832...` |
| set_virtual_snos_program_hash | 占位 `0x602b02cf...` TX `0x63756494...`（**G2 门：首个真实 proved 交易前须以 sepolia 实测 proof_facts 修正**，`snops dump-proof-facts` 对拍） |
| vault v3 `set_settlement_contract(v6)` | TX `0x13d524d3...`（切换点；vault 无 settlement getter，切回 v5 需显式重绑） |
| 回执 | 以上全部 ACCEPTED_ON_L2 SUCCEEDED；`circuit/virtual_snos/claim_helper/vault` 四视图回读核验 ✓ |

本轮（declare+deploy+接线+registry）总花费 ≈ 57.3 STRK（operator 余额 304.5 → 247.2）。

**Sepolia 真实结算冒烟（dual v6，2026-09-19）**：
`STARKNET_SEPOLIA_SMOKE=1 cargo test -p texas --bin texas sepolia_settle_smoke -- --ignored --nocapture`
→ `SEPOLIA_SETTLE_SMOKE_OK hand_id=7`；prefund TX `0x332ae29e...`、
register+settle TX `0x3c8a66d2...`（SUCCEEDED，l2_gas 8,070,480 + l1_data 800）。
随冒烟修复一处**过时断言**（e2e_tests.rs：`proved.settle_calldata` 自 6684d4ef
起改为提交期填充，构建期刻意留空——断言仍按旧行为查长度导致冒烟必挂，已改为
`is_empty()`）。

**registry + env 切换**：`texas/.env` 与 `texas/.env.test` 已指向 dual v6 +
PokerTableRegistry（`STARKNET_TABLE_REGISTRY_ADDRESS`）；`STARKNET_DAPV_SETTLE_ENTRY`
保持 `v2`（fact-registry 腿），切 `snip36` 入口待 G2 门（内网 transaction-prover +
真实 proof_facts 实测钉扎）。服务器启动冒烟 ✓（registry 引导 `create_table`
TX `0x43bbad03...` → registry id 1，链上 `is_open(1)=true` 回读 ✓）。

## ✅ P1-2 类漂移重部署：vault + anonymizer + dual 实例（Sepolia，2026-09-19）

**根因**：客户端买入 multicall 自 P1-2（9108a…/9fdde1d0，2026-09-10）起携带
`vault.set_session_tx_pk`（会话委托同笔登记），而在网 vault 类是 2026-09-04
部署的 `0x2c829f5c...`——无该入口 → 买入交易
`argent/multicall-failed → ENTRYPOINT_NOT_FOUND`（线上实测，桌面买入全挂）。
anonymizer 在网类（9-07 `0x525646bd...`）同样早于 `privacy_invoke_with_session`。
**主网（vault 9-07 / anonymizer 9-07）同样缺 P1-2 入口，上主网前须同批重部署。**

| 项 | 值 |
| --- | --- |
| 新 vault 类 | `0x6de64f9a3388e8224b17b21094f7a4e1435e6026868c8298146bbda17f0c60b`（declare TX `0x35ec65f4...`） |
| 新 anonymizer 类 | `0x6dbb1f827f488beef4d18f2d5535c170d04babed6087776ca7d611a2c750966`（TX `0x49f710fd...`，compiled-hash `Actual 0x3010a6dd...` 显式重试） |
| 新 vault 地址 | `0x1b1b7b37a14ac3b53930d2c5704a08c482d1d6b800626011f799b29f1549438`（deploy TX `0x319b254b...`，构造 `[owner, canonical STRK, 0]`） |
| 新 anonymizer 地址 | `0x335db85a326271f23e7c199b464e67200d8c9fa7570da9807f50ed31fcddf4e`（TX `0x12f903ce...`，构造 `[owner, 新vault, 池 0x0254a6b...]`） |
| 新 dual v6 实例 | `0x66daeeeeb47fdf756d57c24aa64c392441f8b9eb2bab74928c945cfac034a80`（TX `0x3139ad47...`；dual 无 set_vault，换 vault 必须重部署实例；类仍 `0x255cafe3...`） |
| 接线 | vault.settlement=新dual（`0x53172c21...`）、unshield/authorized=新anonymizer（`0x267c38a5...`/`0xf838e6a3...`）；dual.claim_helper/circuit/虚拟OS 占位 三笔（`0x7a299872...`/`0x2b24d1fe...`/`0x7e064ff3...`）全部 SUCCEEDED，视图回读核验 ✓（`session_tx_pk` 入口已存在） |
| 结算冒烟 | 新绑定上 `SEPOLIA_SETTLE_SMOKE_OK`（TX `0x42644423...`，l2_gas 8,070,480） |

**迁移**：旧 vault `0x0629385f...`（total_chips ≈10.38 STRK）保留可提——玩家
自行 `withdraw` 后在新 vault 重新买入；旧 dual 实例 `0x7481ddcd...` 与旧
anonymizer `0x7ee059dd...` 原地保留不再接线。

env：`texas/.env`、`texas/.env.test`、`client/.env.development`（vault +
anonymizer）均已切换。

**遗留（另案）**：私密领取经 Ready 钱包的 Avnu paymaster 提交报
`PaymasterV2Error 156 TRANSACTION_EXECUTION_ERROR`（交易不上链，无 revert 可查）。
合约腿已被 Sepolia fork 测试证明健康（`poker_contracts/tests/unshield_fork.cairo`），
同流程 2026-09-08 曾成功（TX `0x3970a9d6...`）；客户端已加干跑二分诊断
（`strk20PrepareInvoke` 失败路径自动区分钱包层/paymaster 层）。
**2026-09-19 根因实锤**（Avnu paymaster 响应 `data.execution_error`，由 Ready
Shield 实测取得）：
`Invalid proof facts: Virtual OS config hash mismatch. Computed
780173824077612199657331940007038546159930121571926143361206405091891673285
(0x1b9900f7...), expected 155353494348665658624236724160728902643094265960890343456308270214333914199
(0x57ed4d5e...)` —— Ready X 证明器的虚拟 OS 配置哈希与验证端钉扎值版本错位，
属钱包/基础设施侧问题（钱包原生 Shield 同样 156；直付非代发的池交易正常）。
→ 已反馈 Ready/Avnu；期间私密出金以 Public withdrawal 兜底。
**G2 旁证**：本次实测同时给出当前活跃证明器的 virtual OS config hash 真实样本
`0x1b9900f7...`（与我们的占位 `0x602b02cf...`、验证端 `0x57ed4d5e...` 均不同）
——正式钉扎仍须以**本方 settle 流程**的 `snops dump-proof-facts` 实测为准。

## 主网迁移清单（sepolia 重测通过后执行）

1. `CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh` 流程基础上新增 v6 步骤：
   declare（同 sepolia，prepared 资金 ≥ 60 STRK 余量即可，仅 declare+deploy+接线）
   → deploy `[owner, vault, prover]` → set_claim_helper / set_circuit_program_hash
   / set_virtual_snos_program_hash → vault `set_settlement_contract(v6)`。
   **另须同批重部署 vault + anonymizer（P1-2 类漂移，主网在网类为 9-07 之前的
   旧类，缺 `set_session_tx_pk` → 桌面买入必挂）+ 重部署 dual v6 实例绑新
   vault + 全套接线；主网 vault 存量玩家余额需公告自提后在新 vault 重买。**
2. **先满足 G2**：sepolia 上用真实 SNIP-36 proved 交易实测 proof_facts
   （`snops dump-proof-facts`），修正 `virtual_snos_program_hash` 后再切主网
   `STARKNET_DAPV_SETTLE_ENTRY=snip36`；在此之前主网 v6 仅走 fact-registry 腿
   （与 v5 行为等价，无需急于切）。
3. 回退：主网 env 指回 v5 `0x1d39b80b...` + vault 重绑回 v5（两笔 owner invoke）。
4. 回填 strk20.json（mainnet 块）/ 本文档 / server-client env。
