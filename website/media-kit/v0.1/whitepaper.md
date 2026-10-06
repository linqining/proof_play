# ProofPlay Poker 技术白皮书（工作稿 v0.1）

> 母品牌 ProofPlay（历史工作名 ZChain） · devnet 阶段 · 2026-09-12。本文是技术方案（zchain 仓库 `docs/plan-appchain-v1.md`）
> 与 ABI 规范（zchain 仓库 `poker-appchain/docs/ABI.md`）的对外压缩版；两份源文件优先级高于本文。

## 1. 系统模型

**定位**：面向扑克场景的专用 Appchain（Hyperliquid 式）：链内无 gas，收入来自 rake；防滥用由封闭操作集 + 桌准入 + 限流给出，不依赖定价。

**分层**：

1. **桌级执行层**：单 Sequencer 维护软确认链（`SoftConfirmFrame`：index / prev_hash / op / state_root / ts_ms，ed25519 签名）。毫秒级反馈；WAL append + fsync 原子提交。
2. **账本与结算层**：Note 账本（承诺树 + nullifier 集 + 资产类物理隔离）+ 结算核心 `poker-settlement-core`（SettlementPlan / SidePot / RunoutSchedule / PayoutVector / rake 的单一事实源）。
3. **证明层**：按批次出证的 STARK 管道；批次锚定批次根；连续水位只推进最大连续前缀。
4. **资产边界层**：Vault 托管账（充值/提现/对账/finality 门）。v1 为托管模型；Phase 2 升级为 Starknet Vault verifier + withdrawal root + 挑战期。

**资产**：`PLAY`（测试/娱乐，软确认即可提）与 `REAL`（托管真实资产映射，AIR 层隔离，提现要求双重 finality）。

**操作集**（封闭，新操作 = 协议版本升级）：OpenTable / CloseTable / Deposit / WithdrawRequest / Transfer / BuyIn / Settle。

## 2. 协议 ABI 摘要（v1.2.x）

- **编码**：borsh；哈希双轨——AIR 绑定层用 Poseidon252（承诺树、批次根、结算绑定、策略承诺），字节对象根用 blake2b-256 + 域标签（plan_digest / payout_root / side_pot_root）；32B 与域元素之间 hi/lo 无损拆分。
- **Note**：`{asset_class, amount, owner(33B secp256k1), nonce(32B), table_id?}`；承诺树深度 32（Poseidon）；nullifier 集插入序确定性折叠；零值拒绝。
- **FeePolicy**：`Zero | FixedRake { rate_bps, cap, split }`；开桌绑定，无更新路径。
- **结算记录**：v1.2 起 `record.pot` 必须等于 `plan.gross_pot`（pot 从已验证计划派生）；三个结构根（plan_digest / payout_root / side_pot_root）+ `PayoutLeaf` 五元组 + 玩家 `spend_digest` 签名覆盖 `settle_effect`（含 payout_root）。
- **批次根**：Poseidon 折叠，域 `poker-appchain.batch_root.v1`，golden vector 冻结（`00f6fae9…33c52`）。
- **REAL 出证**：`RealSettlementPolicy` 默认 `StarkRequired`（fail-closed）+ verifier key 钉扎 + 三层门（引擎/提交/批次）；attestation v2.1（192B）覆盖 verifier key、引擎版本、pre/post 状态根、plan_digest。
- **提现门槛**：REAL 要求 `proven_watermark ≥ op_index` 且批次根覆盖（`None` 一律拒绝）；PLAY 豁免。

## 3. 结算公式

**守恒**：`Σinputs == Σpayouts + Σrake == plan.gross_pot == record.pot == 已证明终态镜像 pot`（镜像偏移 74，字节级）。

**费率**：`rake = min(floor(rake_base × rate_bps / 10⁴), cap)`，`rake_base` = contested 层 gross 之和（uncalled 返还不计费）；`treasury = floor(rake × treasury_bps / 10⁴)`，`operator = rake − treasury`。AIR 侧 rake opening 同式；mode 0 → 0。

**签名绑定**：`spend_digest = blake2s(DOMAIN, commitment, nullifier, scope, effect)`，effect 含 payout_root——sequencer 无法把授权改打给别人。

计费口径（B9 已统一，如实）：`rake_base` = contested 层 gross 之和，uncalled 返还不计费；poker_l1 与 appchain 同一口径（ABI v1.2.2），含 uncalled 手已出 e2e 正例。个别边界终局形态（如 raked-sole-survivor）仍 fail-closed 拒绝。

## 4. 证明边界

- **证明了什么**：canonical tagged AIR 覆盖手牌状态转移链、nullifier 消耗、custody 恒等式、（可选）rake opening；公开输入（scope v2）逐字段镜像归档布局，含 pre/post 状态根与逐字节 pot。
- **没证明什么**：运营方活性（受理/延迟不受证明约束）；托管方偿付能力（链外守恒靠对账，Phase 2 前无外部可验证方案）；信息层对手合谋在托管模型内不能被密码学排除。
- **验证器**：stwo 2.3；独立 CLI（`poker-wallet verify`，钱包 crate 由并行工作提供）；浏览器 WASM 验证随 proof portal 提供；verifier 版本占位 `texas-air-v2`。

## 5. 威胁模型（摘要）

| 攻击者 | 能力上限 | 约束 |
|---|---|---|
| 恶意 Sequencer | 审查、延迟、停机；试图改赔付 | 改赔付被 effect 签名阻断；结算必须过 11 条 fail-closed 校验 + STARK 验证；行为可被 watcher 取证 |
| 恶意 Prover | 提交假证明 | stwo 验证拒绝；三层门保证 REAL 只认 texas-air 路径 |
| 恶意玩家 | 双花、伪造守恒 | nullifier 集 + 守恒校验拒绝 |
| 托管方 | 挪用外部资产 | **v1 无密码学约束**——核心风险，靠对账报告 + Phase 2 Vault verifier 缓解 |

## 6. 性能方法

- 软确认预算 100ms；devnet 压测（64 桌 × 50 手 → 3200 结算 / 16064 操作）p50 2.1ms / p99 3.5ms（参考机口径，随发布附硬件/网络/并发/样本）。
- 证明管道：按桌并行、批次出证、失败退避重试、背压；水位只推进连续前缀（乱序/失败/崩溃不错推）。
- 报告纪律（M9-ACC-4）：soft-confirm / BFT finality / proof-ready / claimable 四段延迟分别报告，不以 TPH 或交易数替代。

## 7. 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| Phase 0 | 结算核心、P0 修复、连续水位、ABI/hash 冻结 | 完成 |
| Phase 1 (MVP) | 单 Sequencer + 多入口 + ForceInclude + 托管出入金（REAL 受控小流量） | 进行中（ForceInclude/链上出入金未完成） |
| Phase 1.5 | 4–7 validator HotStuff-2/Jolteon checkpoint、阈值 BLS、DA、bond/slash | 未开始 |
| Phase 2 | Starknet Vault verifier、withdrawal root、挑战/退出、储备证明类能力 | 未开始 |
| Phase 3 | table sharding、Narwhal 风格 mempool、多运营方、B2B SLA | 未开始 |

在 Phase 1.5 / Phase 2 完成前，不宣称抗审查最终性、无信任提现或链上合约独立保证的 REAL 结算。
