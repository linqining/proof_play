# 可引用项目事实表（fact-sheet）v0.1

> 数据截至 2026-09-12，来源为本仓库（workspace 构建 + 测试）与 zchain 仓库（github.com/linqining/zchain）的 `docs/plan-appchain-v1.md`。
> 引用规则：数字必须与本表一致；引用性能数字必须连同口径（硬件、并发、样本、分位数）一起引用。

## 项目身份

| 项 | 值 |
|---|---|
| 项目名 | ProofPlay Poker（历史工作名：ZChain Poker / ZChain Poker L1） |
| 当前网络 | devnet（`zchain-poker-devnet`） |
| 原生费用 | 游戏操作免 gas；收入 = rake；无原生代币 |
| 资产 | PLAY（测试/娱乐筹码）、REAL（托管真实资产映射），AIR 层物理隔离 |
| 官网/文档域名 | zchain.example / docs.zchain.example（占位，上线前替换） |

## 协议（可验证）

| 事实 | 值/来源 |
|---|---|
| ABI 版本 | v1.2 系列（v1.2 + v1.2.1，2026-09-12）；`poker-appchain/docs/ABI.md` |
| 结算核心 | `poker-settlement-core`：SettlementPlan / SidePot / RunoutSchedule / PayoutVector / rake / plan_digest（域 `zchain.texas_poker.settlement_plan.v2`，冻结） |
| 批次根 | Poseidon，域 `poker-appchain.batch_root.v1`；golden vector：bindings `[0xAA;32],[0xBB;32]` → `00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52` |
| attestation | v2.1，payload 192B（post_state_commitment / post_state_root / pre_state_root / plan_digest / ed25519） |
| 提现门槛 | REAL：proven watermark ≥ op_index 且批次根覆盖；PLAY 豁免（ABI §9） |
| 操作集 | 封闭 7 操作（OpenTable/CloseTable/Deposit/WithdrawRequest/Transfer/BuyIn/Settle） |
| rake 公式 | `min(floor(pot × rate_bps / 10⁴), cap)`；费率为链内注册表数据 |

## 证明系统（可验证）

| 事实 | 值 |
|---|---|
| 证明栈 | stwo 2.3（circle-STARK，Stark curve）；`stwo-air-utils` 2.3 |
| AIR | Texas canonical tagged AIR（手写约束，29 选择子、状态镜像链、nullifier）；接口 `verify_canonical_tagged_proof` |
| 适配器 | `poker-appchain-texasair`：真实出证正例 + 深度篡改负例（Fiat–Shamir 流/状态镜像字节翻转均被拒绝） |
| E2E | 3 人 REAL 桌完整一手（盲注镜像、raise/all-in/fold/call、收池）单 canonical batch 真实 stwo 出证；守恒恒等式成立 |
| toolchain | nightly-2026-04-15（rust-toolchain.toml 钉扎） |

## 工程状态（可验证）

| 事实 | 值 |
|---|---|
| 测试 | 工作区 2350+ 通过（poker-appchain 86、poker-settlement-core 26、poker-appchain-texasair 13 含 E2E 正例、zchain bin 17、poker_l1 全套件） |
| P0 | §5.2 八项全部关闭（2026-09-12） |
| 多节点 | 3/4 节点全收敛（skew=0）；4 节点 kill-one 容错（quorum(4)=3）；重启 catch-up 追平 |
| 压测 | 64 桌 × 50 手 → 3200 结算 / 16064 操作；买入软确认 p50 2.1ms / p99 3.5ms（预算 100ms；参考机口径） |

## 未完成 / 边界（必须与成就一起引用）

| 项 | 状态 |
|---|---|
| ForceInclude | 未完成 |
| BFT checkpoint | 未开始（v1.5） |
| 出入金链上侧 | 已接线（VaultProvider Mock/Starknet 双实现、存款幂等桥、提现 finality、对账告警）；线上桥校准待真实环境 |
| permissionless withdrawal | 未开始（Phase 2） |
| 第三方审计 | 未做 |
| 已知协议缺口 | 个别 rake 边界终局形态 fail-closed（计费口径已统一 contested-only，B9）；Revealing→Betting 续链属上游路线 |
| 活性 | 单 Sequencer：停机 = 全场停摆（watcher/告警缓解） |
