---
title: 技术
lang: zh-CN
section: technology
lead: Appchain、Note 账本、Texas AIR 证明、Sequencer 与 BFT 路线。v1 为单 Sequencer 托管网络。
---

## 总体架构

```
┌─ ProofPlay Poker Appchain ───────────────────────────┐
│  Sequencer：软确认链 / 查重 / 桌准入 / 限流 / WAL         │
│      ↓                                                   │
│  Note 账本：承诺树(Poseidon, 深32) + nullifier 集          │
│      + 资产类隔离（REAL/PLAY 不可互转、不可混树）            │
│      ↓                                                   │
│  结算核心：poker-settlement-core（单一事实源）              │
│      SettlementPlan / SidePot / PayoutVector / rake      │
│      ↓                                                   │
│  证明管道：批次 / 降级 / 背压 / 连续水位                    │
│      ↓                                                   │
│  费率模块：策略注册表 ZERO | FIXED_RAKE + 分账 + 审计       │
└─────────────────────────────────────────────────────────┘
外部：Starknet（v1 仅预留收款通道；Phase 2 锚定层候选）
```

链内无 gas：游戏操作免 gas，收入来自 rake；费率是状态机里的数据（策略注册表），不是协议参数。

## Note 账本

- note = `asset_class(REAL|PLAY)` + 面额(u64) + owner(secp256k1 压缩公钥) + nonce + 可选 table_id。
- 承诺树：Poseidon 深度 32 Merkle；nullifier 集按插入序确定性折叠。
- 花费需要 owner ECDSA 签名，`spend_digest` 绑定 commitment、nullifier、scope 与 effect——sequencer 无法把授权改打给别人。
- 资产类隔离是 AIR 层不变量，不只是业务层校验。

## Texas AIR 与证明管道

- 证明系统：Texas canonical AIR（手写约束），stwo 2.3 circle-STARK，Stark curve；适配器 crate `poker-appchain-texasair` 走 `verify_canonical_tagged_proof` 完整 STARK 验证。
- 一手证明自 hand-start 镜像起，盲注面额由 custody 恒等式覆盖；批次归档绑定 table、pre/post 状态根与逐字节 pot 镜像（偏移 74）。
- 管道：批次构建、失败退避重试、背压；`mark_proven` 只推进最大连续前缀（缺口不推进水位）。
- REAL 三层门：引擎层 / 管道准入层 / 批次水位层，全部默认收紧（详见 <a href="/docs/protocol/abi/">ABI §8</a>）。

## Sequencer 与软确认

- 软确认帧 `SoftConfirmFrame` 链式哈希 + ed25519 签名；WAL append + 真 fsync 原子提交，失败零状态变更。
- 操作集封闭为 7 个（OpenTable / CloseTable / Deposit / WithdrawRequest / Transfer / BuyIn / Settle），新操作 = 协议版本升级。
- 状态根由 Poseidon 折叠（树根、nullifier 根、注册表根、桌折叠、seq、spent_count、proven_watermark）。

## 共识路线（如实标注）

| 阶段 | 内容 | 状态 |
|---|---|---|
| v1 | 单 Sequencer + watcher 分叉检测 | **进行中**（核心已验证；ForceInclude 未完成） |
| v1.5 | 4–7 validator HotStuff-2/Jolteon checkpoint、阈值 BLS、DA、bond/slash | 未开始 |
| v2 | Starknet Vault verifier、withdrawal root、挑战/退出协议 | 未开始 |
| v3 | table sharding、Narwhal 风格 mempool、多运营方 | 未开始 |

多节点现状：`scripts/multi_node_e2e.sh` 已验证 3/4 节点全收敛（skew=0）、4 节点 kill-one 容错（quorum(4)=3）与重启追块。这是组网验收，不等于 BFT checkpoint 上线。

<div class="notice">
<p>在 v1.5 与 Phase 2 完成前，本项目不宣称抗审查最终性、无信任提现或"REAL 结算由链上合约独立保证"。当前活性与提现依赖运营方，风险已在<a href="/security/">安全页</a>与<a href="/legal/">法务页</a>披露。</p>
</div>

深入阅读：<a href="/docs/architecture/">系统架构文档</a>、<a href="/docs/protocol/abi/">ABI 规范</a>、<a href="/docs/proofs/">证明系统</a>。
