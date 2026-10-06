---
title: 系统架构
lang: zh-CN
section: architecture
description: Appchain 分层、证明管道、Vault 边界、DA 与抗审查设计现状。
lead: 三层职责划分：桌级执行负责体验，证明管道负责结算正确性，Vault/退出协议负责外部资产。
---

## 分层

| 层 | 职责 | v1 状态 |
|---|---|---|
| 桌级执行（Sequencer + 软确认链） | 毫秒级操作反馈、准入、限流 | 完成（ForceInclude 未完成） |
| 结算核心（poker-settlement-core） | SettlementPlan / SidePot / rake 单一事实源 | 完成 |
| Note 账本 | 承诺树 + nullifier + 资产类隔离 | 完成 |
| 证明管道 | 批次、出证、降级、背压、连续水位 | 完成（机制）；stwo 真实出证已打通 |
| 费率模块 | 策略注册表 + 分账 + 审计导出 | 完成（审计导出工具部分） |
| Vault / 出入金 | 托管账 + 对账 + 幂等 + finality 门 | 托管侧完成；链上侧未接线 |
| 锚定层（Starknet） | Vault verifier、withdrawal root | Phase 2，未开始 |
| DA / 抗审查 | relay SeenReceipt、ForceInclude、DA 请求 | v1.5 路线，未开始 |

## 模块落点（仓库）

| 模块 | 落点 |
|---|---|
| M1 Note 账本 | `poker-appchain/src/{note,merkle,nullifier_set}.rs` |
| M2 结算 | `poker-settlement-core/` + `settlement.rs` |
| M3 Sequencer | `sequencer.rs` `soft_confirm.rs` `wal.rs` |
| M4 证明管道 | `pipeline.rs` + `poker-appchain-texasair/` |
| M5 费率 | `fee.rs` |
| M7 出入金 | `vault.rs` |
| M8 安全 | `tests/attacks.rs` `watcher.rs` `real_policy.rs` |
| M9 可观测 | `metrics.rs` `bin/loadtest.rs` |

## 证明管道设计

- 按桌并行、按批次出证；批次锚定批次根（Poseidon，ABI §7）。
- 失败处理：prove 失败/panic 带退避重试不丢任务；批次验证失败不丢 completion。
- 水位：`mark_proven` 只推进最大连续前缀；管道 → 水位经 `ProvenCallback` 接线；重启后由管道对已验证批次重新回调恢复。

## Vault 边界

Vault 管理外部资产与链内 REAL 的映射：充值（托管账 + 对账 + 幂等）、提现（finality 双重门槛 + provenance 查询）。v1 的 Vault 是<strong>托管模型</strong>：它是运营方负债的记账边界，不是无信任出口。Phase 2 的 Vault verifier + withdrawal root + 挑战期才构成密码学退出。

## DA 与抗审查（设计现状，如实）

目标形态：relay SeenReceipt（用户提交后获得"已见"回执）→ inclusion deadline 未包含时任意 validator 提交 `ForceIncludeTx`（2 个 checkpoint 内包含）→ DA 层保证数据可用。<strong>当前均未实现</strong>；单 Sequencer 可以拒绝或延迟受理交易，这是 v1 的明示边界。相关验收项 M3-ACC-6/7、M8-ACC-8 见技术方案 §5.6。
