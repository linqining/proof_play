---
title: 经济模型
lang: zh-CN
section: economics
description: rake 公式、分账、托管边界、费用和风险说明。
lead: 链的收入 = rake；游戏操作免 gas。费率是数据，不是协议参数。
---

| 页面 | 内容 |
|---|---|
| <a href="/docs/economics/rake/">rake 公式与分账</a> | FIXED_RAKE 口径（contested-only，B9 已统一）、分账 |
| <a href="/docs/economics/custody/">托管边界</a> | 资金守恒、托管账与对账、REAL 发行边界 |

## 设计原则

1. <strong>无 gas</strong>：游戏操作不收费，防滥用由封闭操作集 + 桌准入 + 限流给出，不依赖定价。
2. <strong>费率即数据</strong>：策略注册表（`table_id → FeePolicy`）在链内，rake 进入结算记录与证明绑定，可审计、可独立重算。
3. <strong>只有两种策略</strong>：`ZERO` 与 `FIXED_RAKE`；新策略 = 协议版本升级。
4. <strong>托管边界清晰</strong>：PLAY 与 REAL 物理隔离；REAL 是运营方负债映射，守恒恒等式约束链内，不约束托管方偿付能力（Phase 2 之前的明示边界）。

## v1 非目标（与经济相关的）

- 不做 B2B API 计费 / SLA 档位（接口预留）。
- 不以收益或代币升值为产品承诺；无原生代币；任何经济设计另行治理与合规评审。
