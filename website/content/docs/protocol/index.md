---
title: 协议规范
lang: zh-CN
section: protocol
description: ABI、Operation、SoftConfirmFrame、SettlementPlan。
lead: wire format 的唯一事实源是仓库内 poker-appchain/docs/ABI.md；本板块是其导读与摘要。
---

| 页面 | 内容 |
|---|---|
| <a href="/docs/protocol/abi/">ABI 摘要（v1.2.x）</a> | 编码原语、Note、FeePolicy、结算记录、批次根、attestation、finality 门槛 |
| <a href="/docs/protocol/operations/">Operation 与软确认帧</a> | 封闭操作集、帧格式、状态根折叠 |

## 规范地位与版本

- 源文件：仓库内 `poker-appchain/docs/ABI.md`（v1.2 系列：v1.2 / v1.2.1 追加 REAL 出证策略、attestation v2.1、提现 finality 门槛）。
- 所有跨边界结构走 borsh；任何变更必须升版本号（`.v2` 域标签 / 新枚举变体）。
- 域标签常量（`note.commitment.v1`、`batch_root.v1`、`zchain.texas_poker.settlement_plan.v2` 等）一旦冻结不再变更。
