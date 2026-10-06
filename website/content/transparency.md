---
title: 透明度
lang: zh-CN
section: transparency
lead: 托管对账、运营方签名报告、提现队列与服务指标。v1 只展示托管对账——本页不构成任何偿付保证。
sample: true
sample-note: 本页全部数字为 SAMPLE DATA / devnet 示例，用于展示报告结构与数据口径；生产数据由透明度服务按月出具。
custody: true
---

## 本页边界（先说清楚）

- v1 的 Transparency 页面<strong>只能展示托管对账和运营方签名报告</strong>。
- 本页<strong>不是</strong>"储备证明"，也不是"链上偿付保证"；外部可独立验证偿付的能力（第三方 verifier + Vault root）属于 Phase 2 路线。在那之前，本页与月度报告不使用任何暗示偿付已被独立证明的命名。
- 托管对账 ≠ 偿付保证：数字由运营方出具并签名，存在人工调整的可能；每份报告注明数据时间、来源与是否人工调整。

## 托管对账（SAMPLE DATA / devnet，月度结构）

| 指标 | 数值（示例） | 说明 |
|---|---|---|
| 已发行 REAL | 0 | v1 REAL 未对公众开放 |
| 已销毁 REAL | 0 | 提现销毁 |
| 托管 hot wallet 余额 | 12,400.00（示例） | 与链内 PLAY note 无互抵关系（资产类隔离） |
| 待提现队列 | 3 笔 / 860.00（示例） | 均已过 finality 门槛 |
| 已完成提现（当月） | 41 笔 / 21,300.00（示例） | 平均处理 6.2h（示例） |
| 对账差异 | 0.00 | 非零差异必须附事件链接与说明 |
| 数据时间 / 来源 | 2026-08-31T23:59 UTC / 运营方托管账导出 | 是否人工调整：否（示例） |

运营方签名报告：每期报告附运营方 ed25519 签名（覆盖报告哈希），签名方案与 attestation v2.1 同源；验签命令随后续透明度服务一起发布。

## 服务指标（结构示例，SAMPLE DATA）

按 §6.10 口径，每项指标附定义、数据源、时间窗口与"不可用/延迟数据"标记：

| 类别 | 指标 | 当期（示例） |
|---|---|---|
| 体验 | soft-confirm p50 / p95 / p99 | 2.1ms / 2.9ms / 3.5ms（64 桌压测口径） |
| 正确性 | proof verify 成功率 | 100%（E2E + 负例回归口径） |
| 正确性 | settlement 覆盖率 | 100%（全部结算带 plan） |
| 活性 | Sequencer uptime | 99.2%（当月，示例） |
| 资金 | 对账差异 | 0.00（示例） |

本页不以 TPH、注册数或交易数替代资金安全与证明覆盖率指标。

## 提现队列（结构示例）

| 请求 id | 申请时间 | 状态 | 门槛证据 |
|---|---|---|---|
| wd-0041 | 2026-09-12 07:02 | <span class="st st-warn">finalized / 打款中</span> | watermark ≥ op，批次根覆盖 |
| wd-0040 | 2026-09-12 06:44 | <span class="st st-warn">finalized / 打款中</span> | watermark ≥ op，批次根覆盖 |
| wd-0039 | 2026-09-11 22:15 | <span class="st st-ok">已完成</span> | 回执哈希已归档 |

PLAY 提现豁免 finality 双重门槛（软确认即可提）；REAL 提现未达门槛会被拒绝并计数（`withdrawal_finality_rejected_total`）。

## 与路线图的关系

外部可独立验证的偿付能力（Vault root + 第三方 verifier + 挑战期）属于 <a href="/roadmap/">Phase 2</a>。在那之前，用户对托管方的债权凭据是托管账与对账报告本身——这是 v1 托管模式的已知边界，已在<a href="/legal/">法务页</a>作为风险披露。
