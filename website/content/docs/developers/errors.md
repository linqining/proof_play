---
title: 错误码与重试
lang: zh-CN
section: developers
description: 错误分类、幂等键与重试语义。
lead: 校验失败不烧掉幂等键；失败路径 fail-closed，唯一变体。
---

## 错误分类

| 类别 | 例 | 集成者动作 |
|---|---|---|
| 准入拒绝 | `AdmissionRejected("real settlement requires hand proof")`、限流 | 不重试；按错误信息修正 |
| 结算校验 | `SettlementReplay`、投影不符、守恒失败、`VerifierKeyMismatch` | 不重试；记录即上报（可能是恶意/缺陷信号） |
| finality 门 | `WithdrawalNotFinalized { op_index, watermark }` | 等水位/批次根推进后重新申请 |
| 传输 | 超时、断连 | 指数退避重试；写操作先查幂等结果 |

## 幂等与重放键

| 操作 | 幂等键 | 语义 |
|---|---|---|
| Deposit | `deposit_id` | 同 id 同载荷重复提交返回既有条目 |
| WithdrawRequest | `request_id` | 已受理的重复申请直接返回既有条目（不受门槛复审影响） |
| Settle | `hand_binding` | 非零、防重放；重放即 `SettlementReplay` |

关键保证（P0-4 修复）：<strong>先校验后变更</strong>——校验失败的操作不会烧掉 `deposit_id` / `request_id` / `hand_binding`，修正版可以用同一键重提。

## 重试语义

- 所有拒绝路径 fail-closed 且变体唯一（同一违规只有一种错误），便于客户端精确处理。
- 管道内部重试（prove 失败退避）对客户端不可见；客户端只见水位推进。
- 重试风暴防护：公共网关限流待上线；本地 devnet 无限流，压测时自行控速。
