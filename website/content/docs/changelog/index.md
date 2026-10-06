---
title: 变更日志
lang: zh-CN
section: changelog
description: docs/ABI 版本、协议变更、迁移与兼容性。
lead: docs v1.3.0-alpha (ABI v1.2.3)；`latest` 只指向已发布 release。
---

## docs v1.3.0-alpha（2026-09-12）

- 首次发布官网与文档站静态层（13 路由 + 13 板块 + 五个公开服务页面层）。
- 协议基线：ABI v1.2 系列（v1.2 + v1.2.1：结算结构三根、scope v2、REAL 出证策略三层门、attestation v2.1、提现 finality 门槛 §9）。
- 版本号集中定义在 `website/build.py` 的 `SITE`（`ABI_VERSION` / `DOCS_VERSION`）。

## 协议变更史（摘要）

| 版本 | 变更 | 兼容性 |
|---|---|---|
| ABI v1.2.1 | §8 REAL 出证策略与 attestation v2.1；§9 提现 finality 门槛 | 未部署，无兼容包袱 |
| ABI v1.2 | SettlementRecord.plan、NoteSpec.pot_index/runout_index、HandProofBinding 前后根、settlement_binding/settle_effect 新摘要输入、scope v2 | borsh 尾缀追加 |
| ABI v1.1 | SettlementRecord.hand_proof 可选绑定 | 尾缀追加 |
| ABI v1.0 | M0 冻结稿（Note / FeePolicy / 软确认帧 / 操作集） | 基线 |

## 迁移与兼容性纪律

- 所有跨边界结构 borsh；变更必须升版本号（域标签 `.v2` / 新枚举变体）。
- 已冻结域标签（note/nullifier/batch_root/plan/payout_root 等）永不复用。
- 未部署前无兼容包袱；部署后按迁移手册执行（首份迁移手册随 testnet release 发布）。
