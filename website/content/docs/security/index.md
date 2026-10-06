---
title: 安全
lang: zh-CN
section: security
description: 威胁模型、审计报告、漏洞披露、暂停和恢复。
lead: 安全状态如实公开：未做第三方审计；已知的边界写在明面上。
---

| 页面 | 内容 |
|---|---|
| <a href="/docs/security/threat-model/">威胁模型</a> | 信任边界、攻击面、守恒与三层门的数学表述 |
| <a href="/docs/security/disclosure/">漏洞披露</a> | 报告渠道、SLA、公告归档 |

## 当前安全状态

| 项 | 状态 |
|---|---|
| 第三方审计 | 未做（Mainnet candidate 阶段安排；报告将注明范围/commit/未修复问题/日期/不覆盖组件） |
| 内部回归 | 6 类攻击回归 + watcher 分叉检测 + 证明负例矩阵 |
| P0 | §5.2 八项已全部关闭（2026-09-12） |
| 已知遗留 | ForceInclude / BFT checkpoint 未上线；出入金线上桥校准待真实环境；个别 rake 边界终局形态 fail-closed；单 Sequencer 活性 |

安全页面公开当前状态而不是只放"已审计"徽章——审计不等于无漏洞保证。
