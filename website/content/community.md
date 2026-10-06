---
title: 社区
lang: zh-CN
section: community
lead: 频道结构、贡献路径与激励说明。当前没有任何代币空投计划。
---

## 频道结构

| 频道 | 用途 | 纪律 |
|---|---|---|
| `#announcements` | 已签名 release、网络变更、事故通告 | 只读；只发已验证信息 |
| `#developers` | SDK、RPC、proof、节点与 issue 讨论 | 破坏性变更提前通告 |
| `#players` | PLAY 试玩、反馈与牌局问题 | 不讨论 REAL 充提细节（走工单） |
| `#security` | 漏洞披露入口 | 不在公开频道发布未修复细节；流程见<a href="/security/">安全页</a> |
| `#validators` | 节点版本、checkpoint、密钥轮换与故障演练 | v1.5 前以节点运维为主 |

频道接入方式（Discord/Telegram/论坛）将在 testnet 发布时固定并公示邀请链接；devnet 阶段以仓库 issue 与 `#developers` 惯例为准。

## 贡献路径

按难度递进：**文档修复 → 测试向量 → verifier/SDK → 节点/共识 → 生态应用**。

每类贡献的统一要求：

- 遵循 `CONTRIBUTING.md`（DCO/CLA 选择、代码风格、测试命令、安全披露规则——随公开仓库一起发布，当前为占位）。
- 测试向量类贡献必须附 golden vector 与验证方式。
- 安全类贡献一律走 `#security` / 披露邮箱，不走公开 PR。

## 激励说明

- 社区激励优先使用 <strong>PLAY 积分</strong>、黑客松奖金或公开署名（contributor 列表、release notes 署名）。
- <strong>没有代币空投</strong>：在治理、分配、监管与审计方案齐备之前，本项目不设计、不宣传"早期参与者代币空投"。任何以本项目名义进行的空投宣传都与本项目无关。
- v1 不以收益或代币升值为产品承诺；任何经济设计另行治理与合规评审。

## 内容节奏

- 每周开发周报（变更、测试、风险），每两周社区演示，每月透明度报告——模板见 <a href="/media-kit/v0.1/templates/weekly-update.md">media-kit/templates</a>。
- 事故期间停止营销内容，优先发布影响范围、用户操作建议与修复时间线。

## 素材与品牌

使用 logo、颜色或文案请遵循 <a href="/media-kit/v0.1/logo-principles.md">media-kit v0.1</a> 的品牌规范；素材均带版本与环境水印（如 `PLAY / devnet / v1.3`）。
