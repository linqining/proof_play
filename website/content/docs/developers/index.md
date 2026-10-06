---
title: 开发者指南
lang: zh-CN
section: developers
description: RPC、事件、错误码、限流与重试。
lead: 面向集成者的操作参考；自动生成 API 文档待接入。
---

| 页面 | 内容 |
|---|---|
| <a href="/docs/developers/rpc/">RPC 与事件</a> | JSON-RPC 方法、事件形状（手工参考层） |
| <a href="/docs/developers/errors/">错误码与重试</a> | 错误分类、幂等键、重试语义 |

## 集成清单

1. 按<a href="/docs/getting-started/quickstart/">quickstart</a>起本地 devnet。
2. 选定资产类：集成示例只允许 PLAY；REAL 需要 REAL 白名单与 finality 门（v1 不对公众开放）。
3. 实现签名：owner ECDSA（secp256k1，64B compact）覆盖 `spend_digest`；sequencer 侧 ed25519 签帧。
4. 处理最终性：UI 按 soft accepted / proven 两级展示（v1）；不要把软确认渲染为最终确认。
5. 监控水位：`proven_watermark`、批次根覆盖、`real_settlement_rejected_total`。
