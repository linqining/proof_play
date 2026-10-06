---
title: 快速开始
lang: zh-CN
section: getting-started
description: 启动 devnet、试玩 PLAY、验证证明的入口页。
lead: 从克隆仓库到验证一手牌：三条路径，最短 15 分钟。
---

本板块是开发者与玩家进入 ProofPlay Poker devnet（网络与协议标识沿用 ZChain）的入口。

| 页面 | 适合谁 | 内容 |
|---|---|---|
| <a href="/docs/getting-started/quickstart/">15 分钟 quickstart</a> | 开发者 | 克隆 → 构建 → 3 节点 devnet → 完整一手（真实证明）→ 验证 |
| <a href="/docs/getting-started/play/">PLAY 试玩与网络配置</a> | 玩家/测试者 | 网络参数、PLAY 获取、软确认体验边界 |

环境基线（quickstart 假设）：

- Rust toolchain：仓库钉扎 `nightly-2026-04-15`（rust-toolchain.toml；stwo 2.3 prover 需要 nightly 特性）。
- 操作系统：Linux / macOS；Windows 建议 WSL2。
- 无需 GPU；无需第三方服务。
