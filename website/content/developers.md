---
title: 开发者
lang: zh-CN
section: developers
lead: SDK、RPC、ABI、运行节点与示例。从零到验证一手牌的完整入口。
---

## 从这里开始

1. <a href="/docs/getting-started/quickstart/">15 分钟 quickstart</a>：克隆仓库 → 构建 → 起 3 节点 devnet → 跑一手带真实证明的完整牌局。
2. 阅读<a href="/docs/protocol/abi/">协议 ABI 规范</a>（wire format 唯一事实源）。
3. 浏览<a href="/docs/developers/rpc/">RPC 与事件参考</a>、<a href="/docs/developers/errors/">错误码与重试语义</a>。

## 代码仓库

| 入口 | 说明 |
|---|---|
| <a href="https://zchain.example/repo" rel="noopener">主仓库（占位地址）</a> | workspace：poker-appchain、poker-settlement-core、poker-appchain-texasair、poker_l1 等 |
| 构建 | `cargo build --release --bin zchain`（toolchain：nightly-2026-04-15，见 rust-toolchain.toml） |
| 发布纪律 | 每个 release 对应 docs tag、ABI 版本、genesis/config hash、SHA-256 与 SBOM（WEB-ACC-5，待发布流水线） |

## RPC（devnet 示例，静态样例）

JSON-RPC over TCP（newline-delimited）。以下为响应形状示例：

```json
{"id": 1, "result": {"block_count": 18204}}
{"id": 2, "result": {"watermark": {"proven_through": 18196, "batch_root": "0x00f6fae9…"}}}
```

自动生成的 OpenAPI/RPC/ABI 参考页（含正例、负例、错误码、幂等与重试语义）见 <a href="/docs/api-reference/">api-reference 文档板块</a>——该板块当前为手工参考层，自动生成流水线待接入。

## SDK 与工具

| 组件 | 状态 |
|---|---|
| zchain 节点二进制（keygen / node / RPC） | 可用（devnet） |
| poker-appchain 结算库（Rust） | 可用 |
| poker-appchain-texasair 证明适配器 | 可用（真实 stwo 出证/验证） |
| poker-wallet（钱包核心 CLI） | 由并行工作提供（证明验证命令见<a href="/proofs/">证明页</a>） |
| 浏览器 WASM verifier / 钱包插件 | 规划中（plan §6.12） |

## 限流与配额

公共 RPC 网关、API key、webhook 与 SLA 档位属于 Developer portal 服务，当前未上线；本地 devnet 无限流。破坏性变更会通过 changelog 与 `#developers` 频道提前通告（协议升级 = 新操作变体/域标签版本化，不做运行时扩展）。
