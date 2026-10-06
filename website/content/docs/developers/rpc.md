---
title: RPC 与事件
lang: zh-CN
section: developers
description: JSON-RPC 方法参考（手工层，自动生成待接入）。
lead: devnet JSON-RPC over TCP，newline-delimited。以下为已确认存在的形状；自动生成参考含正负例后替代本页。
---

## 已确认方法（节点实现）

| 方法 | 请求 | 响应（形状示例） | 说明 |
|---|---|---|---|
| `get_block_count` | `{"id":1,"method":"get_block_count"}` | `{"id":1,"result":{"block_count":18204}}` | 当前高度（multi_node_e2e 用它验证收敛） |
| `keygen`（CLI） | `zchain keygen --scheme secp256k1` | JSON：`secret_key_hex` / `raw_hex` 等 | 生成 validator/用户密钥 |

## 规划中的查询面（自动生成时定稿）

| 方法（暂名） | 用途 |
|---|---|
| `get_watermark` | proven watermark、批次覆盖（`through_op → batch_root`） |
| `get_hand` / `get_settlement` | 手与结算记录、plan、payout root、proof 归档 |
| `get_table` | 桌与费率策略承诺 |

自动生成要求（§6.4）：从源码 schema 生成，包含正例、负例、错误码、幂等与重试语义；生成流水线接入后本页降级为链接。

## 事件与指标

| 名称 | 类型 | 语义 |
|---|---|---|
| `real_settlement_rejected_total` | counter | REAL 出证在引擎/提交/批次层被拒 |
| `withdrawal_finality_rejected_total` | counter | REAL 提现未达 finality 门 |
| watcher 分叉告警 | alert | 软确认链分叉（WAL 损坏或恶意 sequencer） |

## 传输与框架

- devnet：JSON-RPC over TCP（端口由节点配置指定；multi_node_e2e 从 `RPC_BASE=18545` 起分配）。
- 公共网关的缓存与限流（只读接口）随 Developer portal 上线；钱包签名、提现、外部转账必须二次确认（前端要求，plan §6.2）。
