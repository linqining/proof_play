---
title: PLAY 试玩与网络配置
lang: zh-CN
section: getting-started
description: devnet 网络参数、PLAY 筹码获取与软确认体验边界。
lead: PLAY 是测试/娱乐筹码：软确认即可提供快速体验，不涉及真实资金。
---

## 网络参数（devnet）

| 参数 | 值 |
|---|---|
| 网络名 | `zchain-poker-devnet` |
| 环境 | devnet（每个开发者本地可自建） |
| 费用 | 游戏操作免 gas |
| 原生代币 | 无"必须购买才能使用"的原生代币（plan §6.1） |
| 最终性 | soft accepted 与 proven；BFT ordered / finalized 未上线 |

钱包连接按网络隔离：devnet/testnet 客户端不得误连 mainnet（客户端将内建网络校验）。

## 获取 PLAY

devnet 本地运行时，PLAY note 由铸币入口创建（`Deposit` 操作，`asset_class = PLAY`）；testnet 将提供 faucet。PLAY 面额为 u64，无小数位。

## 软确认体验边界

- 下注操作返回 soft accepted 时显示 frame index 与状态根；这只是运营方承诺。
- 手牌结算后可读取 SettlementPlan、rake 与 payout root。
- PLAY 提现豁免 finality 双重门槛（对比 REAL，见<a href="/docs/protocol/abi/">ABI §9</a>）。
- PLAY 与 REAL 物理隔离：不可互转、不可混树（AIR 层强制）。

## 常见问题

**桌准入被拒？** 检查 table_id 与策略绑定：开桌时绑定费率策略且无更新路径，桌关闭后不可复用。

**软确认与最终确认的区别？** 见<a href="/docs/concepts/finality/">四阶段最终性</a>。
