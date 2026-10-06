---
title: 验证者指南
lang: zh-CN
section: validators
description: 节点部署、validator set 现状、BFT 路线、密钥、监控与升级。
lead: v1 是单 Sequencer 网络；本页如实说明现在能跑什么、BFT 属于哪个阶段。
---

## 现在能做什么（devnet）

- 运行多节点组网验证：`scripts/multi_node_e2e.sh N`（N=3 默认；`scenario_kill_one_of_four.sh`、`scenario_restart_catchup.sh`）。
- 节点能力：genesis validator set（stake 必须为 0，原生质押只能经 UTXO-backed bond 在创世后进入）、TCP P2P 全互联 + 持久拨号/PEX、启动追块（全验块）、JSON-RPC。
- 已验证行为：3/4 节点全收敛（skew=0）；4 节点 kill-one 容错（quorum(4)=3）；n=3 容 0 错（quorum 语义）；重启追平。

## 密钥

```console
zchain keygen --scheme secp256k1   # validator 密钥（JSON：secret_key_hex / raw_hex）
zchain keygen --scheme vrf         # VRF 密钥
```

密钥纪律：validator 密钥离线备份；轮换流程在 v1.5 与 bond/slash 一起定稿；泄露处置走安全公告流程。

## 监控基线

| 监控项 | 方法 |
|---|---|
| 出块活性 | 日志 `commit_round=` / RPC `get_block_count` |
| 高度收敛 | 多节点 `get_block_count` 采样（±1 在途偏差为正常） |
| 证明水位 | proven watermark 连续性、`real_settlement_rejected_total` |
| 分叉 | watcher 告警（软确认链分叉即异常） |

## BFT 路线（v1.5，未开始）

规划：4–7 validator HotStuff-2/Jolteon 风格 checkpoint、阈值 BLS、每桌独立状态分片执行、全局只对批次根/提款根/状态根做最终确认、DA 与 bond/slash。validator 招募、密钥轮换演练与审查演练在 BFT preview 阶段（发布节奏见<a href="/roadmap/">路线图</a>）。

在 BFT 上线前，"验证者"角色限于 devnet 组网验证与观测；不存在质押收益或验证者奖励承诺。
