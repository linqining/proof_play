---
title: 验证器与审计导出
lang: zh-CN
section: proofs
description: 独立验证命令、verifier 版本与审计导出工具。
lead: 验证不要求运营方私有服务；每个结算/提现/checkpoint 都有独立验证路径。
---

## 独立验证命令

```console
# 钱包侧验证（poker-wallet crate 由并行工作提供；命令以该 crate 发布接口为准）
cargo run -p poker-wallet --release -- verify proof.json

# 适配器验证（开发/审计；含真实出证正例 + 深度篡改负例）
cargo test -p poker-appchain-texasair --release

# 节点侧水位/批次根查询（devnet）
# RPC get_block_count；水位与批次根查询方法见 /docs/developers/rpc/
```

verifier 信息：

| 项 | 值 |
|---|---|
| verifier 版本（占位） | `texas-air-v2` |
| 证明系统 | stwo 2.3（circle-STARK，Stark curve） |
| AIR | Texas canonical tagged（`verify_canonical_tagged_proof`） |
| attestation | v2.1（192B payload，ed25519，verifier key 钉扎） |

浏览器本地验证（WASM verifier + verifier 版本/proof digest/耗时展示）随 proof portal 服务提供；CLI 是不依赖任何服务的基准路径。

## 应验证什么（按角色）

| 角色 | 验证项 | 方式 |
|---|---|---|
| 玩家 | 我的手牌结算与赔付 | proof portal / CLI verify（proof digest 来自 explorer） |
| 审计方 | 守恒、rake、payout 绑定 | 适配器测试 + 结算校验关系（ABI §4，11 条 fail-closed） |
| 托管方 | 提现 finality | `withdrawal_provenance(note)` + 批次根覆盖查询 |
| 监督方 | 水位连续性 | proven watermark + 缺口集（重启后可重建） |

## 审计导出

费率与结算的审计导出（M5）：对任意结算集合导出 `{inputs, payouts, rake.total, split, plan_digest}` 的规范化记录，可离线重算守恒与费率公式。当前状态：<strong>导出工具部分完成</strong>（费率记账与分账已实现，规范化导出命令待发布）；发布后将在此页附命令与输出样例。

## 测试向量

golden vector（冻结进仓库）：

- 批次根：bindings `[0xAA;32], [0xBB;32]` → `00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52`（`pipeline.rs::batch_root_golden_vector`）；
- payout_root：RFC 6962 风格构造 golden vector（`zchain.settlement.payout_root.v1`）；
- attestation：v2 形状对 v2.1 一律验证失败（payload 定长 192B）。
