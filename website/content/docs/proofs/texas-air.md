---
title: Texas AIR 与公开输入
lang: zh-CN
section: proofs
description: canonical tagged AIR 概述、scope v2 公开输入字段表、状态镜像偏移。
lead: 公开输入决定"证明了什么"；本页逐字段列出 scope v2。
---

## AIR 概述

Texas canonical tagged AIR 是手写约束的 STARK AIR，覆盖：

- 牌局状态转移（洗牌/发牌承诺、下注动作、街推进、摊牌）；
- 状态镜像链：每个转移绑定 pre/post 镜像承诺；
- nullifier 消耗与 custody 恒等式（盲注面额自 hand-start 镜像起被覆盖）；
- rake opening（可选）：`min(floor(pot·bps/10⁴), cap, pot)`，mode 0 → 0。

一批次可含多手（`first/last_hand_id`），单 canonical batch 出一张证明；E2E 正例为 3 人 REAL 桌完整一手单批次出证。

## 公开输入：TexasArchiveScope v2 字段表

borsh 字段序与 `ArchivedCanonicalTaggedProof` 公开字段逐字段一致：

| 字段 | 类型 | 说明 |
|---|---|---|
| `log_size`, `num_columns` | u32 × 2 | AIR trace 形状 |
| `table_id` | u64 | 桌标识，与结算记录一致 |
| `first_hand_id`, `last_hand_id` | u32 × 2 | 手边界 |
| `first_call_seq`, `last_call_seq` | u32 × 2 | 调用序列边界 |
| `transition_count` | u16 | 转移数（&gt; 0 才有效） |
| `first/last_transition_kind` | u8 × 2 | 首末转移类型 |
| `reveal_timeout_cascade_count` / `_schedule` | u8, [u8;9] | 揭牌超时级联 |
| `batch_digest` | [u8;32] | 批次摘要 |
| `pre/post_state_commitment` | [u8;32] × 2 | 首/终态承诺 |
| `pre/post_state_root` | [u8;32] × 2 | 首/终态 SMT 根（v1.2 绑定进 attestation） |
| `pre/post_lifecycle_root` | [u8;32] × 2 | 生命周期子状态根 |
| `pre/post_overlay_root` | [u8;32] × 2 | 覆盖层子状态根 |
| `pre/post_settlement_commitment` | [u8;32] × 2 | 结算承诺 |
| `pre/post_custody_commitment` | [u8;32] × 2 | 托管承诺 |
| `pre/post_state_image_bytes` | Vec&lt;u8&gt; | 定宽状态镜像（CanonicalStateImage v5，1680B） |
| `range_claimed_sum` | [u32;4] | 范围声明累计 |
| `rake_opening` | Option | `RakeOpeningScope { rake_mode, rake_bps, rake_cap }` |
| `blind_opening` | Option | `BlindOpeningScope { small_blind, big_blind, ante_mode, ante_amount }` |

尾缀字段（`rules_hash` / `state_object_key` / `state_opening_epoch` / `stark_proof_bytes`）不进镜像；镜像一致性由适配器测试钉住。

## 状态镜像偏移（CanonicalStateImage v5，1680B，u64 LE）

| 偏移 | 字段 |
|---|---|
| 66 | `chip_pool` |
| 74 | `pot`（逐字节绑定 `record.pot`——P0-2） |

镜像字节被 Fiat–Shamir 范围绑定 + 端点投影约束：翻转任一字节都会使证明验证失败（深度篡改负例已验证）。

## 结算侧绑定

证明不单独生效：`SettlementRecord` 校验要求 scope 的 table_id、终态承诺、pre/post_state_root 与声明一致，`pot` 与 `record.pot` 逐字节相等，rake opening 与费率公式一致。关系见<a href="/docs/protocol/abi/">ABI 摘要 §4</a>。
