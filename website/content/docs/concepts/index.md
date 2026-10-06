---
title: 核心概念
lang: zh-CN
section: concepts
description: Note、nullifier、桌、手、rake 与四阶段最终性。
lead: ProofPlay Poker 的状态模型与最终性词汇表。
---

## Note 与 nullifier

链内筹码的唯一真身是 note（UTXO 风格）：

```
Note {
  asset_class: u8        // 1 = REAL, 2 = PLAY
  amount: u64            // > 0
  owner: [u8; 33]        // secp256k1 压缩公钥
  nonce: [u8; 32]        // 铸币方生成，全局唯一
  table_id: Option<u64>  // Some = 桌内 seat note
}
```

- `commitment = poseidon(DOMAIN_NOTE_COMMITMENT, ...)` 进入深度 32 的 Poseidon Merkle 承诺树；叶为 commitment 域元素。
- `nullifier = poseidon(DOMAIN_NOTE_NULLIFIER, commitment, secret_hi, secret_lo)`；`spend_secret` 只在客户端，账本不持有。
- 花费 = 提交 nullifier + owner ECDSA 签名；nullifier 集防双花，根按插入序确定性折叠。
- 零值拒绝：`amount == 0`、全零 nullifier（griefing 防御）。

## 桌与手

- <strong>桌（table）</strong>：开桌（`OpenTable`）时绑定费率策略（`FeePolicy`），绑定后<strong>无更新路径</strong>；同策略重绑定幂等。
- <strong>手（hand）</strong>：一手从 hand-start 镜像开始，经下注/发牌转移，以 `Settle` 结束。结算记录带 `hand_binding`（防重放键）。
- <strong>seat note</strong>：买入后桌内筹码以 `table_id = Some(id)` 的 note 表示；本手下注贡献即 seat note 输入，`Σinputs == gross_pot`。

## rake

rake 是平台的抽水，也是这条链唯一的收入来源（游戏操作免 gas）：

- 策略只有两种：`ZERO`（零费）与 `FIXED_RAKE { rate_bps, cap, split }`。
- `rake_of(pot) = min(floor(pot × rate_bps / 10000), cap)`；rake 再按 `treasury_bps` 分账，零头归 operator。
- rake 是<strong>状态机里的数据</strong>（策略注册表 + 结算记录字段），进入证明绑定，可审计。
- 完整公式、contested 口径与守恒关系见<a href="/docs/economics/rake/">经济模型</a>。

## 四阶段最终性

```
soft accepted → BFT ordered → proven → finalized/claimable
```

| 阶段 | 谁给出 | v1 状态 |
|---|---|---|
| soft accepted | Sequencer 软确认链（毫秒级） | 已达到 |
| BFT ordered | 多 validator BFT 排序 | 未上线（v1.5） |
| proven | 证明管道：批次经 STARK 验证，水位连续推进 | 已达到 |
| finalized/claimable | 提现 finality 门槛满足 | REAL 门槛已实现；permissionless claim 未上线（Phase 2） |

软确认只代表运营方承诺，不代表 BFT 最终性，也不能单独授权 REAL 提现；REAL 需要 proven 水位 + 批次根双重门槛。

## 批次与批次根

证明按批次组织。批次根（`BatchRoot`）用 Poseidon 折叠批内结算绑定（帧序排列，无空洞），域标签 `poker-appchain.batch_root.v1`，golden vector 冻结在 ABI §7。批次根是后续 L1 锚定与提现 finality 证据的基础。
