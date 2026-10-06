---
title: ABI 摘要（v1.2.x）
lang: zh-CN
section: protocol
description: poker-appchain ABI v1.2 系列导读：编码原语、Note、FeePolicy、结算记录三根、批次根、attestation v2.1、提现 finality。
lead: 摘要与导读；wire format 唯一事实源见 poker-appchain/docs/ABI.md（源文件随仓库发布）。
---

> 源文件：<code>poker-appchain/docs/ABI.md</code>（v1.2，2026-09-12；v1.2.1 追加 §8/§9）。本页为提炼摘要，字段以源文件为准。

## 1. 编码原语

- 哈希：`poseidon_hash_many`（多元素）；`blake2s-256`（字节摘要）；结算结构根用 `blake2b-256 + 域标签`。
- 32B → 域：hi/lo 无损拆分为两个 felt；felt → 32B 走裸 `to_bytes_be`（只接受 &lt; p 的字节，fail-closed）。
- 域标签：`poseidon(hi, lo)`，hi/lo = blake2s32(domain_utf8)。历史教训：禁止 `byte0 & 0x03` 掩码（域元素可达 2^251，掩码丢位）。

## 2. Note

`asset_class(u8: 1=REAL, 2=PLAY)`、`amount(u64>0)`、`owner(33B secp256k1 压缩公钥)`、`nonce(32B)`、`table_id(Option<u64>)`。承诺树为深度 32 Poseidon Merkle；nullifier 集按插入序确定性折叠；零值与全零 nullifier 拒绝。

## 3. FeePolicy

```
enum FeePolicy { Zero, FixedRake { rate_bps ≤ 10000, cap(0=无封顶), split } }
rake_of(pot) = min(pot * rate_bps / 10000, cap)   // 向下取整；Zero 恒 0
split_of(t)  = (t * treasury_bps / 10000, 余数)     // 零头归 operator
```

开桌绑定、无更新路径；rake_mode 判别值对齐主仓库 `canonical_rake_opening`（NONE=0 / PERCENTAGE=1）。

## 4. 结算记录与三个结构根

`SettlementRecord` v1.2 携带 `plan: SettlementPlan`（poker-settlement-core，结算语义单一事实源）。三个 32B 根把结算从已验证状态派生并完整绑定输出：

| 根 | 算法 | 域标签 |
|---|---|---|
| `plan_digest` | blake2b-256(DOMAIN ‖ borsh(SettlementPlan)) | `zchain.texas_poker.settlement_plan.v2` |
| `payout_root` | RFC 6962 风格树（叶 `H(0x00‖leaf)`、内部 `H(0x01‖l‖r)`，整体前缀域标签；不平衡补空叶哈希到 2 的幂） | `zchain.settlement.payout_root.v1` |
| `side_pot_root` | blake2b-256(DOMAIN ‖ borsh(plan.pots)) | `zchain.settlement.side_pot_root.v1` |

`PayoutLeaf` 五元组 `{asset_class, amount, owner, table_id, pot_index, runout_index}`——赔付完整绑定（P0-7）。玩家 ECDSA 签名覆盖 `settle_effect`（含 payout_root），sequencer 无法改打给别人。

校验关系共 11 条、全部 fail-closed、顺序即实现，核心几条：

- `plan.validate` 通过后，`plan.gross_pot == record.pot`（pot 从已验证计划派生，不再独立可信）；
- `Σinputs == plan.gross_pot`；输出同类非零，payouts 与 plan 投影一一对应（`(pot_index, runout_index, seat, amount)` 规范序）；
- `rake.total == plan.rake == policy.rake_of(pot)`（pot = rake 计费基数 = contested 层 gross 之和，uncalled 返还不计入）且 `policy_commitment` 匹配注册表；
- 守恒 `Σinputs == Σpayouts + Σrake_notes`；分账数额与收款人匹配；
- `hand_proof` 存在时：scope v2 镜像校验 + 终态承诺/pre/post 状态根一致 + pot 逐字节绑定（`post_state_image_bytes` 偏移 74 的 8B LE）+ rake opening 与 `min(floor(pot·bps/10⁴), cap, pot)` 一致；完整 STARK 验证由 `TexasAirEngine::verify_canonical_tagged_proof` 执行。

计费口径（BLOCKERS B9 已统一，ABI v1.2.2）：`rake_base()` = contested 层 gross 之和，uncalled 返还/sole-survivor 层不计费且强制该层 rake 为 0；poker_l1 与 appchain 为同一口径，含 uncalled 手 e2e 正例。个别边界终局形态（如 raked-sole-survivor）仍 fail-closed 拒绝。

### scope v2（TexasArchiveScope）

borsh 字段序与 canonical 归档公开字段逐字段一致：`log_size/num_columns/table_id/hand 与 call_seq 边界/transition 元数据/batch_digest/pre-post 各承诺与根/状态镜像字节/range_claimed_sum/rake_opening/blind_opening`。状态镜像为 1,680B 定宽 borsh，`pot` @ 偏移 74、`chip_pool` @ 66。完整字段表见<a href="/docs/proofs/texas-air/">证明系统·公开输入</a>。

## 7. 批次根 BatchRoot

哈希统一为 Poseidon（域标签 `poker-appchain.batch_root.v1`；历史 blake2s 实现已废弃）。批内结算按帧序排列：

```
fold_0 = 0
fold_i = poseidon_hash_many([fold_{i-1}, hi_i, lo_i])   // binding 32B hi/lo 拆分
batch_root = felt_to_bytes32(poseidon_hash_many([D, fold_n]))
D = poseidon(blake2s32("poker-appchain.batch_root.v1") 拆分)
```

golden vector（冻结）：bindings `[0xAA;32], [0xBB;32]` → `batch_root = 00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52`。空批次不产生批次根。

## 8. REAL 出证策略与 attestation v2.1

`RealSettlementPolicy`：`Disabled | HostAttestation | StarkRequired`，<strong>默认 StarkRequired（fail-closed）</strong>；StarkRequired 必须钉 verifier key，未钉 = REAL 结算全部拒绝。

三层门（默认收紧）：引擎层（host 引擎对 REAL 一律拒）→ 管道提交层（texas-air 前缀 + 钉扎 + hand_proof，不满足不进队列）→ 批次水位层（出队前复查，违反则 completion 原地保留、水位不推进）。

attestation v2.1（payload 定长 192B）：`post_state_commitment(32) ‖ post_state_root(32) ‖ pre_state_root(32) ‖ plan_digest(32) ‖ ed25519 签名(64)`，消息域 `poker-appchain.texas-air-v2`。覆盖四要素：verifier key、引擎版本、pre/post 状态根、已验证计划摘要。

## 9. 提现 finality 门槛

REAL 提现要求：`proven_watermark >= op_index` <strong>且</strong> 批次根覆盖该 op（`Option` 存在性判定，`None` 一律拒绝）。PLAY 豁免。`without_finality_gate` 仅限测试。详见<a href="/docs/concepts/finality/">四阶段最终性</a>。

## 10. 指标

`real_settlement_rejected_total`（REAL 出证三层拒绝合计）、`withdrawal_finality_rejected_total`（提现未达门槛）。
