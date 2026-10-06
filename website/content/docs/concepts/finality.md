---
title: 四阶段最终性
lang: zh-CN
section: concepts
description: soft accepted / BFT ordered / proven / finalized-claimable 的精确含义与提现门槛。
lead: 软确认不是最终确认。最终性按四级标注，REAL 提现有双重门槛。
---

## 状态机

```
soft accepted ──(BFT, v1.5)──▶ BFT ordered ──(STARK verify)──▶ proven ──(finality gate)──▶ finalized/claimable
```

### soft accepted

Sequencer 把操作写入软确认链（`SoftConfirmFrame`，ed25519 签名 + 哈希链）。毫秒级反馈，仅代表<strong>运营方承诺</strong>。WAL append + fsync 原子提交：WAL 失败则零状态变更。

### BFT ordered

v1.5 引入 4–7 validator 对批次根/提款根/状态根做最终确认。当前不存在——每页页眉的最终性图例已注明。

### proven

证明管道按批次出证，`verify` 走真实 STARK 验证路径后，`mark_proven` 只推进<strong>最大连续前缀</strong>：证明乱序、失败、worker 崩溃都不会错误推进水位（M4-ACC-6）。

### finalized/claimable（REAL 提现门槛，ABI §9）

REAL note 提现申请要求来源 op 同时满足：

1. `proven_watermark >= op_index`（连续前缀语义 = 该 op 已证明）；
2. 批次根证据覆盖该 op（`batch_covered_through = Some(t)`，`t >= op`；`None` 一律拒绝——op 0 与"尚无批次根"在裸数值下不可区分，用 Option 存在性判定）。

不满足即 `WithdrawalNotFinalized { op_index, watermark }`，计 `withdrawal_finality_rejected_total`。幂等语义：已受理的同 id 同载荷重复申请返回既有条目。

PLAY note 豁免双重门槛（软确认即可提）。`withdrawal_requires_finality = false` 为显式 opt-out，<strong>仅限测试/开发，禁止生产配置</strong>。

## provenance

`LedgerState.note_origins` 记录每个 note 承诺的铸出 op，消费后不删除（提现销毁后托管打款侧仍可查；WAL 重放重建）。账本外 note 没有 provenance，无法构造门槛证据。
