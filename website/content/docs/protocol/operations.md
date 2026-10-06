---
title: Operation 与软确认帧
lang: zh-CN
section: protocol
description: 封闭操作集 v1、SoftConfirmFrame 格式与状态根折叠。
lead: 操作集封闭为 7 个；新操作 = 协议版本升级，禁止运行时扩展。
---

## Operation v1（封闭）

```
OpenTable   { table_id, policy }
CloseTable  { table_id }
Deposit     { deposit_id, owner, asset_class, amount }
WithdrawRequest { spend, note, request_id }
Transfer    { spends, notes, outputs }
BuyIn       { table_id, spends, notes, seat_owner }
Settle      { SettlementRecord }   // boxed
```

防跨操作重放的 scope 标签：`withdraw.v1` / `transfer.v1` / `buyin.v1` / 结算域。操作集封闭：新操作 = 协议版本升级。

## 软确认帧

```
SoftConfirmFrame { index: u64, prev_hash: [u8;32], op: Operation,
                   state_root: [u8;32], ts_ms: u64 }
SignedFrame      { frame, sig: [u8;64] }   // ed25519 over blake2s(borsh(frame))
```

- 创世帧：index 0，prev_hash 全零；`verify_chain` 全量重验。
- 提交路径：克隆态试算 → 签名 → WAL append + 真 fsync → 原子换入；WAL 失败零状态变更。

## 状态根折叠

```
state_root = poseidon 折叠(承诺树根, nullifier 根, 注册表根, 桌折叠,
                           seq, spent_count, proven_watermark)
```

重放时逐帧比对状态根；分叉即 WAL 损坏。`proven_watermark` 进入状态根，意味着证明进度本身是共识状态的一部分。
