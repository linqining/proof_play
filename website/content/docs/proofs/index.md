---
title: 证明系统
lang: zh-CN
section: proofs
description: Texas AIR、结算 proof、验证器、公开输入和审计导出。
lead: 结算正确性的证据链：AIR 约束、公开输入、独立验证。
---

| 页面 | 内容 |
|---|---|
| <a href="/docs/proofs/texas-air/">Texas AIR 与公开输入</a> | canonical tagged AIR、scope v2 字段表、状态镜像 |
| <a href="/docs/proofs/verify/">验证器与审计导出</a> | 独立验证命令、verifier 版本、审计导出 |

## 证据链一览

```
手牌执行 ──AIR 约束──▶ 批次归档（scope v2 + stwo proof）
                            │ verify_canonical_tagged_proof
                            ▼
        TexasAirEngine ──▶ attestation v2.1（192B，钉扎签名）
                            │ 三层门复查
                            ▼
              proven watermark + 批次根 ──▶ REAL 提现 finality
```

- 证明系统：stwo 2.3 circle-STARK，Stark curve（Felt252）。
- AIR：Texas canonical tagged AIR（29 选择子、状态镜像链、nullifier、Fiat–Shamir 全范围绑定）。
- 负例深度：垃圾 STARK 字节、承诺不一致、桌不一致、缺绑定、坏签名、Fiat–Shamir 流篡改、状态镜像字节翻转——全部被验证器拒绝（仓库回归）。
