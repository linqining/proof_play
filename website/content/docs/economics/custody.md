---
title: 托管边界
lang: zh-CN
section: economics
description: 资金守恒、托管账与对账、REAL 发行与销毁边界。
lead: 守恒恒等式约束链内；托管边界约束链外。两者不能混淆。
---

## 两层守恒

<strong>链内（密码学/校验约束）</strong>：

```
Σinputs == Σpayouts + Σrake_notes == plan.gross_pot == record.pot
        == 已证明终态镜像 pot（字节级，偏移 74）
```

<strong>链外（托管纪律约束，v1 无密码学保证）</strong>：

```
托管外部资产余额 == 已发行 REAL − 已销毁 REAL + 待结算流水    # 由对账验证
```

链内守恒被协议强制（fail-closed）；链外守恒只由托管方纪律 + 对账报告支撑——这就是托管模式的风险边界，Phase 2 的 Vault root 与独立 verifier 才把它升级为外部可验证。

## 托管账（M7，vault.rs）

| 能力 | 状态 |
|---|---|
| 托管账记账（按资产类隔离） | 完成 |
| 充值幂等（`deposit_id`，校验失败不烧键） | 完成 |
| 提现申请 + finality 双重门槛（REAL） | 完成 |
| provenance 查询（`note_origins`，消费后保留） | 完成 |
| 账实对账 + 差异处理 | 完成 |
| 链上侧接线（Starknet 收款/打款通道） | <strong>未完成</strong> |

## REAL 发行与销毁

- 发行：充值确认后按托管入账发行 REAL note；v1 阶段 REAL 不对公众开放（发行受白名单/限额控制，MVP 起）。
- 销毁：提现销毁（nullifier 消耗）后托管打款；provenance 保留供打款侧核对。
- 隔离：REAL/PLAY 不可互转、不可混树（AIR 层不变量）；对外报表分开列示。

## 风险说明

1. 托管方偿付能力不由链内守恒决定——用户对托管方的债权以托管账与对账报告为准。
2. 提现延迟来源：finality 门槛、人工审核、托管打款流程、监管要求。
3. 非零对账差异即事件：暂停打款、定位、出带事件链接的报告（运营方义务，见<a href="/docs/operators/">运营方指南</a>）。
