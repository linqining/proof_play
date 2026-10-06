---
title: 运营方指南
lang: zh-CN
section: operators
description: 牌桌运营、费率注册、充值提现、对账和故障处置。
lead: 运营方是 v1 的托管方与活性提供方；本页是托管义务的操作手册。
---

## 牌桌与费率注册

- 开桌即绑定 `FeePolicy`：`ZERO` 或 `FIXED_RAKE { rate_bps ≤ 10000, cap, split }`；绑定后无更新路径（改费率 = 开新桌）。
- `FeeSplit { treasury_bps, treasury, operator }`：rake 按 `treasury_bps` 分账，零头归 operator。
- `rake_of(base) = min(floor(base × rate_bps / 10000), cap)`；rake_mode 判别值 NONE=0 / PERCENTAGE=1 与主仓库对齐。
- 计费口径（BLOCKERS B9 已统一，ABI v1.2.2）：`base` = <strong>contested 层 gross 之和</strong>——uncalled 返还与 sole-survivor 层不计费，且校验强制这两类层 rake 为 0；含 uncalled 返还的手正常出证（e2e 正例覆盖）。个别边界终局形态（如 raked-sole-survivor）仍 fail-closed 拒绝，不做放宽。

## 充值与提现（托管侧）

| 流程 | 要求 |
|---|---|
| 充值 | `Deposit { deposit_id, owner, asset_class, amount }`；托管账入账 + 对账记录；幂等键不因校验失败被烧掉 |
| 提现申请 | `WithdrawRequest`；REAL 需 provenance + finality 双重门槛，未达即 `WithdrawalNotFinalized` |
| 打款 | 人工审核（如配置）+ 托管打款；打款侧可查 note provenance（消费后不删除） |
| 对账 | 每月出具运营方签名报告（结构见<a href="/transparency/">透明度页</a>）；差异必须附事件说明 |

## 故障处置（runbook 摘要）

| 场景 | 处置 |
|---|---|
| Sequencer 停机 | v1 全场停摆是已知边界；重启后 WAL 重放 + 启动追块恢复；对外按事故流程公告 |
| Prover 停机 | 不影响软确认与已有 finality；水位停滞，REAL 提现延迟——公告中如实说明 |
| 托管账差异 | 立即暂停提现打款，定位差异，出具带事件链接的对账说明 |
| 安全事件 | 走披露流程；暂停期间停发营销内容 |

## 义务清单

1. 维护提现 SLA 并在透明度报告披露实际值。
2. 任何"人工调整"在报告中标注。
3. 不把托管对账表述为偿付保证（术语边界见透明度页）。
4. 事故期间优先发布影响范围、用户操作建议与修复时间线。
