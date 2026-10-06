---
title: rake 公式与分账
lang: zh-CN
section: economics
description: FIXED_RAKE 公式、contested-only 计费口径（B9 已统一）、treasury/operator 分账。安全关键公式附数学式与伪代码。
lead: rake = min(floor(rake_base × rate_bps / 10⁴), cap)，rake_base = contested 层 gross 之和；口径已统一（B9）。
---

## 费率策略（ABI §3）

```
enum FeePolicy {
  Zero,
  FixedRake { rate_bps: u16(≤10000), cap: u64(0=无封顶), split: FeeSplit }
}
FeeSplit { treasury_bps: u16(≤10000), treasury: [u8;33], operator: [u8;33] }
commitment = poseidon(DOMAIN_FEE_POLICY, mode, rate, cap, t_bps, t_x*, t_y*, o_x*, o_y*)
```

注册表：`table_id → 策略`，开桌绑定、<strong>无更新路径</strong>（同策略重绑定幂等）。

## rake 公式

数学式：

```
rake(rake_base) = min( floor(rake_base × rate_bps / 10⁴), cap )    # Zero 策略恒 0
```

伪代码（与 `fee.rs` 实现一致）：

```
def rake_of(rake_base):
    if policy is Zero:
        return 0
    raw = rake_base * policy.rate_bps // 10000     # 整数除法，向下取整
    return raw if policy.cap == 0 else min(raw, policy.cap)
```

`rake_base` = contested 层 gross 之和：uncalled 返还层与 sole-survivor 层不计费，且校验强制这两类层 rake 必须为 0（见下文口径章节）。

rake opening（AIR 侧，批级）同式：`min(floor(pot·bps/10⁴), cap, pot)`，mode 0 → 0；结算校验断言 `record.rake.total` 与之相等。

## 分账公式

数学式：

```
treasury_out = floor(rake × treasury_bps / 10⁴)
operator_out = rake − treasury_out        # 零头归 operator
```

伪代码：

```
def split_of(rake):
    t = rake * split.treasury_bps // 10000
    return (t, rake - t)
```

校验：`treasury_out/operator_out` 数额与收款人必须与 `policy.split_of(rake.total)` 一致，否则结算拒绝。

## 计费口径：contested-only（BLOCKERS B9 已统一）

- `rake_base` = <strong>contested 层 gross 之和</strong>：uncalled 返还层与 sole-survivor 层不计费，且校验强制这两类层 rake 必须为 0（`poker-settlement-core` `plan.rake_base()`，B9 语义约束 core 侧钉死）。
- 结算校验：`rake.total == plan.rake == policy.rake_of(rake_base)`；poker_l1 与 appchain 为同一口径（ABI v1.2.2），含 uncalled 返还手已出 e2e 正例。
- 边界（如实）：个别边界终局形态（如 raked-sole-survivor）仍 fail-closed 拒绝，不做放宽。

## 守恒（把 rake 放进恒等式）

```
Σinputs == Σpayouts + rake.total        # rake note 已含在输出侧
plan.gross_pot == Σinputs               # 与 ABI §4 校验关系一致
```

测试向量：E2E 正例含 treasury/operator rake 分账断言与 uncalled 返还手（contested-only 计费）正例；负例含 rake 篡改拒绝。
