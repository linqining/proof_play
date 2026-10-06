---
title: 威胁模型
lang: zh-CN
section: security
description: v1 信任边界、攻击面与安全关键公式（数学式 + 伪代码）。
lead: 谁能做什么、什么被密码学约束、什么只能靠托管纪律。
---

## 信任边界（v1）

| 参与方 | 能力 | 约束 |
|---|---|---|
| Sequencer（运营方） | 受理顺序、软确认、提现流程控制 | 结算必须通过校验 + 证明；签名绑定赔付；行为可被 watcher 取证 |
| 玩家 | 花费自己的 note（签名） | 不能花别人资产；不能伪造守恒 |
| Prover | 出证 | 伪造证明在 stwo 验证下不可行；出证错误会被三层门拦截 |
| 托管方 | 外部资产保管 | v1 无密码学约束——这是托管模型的核心风险 |

## 安全关键公式

### 守恒恒等式（资金不灭）

数学式：

```
Σ inputs == Σ payouts + Σ rake_notes == plan.gross_pot == record.pot
```

伪代码（`validate_settlement` 顺序即实现，全部 fail-closed）：

```
assert hand_binding != 0 and inputs.len() > 0
plan.validate(inputs.len())                     # 版本/座位层数/gross=rake+awards/层内守恒
assert plan.gross_pot == record.pot             # pot 从已验证计划派生
assert sum(inputs) == plan.gross_pot            # seat note 即下注贡献
for each payout: 同类、非零、table_id 合法
assert payouts 一一对应 plan 投影 (pot,runout,seat,amount 规范序)
assert sum(payouts) + sum(rake_notes) == plan.gross_pot
assert rake.total == plan.rake == policy.rake_of(pot)
assert policy_commitment == registry[table].commitment
```

测试向量：E2E 正例（守恒成立）+ 攻击回归（多付/少付/换人/rake 篡改均拒绝）。

### 费率公式（可证明 rake）

数学式：

```
rake = min( floor(pot × rate_bps / 10⁴), cap )      # cap = 0 表示无封顶
split: treasury = floor(rake × treasury_bps / 10⁴)
       operator = rake − treasury                   # 零头归 operator
```

伪代码：

```
def rake_of(pot):
    if policy.mode == ZERO: return 0
    raw = (pot * policy.rate_bps) // 10000          # 整数除法 = 向下取整
    return min(raw, policy.cap) if policy.cap > 0 else raw
```

费率是状态机数据：`policy_commitment = poseidon(DOMAIN_FEE_POLICY, ...)` 在开桌时绑定，无更新路径；结算时 `record.policy_commitment` 必须匹配注册表。

### 签名绑定（防改打）

数学式：

```
spend_digest = blake2s(DOMAIN_SPEND_DIGEST, commitment, nullifier,
                       scope, effect)
scope  = DOMAIN_SETTLEMENT_BINDING ‖ hand_binding
effect = blake2s("poker-appchain.settle.effect.v1", hand_binding, pot,
                 Σinput_commitments, Σoutputs(owner,amount), rake.total,
                 payout_root)
```

即：玩家签名覆盖<strong>精确赔付结构</strong>（含 payout_root）。sequencer 拿到授权也无法改打给别人；policy_commitment 刻意不在 effect 内，由注册表冻结检查独立强制（两条防线各司其职）。

### REAL 三层门

```
门1 引擎层:   asset_class == REAL and engine != texas-air-*  → reject
门2 提交层:   REAL op requires (mode allows engine) ∧ engine 前缀 texas-air-
              ∧ verifier_key pinned ∧ hand_proof 存在        → else 不进队列
门3 批次层:   出队前复查门2 条件                              → else completion 保留, 水位不推进
默认: mode = StarkRequired, verifier_key = None → REAL 全部拒绝 (fail-closed)
```

## 攻击面与已知缓解

| 攻击 | 缓解 | 残余风险 |
|---|---|---|
| Sequencer 改打赔付 | effect 签名绑定 | 无（密码学约束） |
| Sequencer 审查/延迟受理 | v1 无缓解 | v1.5 ForceInclude |
| 双花 | nullifier 集 + 查重 | 无 |
| 假证明 | stwo 完整验证 + 负例回归 | 依赖 stwo/AIR 正确性（审计目标） |
| 数值篡改（pot） | 镜像偏移 74 逐字节绑定 | 无 |
| WAL 篡改/回滚 | 全量签名重验 + 状态根逐帧比对 | 无 |
| 提现未达 finality | 双重门槛 + provenance | 托管打款侧仍需纪律 |
| 密钥丢失 | 无 | 用户自担（条款明示） |
