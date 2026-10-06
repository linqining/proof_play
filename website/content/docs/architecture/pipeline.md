---
title: 证明管道与水位
lang: zh-CN
section: architecture
description: 批次构建、失败处理、连续水位与 REAL 三层门在管道中的位置。
lead: 管道只推进最大连续前缀；REAL 在三个独立位置被复查。
---

## 批次生命周期

```
submit ──▶ queue ──▶ try_build_batch ──▶ prove(engine) ──▶ verify ──▶ completion ──▶ ProvenCallback ──▶ mark_proven
```

- submit 层即准入：REAL 结算在提交时做第一轮复查（引擎允许集、钉扎、hand_proof），不满足不进队列。
- try_build_batch 出队前做第二轮复查（批次水位层）；违反则 completion 原地保留——该 op 不被标记已证明。
- prove 失败/panic：带退避重试，任务不丢失；批次验证失败：completion 保留，不丢。

## 连续水位

`mark_proven` 维护缺口集，只推进<strong>最大连续前缀</strong>：

```
例：证明完成序 [5, 3, 4]  →  watermark 停在 2（5 是缺口，3/4 入暂存）
    随后 2 完成           →  watermark 推进到 5
```

这保证"已证明"是严格前缀语义：任何 op 被标记 proven 时，其之前所有 op 都已 proven。`proven_watermark` 折叠进状态根，经批次根回调（`record_batch_root` / `mark_proven_through_with_root`）同步批次覆盖信息，重启后由管道重新回调恢复。

## 性能口径

管道级指标（loadtest，64 桌 × 50 手）：3200 结算 / 16064 操作，买入软确认 p50 2.1ms / p99 3.5ms（预算 100ms）。这些是<strong>软确认</strong>延迟，不是 proof-ready 延迟；四段延迟（soft-confirm / BFT finality / proof-ready / claimable）的分别报告是 M9-ACC-4 的要求，工具待发布。所有性能数字附硬件与样本口径后才能对外引用。
