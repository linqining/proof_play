# 开发周报模板

```markdown
# ProofPlay Poker 开发周报 #<编号>（<起始日> – <结束日>）

环境：devnet · 文档版本：docs v1.3.0-alpha (ABI v1.2.2)

## 本周变更
- <代码/协议变更，附 commit 或 PR 链接>

## 测试与验证
- 测试规模：<套件 → 通过/新增数；总规模 2350+>
- E2E / 场景：<multi_node_e2e / kill-one / restart-catchup 结果>

## 指标（有新数据时）
- soft-confirm p50/p95/p99：<值（口径：硬件、并发、样本）>
- proof-ready 延迟：<值或"未测量">
- 水位/批次：<proven watermark、缺口>

## 风险与阻塞
- <阻塞项，附 BLOCKERS 编号（如 B9 rake 口径）>

## 下周计划
- <3–5 条>

## 更正
- <如有此前报告的错误数字，在此更正>
```

纪律：只报已验证数字；不确定就写"未测量"；事故周只写事故。
