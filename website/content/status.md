---
title: 服务状态
lang: zh-CN
section: status
lead: Sequencer、prover、RPC、relay 与提现服务的状态。v1 为静态层 + 示例数据。
sample: true
---

## 组件状态（SAMPLE DATA / devnet）

| 组件 | 状态 | 说明 |
|---|---|---|
| Sequencer（软确认链） | <span class="st st-ok">operational</span> | 出块正常，软确认 p99 3.5ms（压测口径） |
| Prover（证明管道） | <span class="st st-ok">operational</span> | proven watermark 连续推进 |
| RPC（devnet） | <span class="st st-ok">operational</span> | JSON-RPC over TCP；公共网关待上线 |
| Relay（SeenReceipt） | <span class="st st-bad">not deployed</span> | 抗审查 relay 属 v1.5，未部署 |
| 提现服务（托管打款） | <span class="st st-warn">degraded</span> | 示例：人工审核排队，SLA 见透明度报告 |
| BFT checkpoint | <span class="st st-bad">not deployed</span> | v1.5 路线 |

## 指标（SAMPLE DATA，90 天窗口）

| 指标 | 当值 |
|---|---|
| Sequencer uptime | 99.2% |
| RPC 错误率 | 0.3% |
| 手结束 → proof-ready | p50 41s / p95 96s（示例，开发机口径） |
| seen-to-include（relay） | 不可用（relay 未部署） |

## 事故记录（结构模板）

事故期间停止营销内容，本页优先更新。每条事故记录包含：**影响范围**（受影响
组件）、影响描述、开始时间、恢复进度与复盘链接。

| 日期 | 影响范围 | 影响 | 开始时间 (UTC) | 恢复 | 复盘 |
|---|---|---|---|---|---|
| 2026-08-30 | RPC（devnet） | RPC 短暂不可用（约 12 分钟），出块与结算未受影响 | 03:14 | 03:26 | 链接待附 |
| （示例行，无真实事故） | — | — | — | — | — |

## 关于本页

- v1 没有独立 status 后端：本页是<strong>接口就绪的静态层</strong>，页面结构与指标口径已定义；生产状态数据将由 status 服务提供（组件心跳、水位、事故流）。
- 状态能力验收（WEB-ACC-6，模拟 Sequencer/prover/RPC/relay 故障并显示影响与恢复记录）：<strong>静态层故障注入演练已可本机复现</strong>——`website/tools/status_fault_drill.py` 对本页组件状态做 4 个故障变体（sequencer down / prover 积压 / RPC 降级 / 提现延迟）注入、构建并断言渲染结果（受影响组件标记、影响范围文案、含影响范围/恢复字段的事故记录区），演练全程保持 SAMPLE DATA 标注；<strong>线上真实监控注入仍待 status 后端服务</strong>。
- 网络环境：devnet（zchain-poker-devnet）。所有数据为示例，非实时。
