# Documentation map

> English is authoritative; Chinese is a mirror. For the full project story
> start at the [repository README](../README.md).
>
> 以英文为准，中文对照。项目完整介绍从[仓库 README](../README.md) 开始。

## Current-state documents (what is true today)

| Doc | Role |
|---|---|
| [STATUS.md](STATUS.md) | **Authoritative canonical-AIR coverage & trust boundary** — what composes today, what stays fail-closed, each with acceptance criteria |
| [SOUNDNESS.md](SOUNDNESS.md) | **Final soundness status** — three pillars: Lean 4 protocol theorems, DAPV on-chain sigma aggregation, canonical AIR audit & fixes |
| [PERFORMANCE.md](PERFORMANCE.md) | **Final performance record** — release baselines, production recursive pipeline (15–17 s/hand async), on-chain EC_OP gas, decided non-goals, GPU analysis (theoretical) |
| [TODO.md](TODO.md) | Live task board (task status is authoritative here) |

## Design specifications (live)

| Doc | Role |
|---|---|
| [design/DUAL_PROOF_PROTOCOL.md](design/DUAL_PROOF_PROTOCOL.md) | Core settlement architecture spec — dual-proof (P sigma on-chain via EC_OP, G STARK), v2.9 header is the current truth |
| [design/SETTLEMENT_PRIVACY_PLAN.md](design/SETTLEMENT_PRIVACY_PLAN.md) | STRK20 private settlement plan (zero-plaintext settle, SNIP-36 mode, payout anonymizer) |
| [design/SNIP36_INTEGRATION.md](design/SNIP36_INTEGRATION.md) | The single SNIP-36 integration design (dual-gate verification shipped in dual v5) |
| [design/TEXAS_TAGGED_AIR.md](design/TEXAS_TAGGED_AIR.md) | Tagged/canonical transition AIR capability boundary (29 selectors) |
| [design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md](design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md) | Action-signing censorship-resistance design (#16/#17/#18) |

## Operations

| Doc | Role |
|---|---|
| [MAINNET_TX_GUIDE.md](MAINNET_TX_GUIDE.md) | How to run STRK20 transactions on mainnet (wallet operations) |
| [`poker_contracts/DEPLOYMENTS.md`](../poker_contracts/DEPLOYMENTS.md) | Authoritative deployment & wiring ledger (devnet → Sepolia → mainnet) |
| [`strk20.json`](../strk20.json) | Machine-readable deployment manifest (contracts, class hashes, transactions, proof policy) |

## History

`docs/archive/` — superseded designs and old-world reports, each with a header
note; kept for historical context only. Removed process documents (execution
plans, curve-migration plans, mid-flight audits) live in git history.

---

## 中文对照

**现状文档（今天为真的事）**：`STATUS.md`（canonical AIR 覆盖/信任边界
权威）、`SOUNDNESS.md`（健全性最终状态：Lean 定理 / DAPV 链上聚合 / AIR
审计与修复）、`PERFORMANCE.md`（性能最终记录：release 基线、生产递归流水线
15–17 秒/手异步、链上 EC_OP gas、已裁决非目标、GPU 理论分析）、`TODO.md`
（现行任务板，任务状态以此处为准）。

**现行设计规格**：`design/DUAL_PROOF_PROTOCOL.md`（核心结算架构，v2.9 头注
为准）、`design/SETTLEMENT_PRIVACY_PLAN.md`（STRK20 私密结算）、
`design/SNIP36_INTEGRATION.md`（SNIP-36 唯一设计文档，双门验证已随 dual v5
上线）、`design/TEXAS_TAGGED_AIR.md`（AIR 能力边界）、
`design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`（抗审查设计）。

**运维**：`MAINNET_TX_GUIDE.md`（主网交易操作）、
`poker_contracts/DEPLOYMENTS.md`（部署/接线权威账本）、`strk20.json`
（机器可读部署清单）。

**历史**：`docs/archive/`——已被替代的设计与旧世界报告，均带头注，仅史料
价值；已删除的过程文档（执行计划、曲线迁移计划、中途审计）在 git 历史。
