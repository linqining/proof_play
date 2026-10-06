---
title: 安全
lang: zh-CN
section: security
lead: 威胁模型摘要、审计状态（如实：未做第三方审计）、漏洞披露流程与 SLA 承诺。
---

## 当前安全状态（如实公开）

| 项 | 状态 |
|---|---|
| 第三方审计 | <strong>未做</strong>。没有任何已完成的第三方审计报告；上线前（Mainnet candidate 阶段）才会安排 |
| 内部安全回归 | 6 类攻击回归矩阵 + watcher 分叉检测 + 负例深度（Fiat–Shamir 流/状态镜像字节翻转/坏签名等均被拒绝） |
| P0 安全修复 | §5.2 八项已全部关闭（2026-09-12，见<a href="/roadmap/">路线图</a>） |
| 已知缺口 | ForceInclude / BFT / 链上出入金未完成；单 Sequencer 活性依赖运营方 |

审计不等于无漏洞保证。未来发布审计报告时，将注明范围、commit、未修复问题、审计日期与不覆盖的组件。

## 威胁模型摘要（v1）

### 托管边界

v1 是托管式网络：链内筹码（尤其 REAL）是运营方负债的映射。守住资金边界的机制：

- **守恒恒等式**：`Σinputs == Σpayouts + Σrake`，且 `plan.gross_pot == record.pot == Σinputs == 已证明终态镜像 pot`（字节级绑定，状态镜像偏移 74）。
- **签名绑定精确赔付**：`spend_digest = blake2s(DOMAIN, commitment, nullifier, scope, effect)`，effect 含 payout_root——sequencer 无法把授权改打给别人。
- **策略冻结**：费率在开桌时绑定注册表，无更新路径；`record.policy_commitment` 必须匹配。

### REAL 三层门（默认收紧，拒绝路径唯一）

1. **引擎层**：host 签名引擎对 REAL 一律返回 `RealRequiresStarkProof`。
2. **管道提交层**：REAL 要求 texas-air 引擎 + 钉扎 verifier key + 携带 hand_proof，否则任务不进队列。
3. **批次水位层**：出队前复查允许集与钉扎；违反则 completion 原地保留、水位不推进。

默认 `StarkRequired` + 未注入 verifier key = REAL 结算全部拒绝（fail-closed）。

### watcher

watcher 对软确认链做独立分叉检测；sequencer 停机、双签、状态根冲突按 M3-ACC-7 路线生成证据（部分完成，见路线图）。

### 单点活性

单 Sequencer 停机 = 全场停摆。v1 的缓解是 WAL 原子提交、告警与 runbook；结构性缓解（BFT、DA、ForceInclude）在 v1.5。这是明示风险，不是隐藏项。

## 漏洞披露

| 项 | 内容 |
|---|---|
| 报告邮箱 | security@zchain.example（占位，上线前启用并公布） |
| PGP | 占位：指纹与公钥将在邮箱启用时同步公布；公布前可用 `#security` 频道私信联系 |
| 请勿 | 在公开频道/issue 发布未修复漏洞细节 |
| 报告内容 | 影响描述、复现步骤、受影响版本/commit、（可选）修复建议 |

### 响应 SLA 承诺（自报告接收起）

| 阶段 | 承诺 |
|---|---|
| 确认收到 | ≤ 2 个工作日 |
| 初步评估（严重度分级） | ≤ 5 个工作日 |
| 严重（critical）修复或缓解 | ≤ 30 天，期间可发布临时缓解 |
| 高/中/低 | ≤ 90 天按严重度排期 |
| 公告 | 修复发布后同步安全公告，归档于本页 |

严重度按 CVSS 类似口径由运营方与报告者协商；有争议时可要求第三方复核。项目当前不设赏金池；testnet 阶段引入漏洞赏金（见<a href="/roadmap/">发布节奏</a>）。

## 暂停与恢复

v1 运营方保留紧急暂停出入金与结算受理的能力（托管网络的现实边界）。暂停期间：停发营销内容，优先公告影响范围、用户操作建议与修复时间线；恢复后发布事故复盘。相关义务见<a href="/legal/">服务条款</a>。

深入阅读：<a href="/docs/security/threat-model/">威胁模型全文</a>、<a href="/docs/security/disclosure/">披露流程细节</a>。
