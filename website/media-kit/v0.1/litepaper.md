# ProofPlay Poker Litepaper（工作稿 v0.1）

> 面向产品与运营读者。完整技术细节见 whitepaper.md 与公开文档。
> 本文件按发布纪律保留了 custodial 与 PLAY/REAL 限制——不得删减后传播。

## 这是什么

ProofPlay Poker 是一条专为扑克设计的应用链：牌桌操作在链内以毫秒级软确认返回；每一手牌的结算关系（pot、rake、赔付结构）由可独立验证的证明约束；外部资产由明确的 Vault 与提现流程管理。

**当前形态（务必引用）**：devnet；单 Sequencer；**托管式（custodial）v1**。PLAY 是测试/娱乐筹码；REAL 是运营方托管的真实资产映射，当前不对公众开放充值。

## 用户流程

1. **进入**：连接钱包（按网络隔离，devnet 不会误连主网）。
2. **获取筹码**：PLAY 由测试入口提供；不涉及真实资金，也不默认触发充值。
3. **上桌**：买入（BuyIn）后下注，操作立即 soft accepted——界面同时显示 frame index 与状态根，并明确标注这不是最终确认。
4. **结算**：一手结束，读取 SettlementPlan、rake 与 payout root。
5. **验证**：在证明门户输入 hand id / proof digest 浏览器验证，或用独立 CLI 命令验证证明文件。
6. **提现**：PLAY 软确认即可提；REAL（当前未开放）需通过 proven 水位 + 批次根双重 finality，走运营方托管打款。

## 为什么可信（边界内）

- 结算被 11 条 fail-closed 校验约束：守恒（`Σinputs == Σpayouts + rake`）、pot 从已验证计划派生、赔付结构完整绑定、费率与注册表一致。
- REAL 结算默认必须走真实 STARK 证明路径（fail-closed 默认），三层独立复查。
- 任何人可以用独立验证器复验，不依赖运营方私有服务。

## 风险摘要（不可删减）

1. **托管风险**：v1 筹码是运营方负债。REAL 用户对运营方拥有债权，而不是链上自持资产；运营方破产或恶意时可能无法收回。链内守恒不等于偿付能力。
2. **活性风险**：单 Sequencer 停机 = 全场停摆；v1.5 的 BFT checkpoint 与 ForceInclude 之前，运营方可以延迟或拒绝受理交易。
3. **软确认不是最终确认**：快速反馈是运营方承诺；最终性按 soft accepted → BFT ordered → proven → finalized/claimable 四级标注。
4. **无信任提现未上线**：permissionless claim 需等 Vault verifier（Phase 2）；在此之前提现走托管流程，存在人工审核与延迟。
5. **软件与证明系统风险**：未做第三方审计；协议存在已披露的口径缺口（rake contested 口径统一中）。
6. **监管与地区限制**：REAL 的开放范围、提现与身份验证按辖区合规策略执行。

## 路线图一览

| 阶段 | 交付 | 状态 |
|---|---|---|
| Phase 0 | 结算核心 / P0 / 水位 / ABI 冻结 | 完成 |
| Phase 1 (MVP) | 单 Sequencer + ForceInclude + 托管出入金 | 进行中 |
| Phase 1.5 | BFT checkpoint（4–7 validator）、DA | 未开始 |
| Phase 2 | Vault verifier、无信任退出、外部可验证偿付 | 未开始 |
| Phase 3 | 分片、多运营方、B2B SLA | 未开始 |

## 一句话

从软确认开始，以可验证退出为目标——每个阶段以公开规范、测试向量和可复验指标为出口。
