---
title: 产品
lang: zh-CN
section: product
lead: 牌桌、钱包、证明公平与结算流程。所有资金相关能力都标注托管状态与最终性级别。
sample: true
sample-note: 本页的"入口"为 devnet 开发者流程入口，不是面向终端玩家的在线牌桌产品；在线客户端与钱包插件见路线图。
---

## 产品构成

<div class="grid-2">
  <div class="card card-play">
    <p class="card-kicker">TABLES</p>
    <h3>牌桌</h3>
    <p>桌级软确认链提供毫秒级下注反馈：每个操作进入 <code>SoftConfirmFrame</code>（index / prev_hash / op / state_root / ts_ms，ed25519 签名）。devnet 压测买入软确认 p50 2.1ms / p99 3.5ms（64 桌 × 50 手，门槛 100ms）。桌与费率策略在开桌时绑定，无更新路径。</p>
  </div>
  <div class="card card-play">
    <p class="card-kicker">WALLET</p>
    <h3>钱包（wallet-core）</h3>
    <p>共享钱包核心 <code>wallet-core</code> 由并行工作提供：note 托管、密钥派生、软确认验证与证明校验复用同一套实现；浏览器插件与独立应用按路线图（plan §6.12）推进。当前 devnet 阶段通过 CLI 完成 note 管理与验证。</p>
  </div>
  <div class="card">
    <p class="card-kicker">PROVABLE FAIRNESS</p>
    <h3>证明公平</h3>
    <p>每手牌可产出真实 STARK 证明（Texas canonical AIR，stwo circle-STARK，Stark curve）：盲注镜像、下注序列、终态与守恒关系都被 AIR 约束覆盖。验证入口见<a href="/proofs/">证明页</a>，技术细节见<a href="/docs/proofs/">证明系统文档</a>。</p>
  </div>
  <div class="card card-real">
    <p class="card-kicker">SETTLEMENT</p>
    <h3>结算流程</h3>
    <p>结算语义单一事实源 <code>poker-settlement-core</code>：SettlementPlan / SidePot / RunoutSchedule / PayoutVector / rake。pot 从已验证状态派生（不作为独立可信输入），输出结构由 payout_root 完整绑定，玩家签名覆盖精确赔付。</p>
  </div>
</div>

## 玩家流程（devnet / PLAY）

1. 启动或接入 devnet 节点（<a href="/docs/getting-started/quickstart/">15 分钟 quickstart</a>）。
2. 创建 PLAY note（铸币/充值入口由运营方提供；devnet 用本地铸币）。
3. Buy-in 进入牌桌，下注操作获得 soft accepted（显示 frame index 与状态根）。
4. 手牌结束：读取 SettlementPlan、rake 与 payout root。
5. 在证明门户或本地 CLI 验证手牌证明。

示例不得默认使用 REAL 或真实外部地址（文档最低要求，plan §6.4）。

## REAL 流程（v1 托管边界）

<div class="notice">
<p>REAL 当前处于<strong>协议实现完成、运营未开放</strong>状态：结算出证策略默认 <code>StarkRequired</code>（fail-closed），提现要求连续 proven 水位 + 批次根双重 finality。但 <strong>ForceInclude、BFT checkpoint 与链上出入金尚未完成</strong>，因此 REAL 不对公众开放充值。</p>
</div>

- 充值：托管账 + 对账 + 幂等已实现（M7 托管侧）；链上侧接线未完成。
- 提现：`WithdrawRequest` 需 provenance + 批次根证据，未达 finality 门槛即拒绝（`WithdrawalNotFinalized`）。
- 不可无信任提现：permissionless claim 需等 Vault verifier 上线（Phase 2）。

<div class="trust-note">
<p>本页所有资金相关能力均受<a href="/legal/">服务条款与风险披露</a>约束。软确认不是最终确认；当前网络为 devnet 托管网络。</p>
</div>
