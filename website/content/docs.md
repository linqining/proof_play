---
title: 文档
lang: zh-CN
section: docs
lead: 版本化文档站：13 个板块，从 15 分钟 quickstart 到协议规范与威胁模型。docs v1.3.0-alpha (ABI v1.2.3)。
---

文档站与代码同步版本化：`latest` 只指向已发布 release，草案进入 `next`（<a href="/docs/changelog/versioning/">版本说明</a>）。生产环境将托管于 docs.zchain.example，路径结构与本站 /docs/ 完全一致。

<div class="grid-2">
  <div class="card">
    <h2 class="card-h"><a href="/docs/getting-started/">快速开始</a></h2>
    <p>15 分钟 quickstart：启动 devnet、完成一手 PLAY、验证证明；玩家网络配置。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/concepts/">核心概念</a></h2>
    <p>Note、nullifier、桌、手、rake 与四阶段最终性。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/protocol/">协议规范</a></h2>
    <p>ABI（v1.2.x）、Operation 集、SoftConfirmFrame、SettlementPlan、批次根与 attestation。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/architecture/">系统架构</a></h2>
    <p>Appchain 分层、证明管道、Vault 边界、DA 与抗审查设计现状。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/developers/">开发者指南</a></h2>
    <p>RPC、事件、错误码、限流与重试语义。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/validators/">验证者指南</a></h2>
    <p>节点部署、validator set 现状、BFT 路线、密钥与监控。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/operators/">运营方指南</a></h2>
    <p>牌桌运营、费率注册、充值提现、对账与故障处置。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/proofs/">证明系统</a></h2>
    <p>Texas AIR、公开输入（scope v2）、验证器与审计导出。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/security/">安全</a></h2>
    <p>威胁模型、三层 REAL 门、漏洞披露与暂停/恢复。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/economics/">经济模型</a></h2>
    <p>rake 公式（含 contested 口径）、分账、托管边界；安全关键公式附数学式与伪代码。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/api-reference/">API 参考</a></h2>
    <p>RPC/ABI 手工参考层；自动生成流水线待接入。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/changelog/">变更日志</a></h2>
    <p>docs/ABI 版本、协议变更、迁移与兼容性、latest/next 机制。</p>
  </div>
  <div class="card">
    <h2 class="card-h"><a href="/docs/legal/">法务与合规</a></h2>
    <p>条款、隐私、地区限制与责任边界（与官网 /legal/ 同源）。</p>
  </div>
</div>

## 文档发布最低要求对照

每个代码 release 对应 docs tag / ABI 版本 / genesis hash；API 文档含正负例与错误码；安全关键公式同时给出数学表达式、规范伪代码与测试向量；Note/结算/提现/checkpoint 提供独立验证命令；"已实现/部分实现/仅 PoC/禁止生产使用"明确列出；性能数字附硬件与分位数。逐条状态见仓库内 `website/docs-status.md`。
