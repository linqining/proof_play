---
title: ProofPlay Poker —— 每一局，都有证
lang: zh-CN
section: home
lead: ProofPlay Poker —— 让游戏自己证明公平。底层网络沿用 ZChain 技术标识；当前环境信息以状态页为准。
---

<div class="hero">
  <div class="hero-grid">
    <div class="hero-copy">
      <p class="tagline-en">Every game, proven.</p>
      <h1>不信发牌，验证每一手。</h1>
      <p>ProofPlay Poker 让牌面保持私密，让洗牌、动作与结算留下可复验的证据。用户品牌使用 ProofPlay；底层网络、协议域标签和部署标识暂时沿用 ZChain。</p>
      <div class="cta-row">
        <a class="btn btn-play" href="/product/">立即试玩 PLAY</a>
        <a class="btn btn-ghost" href="/docs/">阅读技术文档</a>
        <a class="btn btn-ghost" href="/proofs/">验证一手牌</a>
        <a class="btn btn-real" href="/status/">Network Status</a>
      </div>
    </div>
    <div class="hero-visual" aria-hidden="true">
      <div class="felt-oval"></div>
      <div class="pcard pcard-1"><span class="pc-rank">Q</span><span class="pc-suit">♣</span><span class="pc-foot">Q♣</span></div>
      <div class="pcard pcard-2 pcard-red"><span class="pc-rank">K</span><span class="pc-suit">♥</span><span class="pc-foot">K♥</span></div>
      <div class="pcard pcard-3"><span class="pc-rank">A</span><span class="pc-suit">♠</span><span class="pc-foot">A♠</span></div>
      <div class="hero-chips">
        <span class="chip chip-net">devnet</span>
        <span class="st st-ok">soft accepted</span>
        <span class="st st-ok">proven</span>
      </div>
    </div>
  </div>
</div>

<div class="stat-band">
  <div class="stat"><span class="stat-num">2.1 ms</span><span class="stat-label">软确认 p50（门槛 100ms）</span></div>
  <div class="stat"><span class="stat-num">3,200</span><span class="stat-label">压测结算（64 桌 × 50 手）</span></div>
  <div class="stat"><span class="stat-num">16,064</span><span class="stat-label">压测牌局操作</span></div>
  <div class="stat"><span class="stat-num">2,350+</span><span class="stat-label">工作区测试通过</span></div>
</div>

<div class="entry-grid">
  <div class="card card-play">
    <p class="card-kicker">01 / PLAY NOW</p>
    <h2>立即试玩</h2>
    <p>只进入 PLAY 测试/娱乐环境，不涉及真实资金，也不默认触发充值。devnet 环境由本地 devnet 配置启动，入口见<a href="/product/">产品页</a>与<a href="/docs/getting-started/quickstart/">15 分钟 quickstart</a>。</p>
  </div>
  <div class="card card-play">
    <p class="card-kicker">02 / VERIFY A HAND</p>
    <h2>验证一手牌</h2>
    <p>输入 hand id 或 proof digest 跳转到<a href="/proofs/">独立验证入口</a>；同时提供独立 verifier 命令，不依赖运营方私有服务。</p>
  </div>
  <div class="card">
    <p class="card-kicker">03 / READ THE DOCS</p>
    <h2>阅读文档</h2>
    <p>版本化文档站（13 个板块），关键安全说明在<a href="/docs/security/">安全</a>与<a href="/docs/economics/">经济模型</a>章节，而不是藏在 FAQ。</p>
  </div>
  <div class="card card-real">
    <p class="card-kicker">04 / NETWORK STATUS</p>
    <h2>网络状态</h2>
    <p>Sequencer、prover、BFT checkpoint、提现服务的状态入口：<a href="/status/">/status/</a>。v1 为静态层 + 示例数据，接口由后续 portal 服务提供。</p>
  </div>
</div>

## 产品三点说明

<div class="grid-3">
  <div class="card">
    <h3>快</h3>
    <p>桌级软确认提供毫秒级操作反馈。devnet 压测（64 桌 × 50 手，3200 结算 / 16064 操作）买入软确认 p50 2.1ms / p99 3.5ms，门槛 100ms。</p>
  </div>
  <div class="card">
    <h3>明</h3>
    <p>每手牌都有结算摘要、rake 关系和可审计的状态变化：SettlementPlan、payout root、批次根全部进入证明绑定。</p>
  </div>
  <div class="card">
    <h3>稳</h3>
    <p>从单 Sequencer 逐步升级到 BFT checkpoint 与可验证提现——这是路线图，不是现状。见<a href="/roadmap/">路线图</a>。</p>
  </div>
</div>

## 信任声明（v1 托管网络）

<div class="trust-note">
<p>当前 v1 是<strong>托管式网络</strong>。PLAY 可用于测试和娱乐；REAL 资产仍受运营方托管与提现流程约束。无信任提现、抗审查最终性和多运营方共识属于后续里程碑，只有在对应 verifier、BFT 和退出协议上线并通过验收后才会启用。</p>
</div>

## 资产类型：PLAY 与 REAL

<div class="grid-2">
  <div class="card card-play">
    <h3>PLAY —— 测试/娱乐筹码</h3>
    <p>用于开发、测试与娱乐对局。软确认即可提供快速体验；提现豁免 finality 双重门槛（见 <a href="/docs/protocol/abi/">ABI 规范 §9</a>）。PLAY 与 REAL 物理隔离：不可互转、不可混树，隔离由 AIR 层强制。</p>
  </div>
  <div class="card card-real">
    <h3>REAL —— 托管真实资产映射</h3>
    <p>运营方托管资产在链内的映射。结算默认 <code>StarkRequired</code>（fail-closed）：必须经真实 STARK 证明路径出证；提现要求连续 proven 水位 + 批次根双重 finality。v1 阶段 REAL 不对外开放充值，上线节奏见<a href="/roadmap/">路线图</a>。</p>
  </div>
</div>

## 最终性级别

所有 explorer 数据、结算与提现状态都按下面四级标注，本站每个页面页眉都有同一图例：

| 级别 | 含义 | v1 状态 |
|---|---|---|
| <span class="st st-info">soft accepted</span> | 桌级软确认，毫秒级操作反馈；仅代表运营方承诺 | 已达到 |
| <span class="st st-muted">BFT ordered</span> | 多 validator BFT 对批次/状态根排序确认 | 未上线（v1.5） |
| <span class="st st-ok">proven</span> | 批次经 STARK 证明路径验证，水位连续推进 | 已达到 |
| <span class="st st-warn">finalized/claimable</span> | 满足提现 finality 门槛，可进入提现流程 | REAL 侧部分达到（门槛已实现）；permissionless claim 未上线（Phase 2） |

软确认不是最终确认；REAL 只有在 proven + finality 门槛满足后才进入托管打款流程。

## 项目事实（devnet，2026-09）

| 事实 | 状态 |
|---|---|
| 结算核心 <code>poker-settlement-core</code>（单一事实源） | 已落地 |
| §5.2 P0 八项 | 全部关闭 |
| 真实 stwo 出证（canonical AIR，Stark curve） | 已打通（含 E2E 正例 + 篡改负例） |
| 多节点组网 | 3/4 节点收敛（skew=0），4 节点 kill-one 容错 |
| 工作区测试 | 2350+ 通过 |
| ForceInclude / BFT checkpoint / 链上出入金 | 未完成（Phase 1 余项 / v1.5） |

完整事实表（可引用版本）见 [media-kit fact-sheet](/media-kit/v0.1/fact-sheet.md)；对外承诺边界见[路线图](/roadmap/)与[法务与风险披露](/legal/)。

## 英文简介（English short copy）

> Every game, proven.
>
> ProofPlay Poker (powered by ZChain) is a purpose-built appchain for poker: fast table-level confirmations, provable settlement and rake accounting, with final asset release handled by an explicit Vault and exit protocol.
>
> ProofPlay Poker v1 is a custodial network. PLAY is for testing and entertainment; REAL assets remain subject to operator custody and the withdrawal process. Trustless withdrawal, censorship-resistant finality and multi-operator consensus are later roadmap milestones and will only be enabled after the corresponding verifier, BFT and exit protocol pass acceptance.
