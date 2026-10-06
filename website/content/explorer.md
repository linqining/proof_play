---
title: 区块浏览器
lang: zh-CN
section: explorer
lead: 交易、手、结算、rake、资产标识与 checkpoint 查询。所有数据标注确认层级。
sample: true
---

## 数据来源与确认层级

explorer 的每条记录都标注来源层级：<span class="st st-info">soft accepted</span>（软确认）→ <span class="st st-muted">BFT ordered</span>（未上线）→ <span class="st st-ok">proven</span>（已证明）→ <span class="st st-warn">finalized/claimable</span>。v1 阶段实际出现 soft accepted 与 proven 两级；失败原因与水位缺口也会如实展示，不做隐藏。

本页提供一个<strong>可选的实时层</strong>：本地起 devnet replay 网关（`explorer_gateway`，对 appchain WAL 做只读重放）时，页面自动改用网关数据并保留同样的层级标注；网关未运行时，以下全部保持示例数据。该实时层仅覆盖 devnet replay 网关能查询的范围（status / 帧摘要 / 结算查询），不是生产数据服务。

<div class="explorer-live" hidden>
  <p>
    <span id="explorer-live-badge" class="st st-ok">实时数据 · replay 网关</span>
    <button id="explorer-refresh" type="button" class="st st-info" aria-label="刷新实时数据（devnet replay 网关）">刷新实时数据</button>
    <span id="explorer-live-note"></span>
  </p>
</div>

## 最近的块（SAMPLE DATA / devnet）

<div data-explorer="blocks"></div>

| 高度 | 时间 (UTC) | 操作数 | 状态根 | 层级 |
|---|---|---|---|---|
| 18204 | 2026-09-12 08:31:04 | 12 | 0x9a3f…c21e | <span class="st st-ok">proven</span> |
| 18203 | 2026-09-12 08:30:52 | 7 | 0x51bd…07aa | <span class="st st-info">soft accepted</span> |
| 18202 | 2026-09-12 08:30:41 | 9 | 0xe4c2…8f10 | <span class="st st-ok">proven</span> |

## 手牌与结算（SAMPLE DATA / devnet）

<div data-explorer="settlements"></div>

| hand id | 桌 | pot | rake | payout root | 结算层级 | proof |
|---|---|---|---|---|---|---|
| 1042 | 7 | 1,840 | 92 | 0x77ab…39d1 | <span class="st st-ok">proven</span> | <a href="/proofs/">下载 / 验证</a> |
| 1041 | 7 | 620 | 31 | 0x0cdd…a2f4 | <span class="st st-ok">proven</span> | <a href="/proofs/">下载 / 验证</a> |
| 1040 | 3 | 0 | 0 | 0x51bd…07aa | <span class="st st-info">soft accepted</span> | 待批次出证 |

rake 口径说明：`FIXED_RAKE` 策略下 `rake = min(floor(rake_base × rate_bps / 10000), cap)`，`rake_base` = contested 层 gross 之和——uncalled 返还与 sole-survivor 层不计费（BLOCKERS B9 已统一为 contested-only 口径，ABI v1.2.2；<a href="/docs/economics/rake/">经济模型文档</a>有详细说明）。

## 资产标识（REAL 多币种与 GAME 币）

链上资产按 <code>AssetId = {domain, token_id}</code> 两级标识（ABI v2）：REAL 域（domain=1）为封闭枚举的三种托管资产——NATIVE（token 0）/ USDT（token 1）/ USDC（token 2）；GAME 域（domain=2）为游戏内虚拟筹码——遗留 PLAY（token 0）与经 genesis 注册表发行的游戏币（token_id ≥ 1）。实时网关（replay 模式）在 <code>/api/v1/status</code> 的 <code>assets</code> 字段导出逐 token 的 issued / burned / outstanding（十进制字符串，链上可见面口径；index 模式该字段如实为 null）；<code>/api/v1/settlement/{binding}</code> 明细的 inputs / payouts / rake 输出逐项带 <code>asset_id</code>（domain 判别值 + token 名称解析）。

**REAL 域多币种**：每种 token 独立托管分账、独立提现通道、独立对账恒等式（issued = 存续 + 已销毁毛额）；<strong>不允许跨币种轧差</strong>——一种 token 的短库不能用另一种 token 的长库抵偿（协议强制，非运营策略）。托管侧储备与提现队列属部署面，只读网关不导出，explorer 如实标注数据来源限于链上可见面。

**GAME 币**：游戏内虚拟筹码，非投资品——不可赎回、不可与 REAL 域资产兑换、不可跨链转移，只能在发行方生态内消费；这些是协议结构性质（操作集里不存在 GAME → 外部资产的出口变体），不是运营承诺。供给按恒等式对账并逐 token 导出：<code>outstanding = Σminted − Σburned</code>，并与存续 note 面额合计三边核对（不一致时 explorer 原样展示告警位）。GAME 桌计费采用销毁处置（FixedRakeBurn）：rake 不进入任何托管账，直接销毁并同步收缩 outstanding。GAME 币不设任何收益、回报或升值表述；本页展示的一切供给数字都是链上对账口径的记录，不构成任何价值陈述。

## Checkpoint / 水位（SAMPLE DATA / devnet）

<div data-explorer="checkpoint"></div>

| 项 | 值 |
|---|---|
| proven watermark | 18196 / 18204（缺口：无） |
| 最新批次根 | 0x00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52 |
| BFT checkpoint | 未上线（v1.5） |
| 批次大小 | 32 ops / 批（示例配置） |

## 关于本页

- 本页是<strong>接口就绪的静态层</strong>：页面结构与数据口径已定义，数据全部为示例。生产 explorer 由独立服务提供（区块/交易/手/结算/rake 查询、proof 下载、confirmation 层级与失败原因展示）。
- 实时层（E1/E2）当前以 <code>explorer_gateway</code> 只读网关形式落地：<strong>devnet replay 模式</strong>——网关从 appchain WAL 全量重放（验签 + 状态根重验）并提供只读 JSON API（<code>/api/v1/status</code>、<code>/api/v1/frames</code>、<code>/api/v1/settlements</code> 等），默认只绑回环。它查询的是已落 WAL 的软确认链与 proven log 水位，不代表生产环境的实时承诺。
- 任意 settlement 都将可跳转 proof portal 由浏览器本地复验（WEB-ACC-4，待 portal 服务）。
- 浏览器分阶段开发计划（实时网关 → 领域查询 → proof 复验闭环）见<a href="/roadmap/">路线图</a>。

<script src="/assets/js/explorer-live.js" defer></script>
