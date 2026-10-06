# 官网/文档交付验收记录（plan §6.11 WEB-ACC-1..8）

日期：2026-09-12 · 范围：`website/`（静态站 + 工具 + 素材包）
构建：`python3 website/build.py` → `dist/`（41 个 HTML 页面，另含 assets 与 media-kit 静态拷贝）

图例：✅ 本地已验证 · 🟡 部分 · ⬜ 待部署/待后端（不虚标完成）。

---

## WEB-ACC-1 移动端/桌面端可访问性、TLS、性能、断链

- **断链** ✅（本地）：`python3 website/tools/check_links.py` — 站内链接全图遍历
  2567 个内部链接 / 41 页，**0 断链**（含 `#fragment` 对目标文件 id 校验）；
  外链 42 个只做格式检查、不请求网络。
- **可访问性** ✅（正则级）：`python3 website/tools/check_a11y.py` — 41 页全部通过：
  img 全部有 alt；表单控件有 label（proofs 页验证输入框带 `label for=hand-id`）；
  无标题跳级；每页恰 1 个 h1；viewport meta 与 `html lang` 齐备。
  色彩对比：12 组文字/背景组合全部 ≥ 7.85:1（最低 4.5:1 门槛，实际值见工具输出）。
- **移动端** ✅（CSS + 截图验证）：媒体查询断点 960px / 640px；meta viewport。
  已用本地 `python3 -m http.server` + Chrome 实测截图：1280px 桌面（首页、
  quickstart 文档页）与 375px 移动端——导航换行、徽章换行、CTA 全宽、文档侧栏
  折叠为顶部面板，均正常。
- **性能** ✅（静态站特性）：零 JS、零 webfont、单 CSS 文件；未做 Lighthouse 基线
  （无部署环境意义有限），标注为待部署后补测。
- **TLS** ⬜ 待部署：域名与证书属上线部署项（zchain.example 为占位，plan §6.1）。

**结果**：本地可执行部分全部通过；TLS/线上性能待部署。

## WEB-ACC-2 性能/最终性/托管/路线图表述与计划一致；禁用词扫描为零

- **禁用词扫描** ✅：`python3 website/tools/scan_banned_words.py` — 扫描 dist/ 全部
  HTML/MD（59 个文件），禁用词 11 项（稳赚/零风险/绝对公平/不可阻止/银行级安全/
  trustless casino/censorship-proof/guaranteed fair returns/proof of reserves/
  guaranteed/risk-free），**0 命中**。扫描器灵敏度已用临时样本自测（命中时退出码 1）。
  豁免规则未启用：全站 0 命中，无需引用性豁免。
- **表述一致性** ✅（内容审查）：路线图页按事实逐项标注（Phase 0 完成、Phase 1 进行中、
  ForceInclude/BFT/链上出入金未完成、v1.5/Phase 2 未开始）；每页页眉固定显示
  devnet 徽章、PLAY/REAL 资产说明、四级最终性图例（v1 实际达到 soft+proven）；
  英文页保留 custodial / PLAY-REAL / roadmap 限制（首页、litepaper、whitepaper）；
  transparency 页明确不使用 proof-of-reserves 类命名；REAL 页显示"不可无信任提现"。

**结果**：通过（扫描 0 命中）。

## WEB-ACC-3 quickstart 在干净环境 15 分钟完成 PLAY 一手

- 🟡 部分：`/docs/getting-started/quickstart/` 已写完整流程（克隆 →
  `cargo build --release --bin zchain` → `scripts/multi_node_e2e.sh 3` →
  loadtest 单桌演示 + `poker-appchain-texasair` E2E 一手 → 验证命令），
  全部命令与仓库现状核对过（脚本用法、参数、二进制路径）。
- 干净环境实测（含首次构建计时、预期输出逐字比对）待在干净 CI/容器环境执行；
  逐操作的 wallet-core CLI（创建 note/开桌/下注）依赖并行工作的 `poker-wallet`
  crate，quickstart 已注明当前以测试命令演示同等链路。

**结果**：文档就绪；15 分钟实测与 CLI 替换待 wallet-core / 干净环境。

## WEB-ACC-4 explorer settlement 跳转 proof portal，浏览器本地复验

- ⬜ 待 portal 服务：explorer 与 proofs 页面已实现"接口就绪的静态层"——
  结算表带"下载/验证"入口、portal 表单（label/占位符/禁用态按钮）与数据源说明，
  并标注 SAMPLE DATA / devnet。浏览器本地复验（WASM verifier + verifier 版本/
  digest/耗时展示）需 portal 后端，v1 无后端。独立 CLI 验证路径已可用文档化。

**结果**：页面层完成；跳转与本地复验待 portal 服务。

## WEB-ACC-5 release 自动同步 docs tag、ABI、genesis hash、changelog、SBOM、签名

- 🟡 部分：版本化机制已落地——版本号集中在 `build.py SITE`，docs 页脚
  `docs v1.3.0-alpha (ABI v1.2.3)`，`/docs/changelog/` 有版本历史与迁移纪律，
  `/docs/changelog/versioning/` 定义 latest/next。
- 自动同步流水线（release → docs tag/genesis hash/SBOM/签名）待发布基础设施。

**结果**：机制与内容就绪；自动化待发布流水线。

## WEB-ACC-6 status page 可模拟故障并显示影响与恢复记录

- 🟡 部分：`/status/` 已实现组件状态表（Sequencer/prover/RPC/relay/提现服务）、
  指标表、事故记录模板（含"事故期间停营销"纪律）与数据源说明，标注
  SAMPLE DATA / devnet。故障注入模拟需 status 后端服务（待 portal 服务）。

**结果**：静态层完成；故障模拟与实时数据待服务。

## WEB-ACC-7 REAL 页面在 verifier/BFT/Vault 未就绪时显示"不可无信任提现"，无误导按钮

- ✅：/product/ REAL 流程区、/transparency/（custody 横幅 + 边界声明）、/legal/ §5、
  /roadmap/ 承诺边界、/status/ 组件表均明示 v1 不可无信任提现；proofs 页验证按钮
  为禁用态并注明"portal 服务上线后开放"；REAL 未就绪的三个原因（verifier 门槛、
  BFT、Vault）在页面间一致引用。custody 横幅出现在所有资金相关页面。

**结果**：通过。

## WEB-ACC-8 法律/风险/地区/负责任使用/漏洞披露在首次充值/提现前可见

- ✅（静态站层面）：/legal/ 覆盖 §6.9 全部 10 项（条款、隐私、Cookie、地区限制与
  KYC、PLAY/REAL 法律属性与托管关系、公平证明边界、7 类风险提示、负责任游戏
  三工具、漏洞披露 SLA、联系渠道）；/docs/legal/ 与官网同源互链。
  充值/提现流程中的强制可见性（前端拦截/勾选）属客户端功能，待客户端实现；
  本站已在 legal 页首注明该要求（WEB-ACC-8 引用）。

**结果**：内容完整可用；流程内强制展示待客户端。

---

## 汇总

| 项 | 结果 | 遗留 |
|---|---|---|
| WEB-ACC-1 | ✅ 本地全过 | TLS、线上性能基线：待部署 |
| WEB-ACC-2 | ✅ 0 命中 | — |
| WEB-ACC-3 | 🟡 文档就绪 | 干净环境实测；wallet-core CLI |
| WEB-ACC-4 | ⬜ 页面层完成 | portal 服务（后端 + WASM verifier） |
| WEB-ACC-5 | 🟡 机制就绪 | release 自动化流水线 |
| WEB-ACC-6 | 🟡 静态层完成 | status 后端（故障注入） |
| WEB-ACC-7 | ✅ | — |
| WEB-ACC-8 | ✅ 内容完整 | 客户端流程内强制展示 |

## 版本记录

- 本站页脚版本：`docs v1.3.0-alpha (ABI v1.2.3)`，集中定义于 `build.py SITE`。
- 注意：仓库内 `poker-appchain/docs/ABI.md` 头部当前标注 v1.2 / v1.2.1；发布前需
  与 `SITE["ABI_VERSION"]` 同步核对（改一处即可）。

---

# 2026-09-12 追加：WEB-ACC-3 本机计时 + WEB-ACC-6 静态层故障注入演练（本机可复现证据）

（本节为追加记录，不改动上方既有验收内容。）

## WEB-ACC-3 追加：quickstart 本机计时（新工具 `website/tools/quickstart_timed.sh`）

**测了什么**：按 quickstart 文档步骤逐步计时并输出总墙钟——`cargo build
--release --bin zchain` → `ZCHAIN_BIN=target/release scripts/multi_node_e2e.sh 3`
→ loadtest 单桌演示 → `e2e_full_hand` 完整一手真实 stwo 出证 → texasair 适配器
负例回归全套（`perf_baseline` 标 `#[ignore]` 不计入）。克隆步骤不适用（已在本
仓库内），从构建起算，脚本内注明。每步失败即中止（exit 1）。

**本机实测（2026-09-12，同一台 Apple Silicon 开发机，rust-toolchain pinned
nightly-2026-04-15 / cargo 1.97.0-nightly）**：

| 模式 | build | devnet(3 节点) | loadtest | e2e_full_hand | 测试套 | **总墙钟** |
|---|---|---|---|---|---|---|
| 温缓存（增量） | 3.6s | 38.9s | 45.4s | 1.5s | 4.3s | **93.7s** |
| 部分干净（`cargo clean --release -p zchain -p poker_l1` 后重跑） | 12.8s | 30.9s | 43.7s | 1.4s | 4.1s | **93.3s**（含 clean 0.4s） |

两者都在 15 分钟门槛内（约 9 倍余量）。工具用法：`quickstart_timed.sh
[--partial-clean]`，支持 `QUICKSTART_TIMED_JSON=<path>` 输出机器可读结果。

**诚实边界（不虚标）**：

- **完全干净环境（新 clone + 无 cargo 缓存，含首次编译 stwo）未测**——本机已有
  全部构建缓存，全量重建代价大不做；文档"构建约 4 分钟"的首次口径需干净
  CI/容器另行测量。
- `e2e_full_hand`/测试套：texasair crate 是自带 lockfile/target 的独立 crate，
  脚本以 `--manifest-path` 在其目录内调用（与文档 `-p` 书写等价可执行，脚本内
  注明；文档从仓库根跑 `-p` 实际不可解析该包）。
- 工具细节发现：nightly cargo 的 `cargo clean -p` 不带 `--release` 只清 dev
  profile（实测 "Removed 0 files"），脚本已用 `--release` 形式并注明。
- wallet-core CLI 替换路径仍待 wallet-core 发布（上方原文口径不变）。

**结果**：🟡 → 本机温缓存/部分干净两口径实测 **93.7s / 93.3s**，远低于 15 分钟；
完全干净环境数字保留待测。

## WEB-ACC-6 追加：status 故障注入演练——静态层可本机复现（新工具 `website/tools/status_fault_drill.py`）

**测了什么**：对 status 页组件状态表注入 4 个故障变体——sequencer down（major
outage）/ prover 积压（degraded）/ RPC 降级（degraded）/ 提现延迟（major
outage）。每个变体在**临时目录**拷贝站点（build.py + templates + content +
assets）→ 注入 `content/status.md`（组件徽章 + 影响范围文案 + 事故记录区新增
DRILL 行）→ 运行 `build.py` → 断言渲染出的 `dist/status/index.html`。演练页
永不入站、永不覆盖 dist/。

**结果（2026-09-12 本机）：4/4 变体 + 基线 = 5/5 全过**，每个变体断言：

| 断言 | 结果 |
|---|---|
| a. 受影响组件标记（`st-warn`/`st-bad` 徽章 + 变更后状态词） | ✅ 4/4 |
| b. 影响范围文案（组件行说明 + 事故行"影响范围"单元格 + 影响描述） | ✅ 4/4 |
| c. 恢复记录区（事故表 DRILL 行：影响范围 / 开始时间 / 恢复进度 / 复盘 + "演练注入，非真实事故"标注） | ✅ 4/4 |
| d. 未受影响组件保持原状（逐变体抽查无关组件仍 operational） | ✅ 4/4 |
| e. SAMPLE DATA / devnet 标注仍在（演练页不冒充真实数据） | ✅ 4/4 |
| 基线（无注入构建）：各组件原状态 + 事故表含"影响范围"列 | ✅ |

**模板补强**：`content/status.md` 事故记录表按本验收项补 **影响范围** 列（记录
结构 = 影响范围 / 影响 / 开始时间 / 恢复 / 复盘），"关于本页"同步更新能力边界。

**诚实边界（不虚标）**：本项证明的是**静态层**——"注入故障数据 → 构建 → 渲染
受影响组件标记 + 影响范围文案 + 恢复记录区"的通路可本机复现；**线上真实监控
注入（组件心跳、水位、事故流实时数据）仍待 status 后端服务部署**，组件状态
仍为 SAMPLE DATA。

**复现**：`python3 website/tools/status_fault_drill.py`（退出码 0 = 全过）。

## 回归确认（2026-09-12）

- `python3 website/build.py`：41 页构建成功；
  `check_links.py` 2567 内链 / 42 外链 **0 断链**；
  `check_a11y.py` 全过；`scan_banned_words.py` **0 命中**（59 文件）——与既有
  基线一致，本次追加内容（status.md 影响范围列等）未引入回归。
- 扩展侧既有测试不回归：`validation.test.js` 28/28、`wasm_smoke.mjs` 通过。
  M6-ACC-1 浏览器验证吞吐的新证据见 `extension/ACCEPTANCE.md` 追加节。

## 回归确认（2026-09-13，ABI v1.3 同步）

- `poker-appchain/docs/ABI.md` 升 **v1.3**（新增 §15 洗牌/发牌证明链消费面 +
  changelog；`build.py SITE["ABI_VERSION"]`/`FOOTER_VERSION` 同步 v1.3）。
- `python3 website/build.py`：41 页构建成功；`check_links.py` 2569 内链 /
  42 外链 **0 断链**；`check_a11y.py` 全过（41 页）；`scan_banned_words.py`
  **0 命中**（59 文件）。
- 版本串 grep 复核：`dist/` 内页脚呈 `ABI v1.3`，无 `v1.2.4` 残留。

---

# 2026-09-13 追加：版面重设计（「午夜毡布」v2 主题）

**改了什么**（用户要求"使用 UI 相关 MCP 重新设计版面"）：

- **设计 token**：新调色板「午夜毡布」经 WCAG 对比度预验后定稿（全部组合 ≥ 8.6:1，
  门槛 4.5），四处同源同步：`assets/css/main.css :root`、`media-kit/v0.1/colors.md`、
  `media-kit/v0.1/brand.css`、`tools/check_a11y.py PALETTE`。零 webfont / 零 JS 约束不变。
- **`assets/css/main.css` 全量重写**：sticky 毛玻璃头部 + env-strip 移出吸顶区；
  首页 hero 双栏（文案 + 纯 CSS 扑克牌扇面视觉，aria-hidden）+ 数据统计带（stat-band）；
  卡片升级为渐变面 + hover 抬升；表格圆角化（border-radius + 行 hover + 移动端横向滚动）；
  状态徽章/横幅/侧栏/页脚全套翻新；断点 960px / 640px 行为复核（移动端取消吸顶）。
- **模板/构建器**：`base.html`/`docs.html` 页头结构改为 `[[PAGE_HEAD]]`（首页由 hero
  自带 h1，消除标题重复；`<title>` 首页不再带站名后缀）；`build.py` 行内信任标签
  白名单补充 `a/strong/em/code`——修复既有缺陷：段落/表格单元格中手写的原生标签
  曾被转义为字面文本显示（如 `<code>poker-settlement-core</code>`、explorer 页
  AssetId 代码片段），与既有"行首 HTML 块直通"同一信任模型，内容均为站内自有文件。
- **内容**：首页 `index.md` 版面重构（hero 双栏 + stat-band + 入口卡）；两处段落内
  裸 `<a>` 改为 markdown 链接。

**工具链使用**：ui-toolkit `import_design_tokens`（43 token）+ `generate_component`
（token 接线验证）+ `audit_component`（hero 版面 100/100）；chrome-devtools MCP
（1440px / 375px 实测截图迭代）；judge 代理视觉验收（首轮 5 页：2 fail 3 pass，
fail 均为上述 `<code>` 转义问题；修复后复验）。

**回归确认（2026-09-13）**：

- `python3 website/build.py`：41 页构建成功；
- `check_a11y.py` 41 页全过，12 组对比度 8.75–17.61:1；
- `check_links.py` 2569 内链 / 42 外链 0 断链；
- `scan_banned_words.py` 0 命中（59 文件）；
- judge 复验结论：首轮 5 页（首页桌面/文档页/explorer/状态页桌面/首页移动）2 fail 3 pass，
  fail 均为 `<code>` 转义问题；修复重建后复验 3 页全部 pass——代码片段渲染为等宽样式、
  无字面标签残留、无新引入问题，**5/5 页通过视觉验收**。

---

# 2026-09-13 追加：配色 v3（青黑毡布）+ 纯 CSS 动效层

**改了什么**（用户要求"继续修改配色，增加页面动效"）：

- **配色 v3**：冷调青黑底（bg `#070d0a`）+ 春翡翠强调（felt `#37e39c`）+ 天蓝 PLAY
  （`#66c4ff`）+ 暖金 REAL（`#ffc75a`）。改动前先脚本预验 WCAG 对比度：13 组组合
  全部 ≥ 9.1:1；四处同源同步（main.css / colors.md / brand.css / check_a11y.py）。
  hero 主标题新增白→翡翠渐变文字（大字号下两侧均高对比）。
- **动效层（纯 CSS，零 JS）**：首屏入场（hero 文案逐行上浮、入口卡/统计带错峰
  `rise-in`）、hero 扑克牌缓慢浮动（`translate` 属性与旋转定位解耦，老浏览器自动
  忽略）、devnet 徽章呼吸点、按钮 hover 扫光、既有卡片/行 hover 过渡。
  全部动效在 `prefers-reduced-motion: reduce` 下关闭。
- **顺手修复**：hero 标题选择器由 `.hero h2` 修正为 `.hero h1, .hero h2`（内容改为
  h1 后原规则失配，clamp 字号此前未生效）。
- **踩坑记录（验收发现并修复）**：初版动效含 `animation-timeline: view()` 滚动显现
  层（`@supports` 包裹）——judge 整页截图发现"产品三点说明/信任声明/资产类型"三
  章节正文停在 `opacity: 0`：scroll-driven 动画在整页截图/打印等非滚动渲染路径下
  不前进。已整体移除该层并留注释，动效只保留不依赖滚动/JS 的部分；colors.md 同步
  记入"明确不做"。

**回归确认（2026-09-13）**：41 页构建成功；`check_a11y.py` 全过（12 组对比度
9.17–18.0:1）；`check_links.py` 0 断链；`scan_banned_words.py` 0 命中。
judge 验收：首轮 3 页（首页桌面/explorer/首页移动）2 fail 1 pass（fail = 上述
滚动动画空白）；移除后复验首页桌面 + 首页移动全部 pass——三章节正文完整可见、
无半透明残留/错位/截断、新配色对比度良好，**本轮 3/3 页通过视觉验收**。



> **部署依赖项**：本文件中标注"待部署/待后端/待 CI"的条目已集中登记到 [`RELEASE_PREREQUISITES.md`](./RELEASE_PREREQUISITES.md)（发布前置清单，含关联门槛与关闭动作）；完整验收判定 = 本地证据 + 前置清单关闭。
