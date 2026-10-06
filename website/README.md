# ProofPlay Poker 官网 / 文档站（website/）

静态站，零构建依赖：`python3 build.py`（仅 Python 3 标准库）把 `content/`（markdown）+
`templates/`（HTML 模板）+ `assets/` 构建到 `dist/`。无 npm、无框架、可复现。

对应计划：zchain 仓库（github.com/linqining/zchain）的 `docs/plan-appchain-v1.md` §6（产品化蓝图）。

## 构建与部署

```console
python3 website/build.py          # 产出 website/dist/
# 本地预览（必须经 HTTP 服务；站内链接为根绝对路径，直接 file:// 打开会断链）
cd website/dist && python3 -m http.server 8000
# 浏览 http://localhost:8000/
```

部署：`dist/` 是纯静态文件，任意静态托管（Nginx / S3+CDN / GitHub Pages / Vercel 静态模式）均可。
注意：域名与仓库地址目前为占位（`https://zchain.example`，plan §6.1），上线前替换并完成 DNS/TLS/品牌审核；
`website/build.py` 顶部 `SITE` 字典集中定义全部版本号与占位地址。

## 信息架构

### 官网 13 路由（§6.2）

| 路由 | 源文件 | 内容 |
|---|---|---|
| `/` | content/index.md | 首屏四入口（Play Now / Verify a Hand / Read the Docs / Network Status）+ §6.3 主文案原文 + 信任声明 |
| `/product/` | content/product.md | 牌桌 / 钱包 / 证明公平 / 结算流程 |
| `/technology/` | content/technology.md | Appchain、Note、AIR、Sequencer、BFT 路线 |
| `/proofs/` | content/proofs.md | 证明门户静态层（SAMPLE DATA）+ 独立验证命令 |
| `/explorer/` | content/explorer.md | 浏览器静态层（SAMPLE DATA），四级最终性标注 |
| `/developers/` | content/developers.md | SDK/RPC/ABI/节点入口 |
| `/docs/` | content/docs.md | 文档站入口（13 板块索引） |
| `/roadmap/` | content/roadmap.md | Phase 0 完成 / Phase 1 进行中 / v1.5+ 未开始 |
| `/security/` | content/security.md | 威胁模型摘要、披露 SLA、审计状态（未做第三方审计） |
| `/transparency/` | content/transparency.md | 托管对账静态层（SAMPLE DATA），明确非偿付保证 |
| `/community/` | content/community.md | 频道、贡献路径、PLAY 积分、无代币空投声明 |
| `/legal/` | content/legal.md | §6.9 全项 |
| `/status/` | content/status.md | 状态页静态层（SAMPLE DATA） |

### 文档站 13 板块（§6.4，/docs/ 子路径）

`content/docs/<section>/`：getting-started（15 分钟 quickstart）/ concepts / protocol /
architecture / developers / validators / operators / proofs / security / economics /
api-reference / changelog / legal。每页属于 docs 布局（侧边栏 + 面包屑 +
页脚版本号 `docs v1.3.0-alpha (ABI v1.2.3)`）。

### 素材包（§6.6/§6.7）

`media-kit/v0.1/`：logo、颜色/字体规范、one-pager、宣传语、社交文案、新闻稿模板、
FAQ、fact-sheet、90 秒视频脚本、whitepaper、litepaper、发布节奏表与四份运营模板。
构建时原样拷贝到 `dist/media-kit/`。

## 如何加页面

1. 在 `content/`（官网）或 `content/docs/<section>/`（文档）新建 `.md`。
2. 文件头加 front matter：

   ```markdown
   ---
   title: 页面标题
   lang: zh-CN
   section: proofs            # 官网页：用于导航高亮（对应 build.py NAV 的 key）
   lead: 一句话导语。
   sample: true               # 可选：页首显示 SAMPLE DATA / devnet 横幅
   custody: true              # 可选：页首显示托管提示横幅
   ---
   ```

3. 正文为受限 Markdown（标题/列表/表格/引用/代码栅栏/行内样式），原生 HTML 块
   （行首 `<`）原样输出，可用于卡片布局 `<div class="card">`。
4. `python3 build.py` 后运行三个验收工具（见下）。

## 验收工具

```console
python3 website/tools/scan_banned_words.py   # WEB-ACC-2 禁用词扫描，0 命中
python3 website/tools/check_links.py         # 断链检查（站内全图遍历 + 锚点；外链只查格式）
python3 website/tools/check_a11y.py          # img alt / label / 标题层级 / viewport / lang / 对比度
```

三者全部退出码 0 才允许提交构建产物。结果记录在 `ACCEPTANCE.md`，
§6.4 文档最低要求对照在 `docs-status.md`。

## 页眉固定元素（每页）

网络环境徽章（`devnet · zchain-poker-devnet`）、资产类型说明（PLAY 娱乐筹码 · REAL
托管映射 · v1 托管网络）、最终性图例（soft accepted → BFT ordered → proven →
finalized/claimable，v1 实际达到 soft + proven）。改动文案请同步 `build.py` 的
`env_strip_html()`。

## 纪律

- 所有"当前状态"表述以仓库事实为准：未上线能力（ForceInclude / BFT / 链上出入金 /
  permissionless withdrawal / 第三方审计）不得写成可用。
- explorer / status / transparency / proofs 四个页面是"接口就绪的静态层"，
  数据必须带 SAMPLE DATA / devnet 标注。
- 版本号修改只在 `build.py` 的 `SITE` 处进行（`ABI_VERSION` 需与
  `poker-appchain/docs/ABI.md` 同步核对）。

- 发布前置清单（部署依赖项集中登记）：[RELEASE_PREREQUISITES.md](./RELEASE_PREREQUISITES.md)
