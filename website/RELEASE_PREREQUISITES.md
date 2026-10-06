# 发布前置清单（Release Prerequisites）

> 本清单集中列出 WEB-ACC / WALLET-ACC / M6-ACC 中**依赖部署环境、外部服务或
> 发布工程**才能闭环的项。它们不是被遗忘的工作，而是按计划 §6.11 的验收口径
> 无法在本仓库单机环境内完成的收尾。每项标注：关联门槛、当前状态（截至
> 2026-09-12）、关闭所需动作。本地已验证的部分见 `website/ACCEPTANCE.md`、
> `extension/ACCEPTANCE.md`、`poker-wallet/README.md` 的对应记录。

## A. 基础设施与部署

| # | 项 | 关联门槛 | 当前状态 | 关闭动作 |
|---|---|---|---|---|
| A1 | 生产域名 + DNS + TLS（`zchain.example` 为 §6.1 占位） | WEB-ACC-1 | 占位 | 域名采购、DNS、证书、品牌评审后替换全站链接 |
| A2 | 静态托管 + CDN + 缓存/限流策略 | WEB-ACC-1 | 本机 `build.py` + http.server 验证 | 选中托管（对象存储/静态托管均可）、部署流水线 |
| A3 | **portal 后端服务**（explorer/status/transparency/proofs 的实时数据源：Sequencer metrics + 节点 RPC 桥） | WEB-ACC-4 / WEB-ACC-6、§6.5 五服务 | **explorer 侧已交付**：`explorer_gateway` devnet 网关（WAL 回放 + L1 RPC 代理，真实 3 节点联测一致）+ 页面同源实时接线；status/transparency 实时面板仍待部署 | 生产 portal 部署网关/只读桥（explorer 模式可复用 `explorer_gateway`，加反代同源与 TLS）；缓存与限流已内建（§6.2） |
| A4 | 线上 status 真实监控与故障演练 | WEB-ACC-6 | **静态层演练已通过**（`tools/status_fault_drill.py` 4 变体） | 接真实健康探测 + 事故记录存储；线上注入一次并归档 |
| A5 | **release 自动化**：docs tag / ABI 版本 / genesis hash / changelog / SBOM / 签名随 release 同步 | WEB-ACC-5 | 版本号集中定义于 `build.py SITE["ABI_VERSION"]`；changelog 手动 | CI release job：生成 SBOM（cargo-audit/cyclonedx）、签名、写入站点版本端点 |
| A6 | API 文档从源码 schema 自动生成 | §6.4 | api-reference 页为手工索引 | RPC/ABI schema 导出工具 + 构建钩子 |

## B. 钱包发布工程（§6.12）

| # | 项 | 关联门槛 | 当前状态 | 关闭动作 |
|---|---|---|---|---|
| B1 | **真机兼容矩阵**：MetaMask/Rabby、Argent X/Braavos、WalletConnect 真实 relay、Ledger/Trezor | WALLET-ACC-1 | 适配层完成 + capability 拒绝路径有测试（`extension/adapters/`）；真机互操作未测 | 三类真实钱包逐一过连接/签名/拒绝矩阵并留档；WC 需注册 projectId（B6） |
| B2 | 跨端签名一致性（WASM/桌面/移动 同 digest、sig bytes、tx hash） | WALLET-ACC-2 | WASM 与 Rust 同源已保证；跨端对比未测 | 移动/桌面壳落地后跑跨端向量（fixture 已可导出） |
| B3 | crash dump / 遥测 / 剪贴板敏感数据扫描 | WALLET-ACC-4 | 0.1 无分析 SDK/clipboard；`logSafe` 白名单日志 | 发布前跑敏感扫描工具链并入 CI |
| B4 | **可复现构建 + 签名包 + SBOM + 第三方安全审查 + 更新回滚** | WALLET-ACC-8、Extension 1.0 | 未开始（0.1 明确不声称） | 锁定工具链哈希、rebuild 校验、签名流程、外审排期 |
| B5 | WalletConnect 生产接入（`@walletconnect/sign-client` 注入 + projectId + relay 稳定性） | WALLET-ACC-1 / Extension 0.3 | 适配核心 + 内存 SignClient stub，接口就绪 | 注册 projectId、注入真实 SignClient、跑 B1 真机矩阵 |
| B6 | 独立钱包应用（Tauri 桌面 / React Native 移动壳） | §6.12.5 | CLI 钱包可用；GUI 壳未开始 | 复用 wallet-core，按 MVP 功能清单实现 |
| B7 | 移动平台 Secure Enclave/Keystore 包装、硬件钱包可读签名 | §6.12.5/6.12.7 | 未开始 | B6 之后 |

## C. 验证器与证明

| # | 项 | 关联门槛 | 当前状态 | 关闭动作 |
|---|---|---|---|---|
| C1 | **浏览器完整 STARK 验证（stwo-wasm）** | M6-ACC-1 完整口径 | v1 口径 = 结算关系验证面（wallet-core wasm）：连续 10 手已实测（见 extension/ACCEPTANCE.md M6-ACC-1 节） | stwo 编译 wasm（体积/性能可行性研究先行）或明确 v1 文档口径维持"关系验证 + 主机 STARK" |
| C2 | WEB-ACC-3 完全干净环境计时（新 clone、无 cargo 缓存、无 node_modules） | WEB-ACC-3 | 本机温/热缓存计时已测（见 ACCEPTANCE） | CI 干净容器跑 quickstart 并计时落档 |

## D. 内容与合规

| # | 项 | 关联门槛 | 当前状态 | 关闭动作 |
|---|---|---|---|---|
| D1 | `/legal` 法律文本法务评审（条款/隐私/地区/责任游戏） | WEB-ACC-8 | 模板全项就绪，未经法务评审 | 法务评审定稿；PGP key 与披露邮箱启用 |
| D2 | 品牌评审（工作名/视觉资产定稿） | §6.1 | 工作名 + 自绘 logo v0.1 | 品牌评审后全站替换并保留协议 id 版本化 |
| D3 | §6.7 各阶段门槛核对（P0/P1 安全项、事故演练、审计范围公示） | §6.7/§6.9 | 清单就绪 | 按发布阶段逐项核对签字 |
| D4 | 第三方审计报告页（范围/commit/未修复项/日期） | §6.9 | 如实标注"未做第三方审计" | 审计合同 → 报告 → 页面更新 |

## 判读规则

- 本清单任一项未关闭前，对外表述必须遵守 §6.1/§6.3 红线：不写"无信任提现 /
  抗审查最终性 / proof of reserves / 兼容所有主流钱包"等未达成能力。
- 已本地验证的验收证据（扫描、演练、吞吐、E2E）不因本清单存在而失效，但
  WEB/WALLET-ACC 的完整判定以"本地证据 + 本清单关闭"合并为准。
