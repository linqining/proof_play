---
title: 路线图
lang: zh-CN
section: roadmap
lead: Phase 0 已完成，Phase 1 进行中；v1.5 / Phase 2 / Phase 3 未开始。未上线的能力不在本页宣称可用。
---

## 当前状态（2026-09-12）

### Phase 0 —— 已完成

- [x] 统一结算核心 `poker-settlement-core`（SettlementPlan / SidePot / RunoutSchedule / PayoutVector / rake / SettlementPlanDigest，域标签冻结）
- [x] §5.2 P0 八项全部关闭（结算单一事实源、pot 派生、REAL 真证明、原子提交、连续水位、哈希/顺序统一、输出完整绑定、共识校验）
- [x] 连续证明水位（缺口集实现，只推进最大连续前缀）
- [x] ABI 冻结（v1.2.x：批次根 §7 Poseidon 域标签 + golden vector、attestation v2.1、提现 finality 门槛 §9）

### Phase 1（MVP）—— 进行中 🚧

- [x] 单 Sequencer（软确认链 / WAL 原子提交 / 限流 / 重放）
- [x] 真实 stwo 证明（canonical AIR，E2E 一手真实出证 + 深度篡改负例）
- [x] 3/4 节点组网验收（全收敛 skew=0；4 节点 kill-one 容错；重启追块）
- [x] E2E 完整一手（3 人 REAL 桌：盲注镜像 → raise/all-in/fold/call → 收池 → 守恒恒等式成立）
- [x] ForceInclude（M3-ACC-6：SeenReceipt 签发/查询、inclusion deadline 强制包含、tx_hash 确定性排序、CensorshipProof 三态检测；罚没仅记录属 v2）
- [ ] BFT checkpoint（属 v1.5 范围，本 Phase 只要求入口预留）
- [ ] 链上出入金收尾（链上侧已接线：VaultProvider trait + Mock/Starknet 双实现、存款幂等桥、提现 finality 执行、自动对账告警；剩余为线上桥校准，待真实 Starknet 环境）
- [x] watcher 证据独立化（M3-ACC-7：`appchain_watcher` 独立进程，软确认链/结算语义/proven log 批次根/checkpoint 四路独立重算交叉核对 + 分叉检测）

### 钱包与产品化（plan §6 / M6，v1.3 已交付）

- [x] wallet-core 九模块 + CLI 钱包 + Extension 0.1（MV3 + wallet-core WASM + `zchain_*` provider，真实浏览器 E2E；M6-ACC-1 浏览器吞吐 PASS）
- [x] 连接协议适配器：EIP-1193 只读白名单 / WalletConnect v2 namespace 映射 / Starknet SNIP-12 授权委托（79 用例钉住红线；真机矩阵归发布前置清单）
- [x] 官网 13 路由 + 文档站 28 页 + media-kit v0.1（devnet 静态交付；TLS/CDN/portal 后端/release 自动化为发布前置，见状态页披露）
- [x] 验收扫描：禁用词 0 命中、内链 0 断链、a11y 全过（`website/ACCEPTANCE.md`）

### v1.5 —— 未开始

- [ ] 4–7 validator HotStuff-2/Jolteon checkpoint、阈值 BLS
- [ ] DA 层、bond/slash
- [ ] 抗审查演练（审查交易在 2 个 checkpoint 内强制包含）

### Phase 2 —— 未开始

- [ ] Starknet Vault verifier、withdrawal root
- [ ] 挑战/退出协议、permissionless claim
- [ ] 储备证明类能力（外部可独立验证偿付；术语使用受<a href="/transparency/">透明度页</a>边界约束）

### Phase 3 —— 未开始

- [ ] table sharding、Narwhal 风格 mempool、多运营方、B2B SLA

## 区块浏览器开发计划

explorer 当前为<strong>接口就绪的静态层</strong>（SAMPLE DATA 全标注）。开发按四个阶段推进；未上线能力不在页面宣称可用。

### E0 —— 静态层（已完成）

- [x] 页面结构与数据口径定义：四态确认层级、PLAY/REAL 标识、失败原因与水位缺口如实展示
- [x] SAMPLE DATA 静态层上线（`/explorer/`，已标注非实时）

### E1 —— 只读实时网关（已完成）

- [x] 只读 JSON 网关 `explorer_gateway`：appchain WAL 回放态 + L1 节点 RPC 代理（每 IP 限流、缓存；默认只绑回环，`--public` 显式开启并告警）
- [x] explorer 页接实时数据（同源 fetch + 刷新按钮；无网关时静默保持 SAMPLE DATA 现状，不误标实时）
- [x] 验收：3 节点 devnet 起网后，经网关取回真实高度与块（代理 `zchain_block_height` 与节点直连一致，块含 DAG commit certificate）

### E2 —— appchain 领域查询（部分完成）

- [x] 结算查询：`/api/v1/settlements`（分页 + 桌过滤 + proven/soft_accepted 层级标注）、`/api/v1/settlement/{hand_binding}` 全量明细
- [x] 水位与批次根：`/api/v1/status`（proven watermark，proven-log 恢复）+ `/api/v1/batch_roots`；契约经 watcher 独立重算交叉校验一致
- [x] proof 归档检索：证明注册表（pipeline 挂账 JSONL）+ `/api/v1/proof/{binding}` 下载（引擎头 + base64 归档字节）；settlement 明细含 payout_root 与 proof 链接，"帧 → settlement → payout_root → 归档下载"全链路已测试与 smoke 钉住
- [ ] indexer 持久化（archive 节点级；当前为 replay 态 + 注册表/聚合 sidecar）

### E3 —— proof portal 本地复验闭环（WEB-ACC-4）

- [ ] explorer settlement 一键跳转 `/proofs/`，输入 digest/hand id 由浏览器本地验证，显示 verifier 版本、proof digest 与验证耗时（§6.2）
- [ ] v1 复验面 = wallet-core wasm 结算关系验证（与 M6-ACC-1 同口径）；stwo-wasm 完整 STARK 浏览器验证列入发布前置 C 组

### E4 —— checkpoint 与 rake 审计视图（v1.5 联动）

- [ ] BFT checkpoint 上线后补 ordered / finalized 两态真实来源（此前该两级显示"未上线"）
- [ ] rake 累计视图与独立审计导出工具联动（M5-ACC-3）

## 发布节奏（plan §6.7）

| 阶段 | 对外内容 | 资金范围 | 退出条件 | 状态 |
|---|---|---|---|---|
| Devnet | 开源代码、quickstart、模拟牌局 | 仅 PLAY | smoke test 与文档可复现 | **当前** |
| Testnet | faucet、explorer、proof portal、漏洞赏金 | PLAY；REAL 关闭 | P0/P1 安全项关闭、事故演练通过 | 未开始 |
| MVP | 受控 PLAY + 小规模 REAL 内测、透明度报告 | REAL 白名单/限额 | 账实对账、提现 SLA、runbook | 未开始 |
| BFT preview | validator 招募、checkpoint、DA、ForceInclude 演示 | REAL 仍受限 | 4–7 validator 容错与审查演练 | 未开始 |
| Mainnet candidate | 第三方审计、公开 release、迁移手册 | 按地区与合规策略 | 全部主网门槛与回滚演练 | 未开始 |

## 承诺边界

在 Phase 1.5 与 Phase 2 完成前，本项目不对外宣称抗审查最终性、无信任提现或"REAL 结算由链上合约独立保证"。当前 v1 是托管式网络：软确认只代表运营方承诺；REAL 提现要求 proven 水位 + 批次根双重 finality，且仍走运营方托管打款流程。

已知遗留（如实披露）：

- rake 口径已统一（BLOCKERS B9 已关闭）：`rake_base()` = contested 层 gross 之和、uncalled 返还不计费（ABI v1.2.2，含 uncalled 手 e2e 正例）；遗留仅个别边界终局形态（如 raked-sole-survivor）仍 fail-closed 拒绝。
- Revealing→Betting 洗牌/发牌续链属上游路线；当前一手证明自 hand-start 镜像起。
- 单 Sequencer 停机 = 全场停摆（v1 已知边界，watcher + 告警缓解）。
