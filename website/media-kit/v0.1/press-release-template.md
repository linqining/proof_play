# 新闻稿模板 v0.1

> 占位符以 `[方括号]` 保留，发布前填写；禁止删除托管与路线图限定句。

---

```text
ProofPlay Poker 发布 [网络版本/测试网版本]：面向扑克场景的专用 Appchain

[城市]，[日期] —— ProofPlay Poker 今日开放 [devnet/testnet/MVP]。该网络将桌级操作、结算证明和外部
资产边界分层设计：玩家可在 PLAY 环境体验低延迟牌局，开发者可以通过公开 ABI、
RPC 和 proof portal 复验结算记录。当前 REAL 资产仍处于 [托管/白名单/限额] 阶段；
BFT checkpoint、强制包含和 permissionless withdrawal 按公开路线图逐步启用。

本次发布包含：版本化协议文档、可复现 devnet、区块浏览器、状态页、漏洞披露流程
和公开测试指标。项目不会把测试网性能、托管对账或第三方审计表述为无信任保证。

技术要点（发布时按实际勾选）：
- [单 Sequencer 软确认链，操作反馈 p50/p99 实测值（附硬件口径）]
- [结算核心 SettlementPlan 单一事实源，payout root 完整绑定赔付]
- [真实 STARK 出证（stwo / Texas canonical AIR），独立 CLI 验证命令]
- [多节点组网验收：N 节点收敛与容错场景记录]

引用（发言人占位）：
"[关于分层设计与证明边界的引述]" —— [姓名]，[职务]

关于 ProofPlay Poker：
[一句话定位 + 仓库/文档/浏览器/状态页链接。项目为工作名，域名上线前为占位。]

媒体联系：[邮箱占位]
```

---

## 发布前检查

- [ ] 所有性能数字附硬件、并发、版本、样本数与 p50/p95/p99 原始报告链接。
- [ ] 禁用词扫描 0 命中（`python3 website/tools/scan_banned_words.py`）。
- [ ] REAL 状态句未被删改。
- [ ] 水印与版本号与发布版本一致。
