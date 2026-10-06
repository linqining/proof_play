# 文档站最低要求对照（plan §6.4）— docs-status.md

对照对象：zchain 仓库（github.com/linqining/zchain）`docs/plan-appchain-v1.md` §6.4「文档发布最低要求」+ 15 分钟 quickstart 要求。
状态图例：✅ 完成 · 🟡 部分 · ⬜ 待后端/待发布（不虚标完成）。

| # | 要求 | 状态 | 说明 / 落点 |
|---|---|---|---|
| 1 | 每个代码 release 对应 docs tag、ABI 版本、genesis/config hash | ⬜ 待发布 | 版本字符串已集中在 `build.py SITE`（docs v1.3.0-alpha / ABI v1.3）；release 自动同步流水线待发布基础设施（WEB-ACC-5）。`/docs/changelog/versioning/` 已定义 latest/next 机制 |
| 2 | API 文档从源码 schema 生成，含正例、负例、错误码、幂等与重试语义 | 🟡 部分 | 手工参考层已完成：`/docs/developers/rpc/`、`/docs/developers/errors/`、`/docs/api-reference/`（含生成要求清单）；生成流水线待接入 |
| 3 | 每个安全关键公式同时给出数学表达式、规范伪代码和测试向量 | ✅ | `/docs/security/threat-model/`（守恒、费率、签名绑定、三层门）与 `/docs/economics/rake/`：数学式 + 伪代码；测试向量指向仓库 golden vector（batch_root / payout_root / attestation 负例） |
| 4 | Note、结算、提现、checkpoint 提供独立验证命令，不要求运营方私有服务 | 🟡 部分 | Note/结算/提现验证命令已写（`/docs/proofs/verify/`：`cargo run -p poker-wallet --release -- verify proof.json`，wallet crate 由并行工作提供；适配器测试命令可用）；checkpoint 独立验证依赖 BFT（v1.5，未上线，页面已如实标注） |
| 5 | 明确列出"已实现 / 部分实现 / 仅 PoC / 禁止生产使用" | ✅ | `/docs/architecture/` 模块状态表、`/docs/validators/`（BFT 未开始）、`/roadmap/`（逐项勾选）、各页"状态"列；与仓库 BLOCKERS.md（B9 等）互相引用 |
| 6 | 所有性能数字附硬件、网络、并发、版本、样本数、p50/p95/p99 与原始报告链接 | 🟡 部分 | 已附口径（64 桌 × 50 手、3200 结算、p50 2.1ms / p99 3.5ms、预算 100ms、参考机口径声明）；独立可复验的原始报告文件待随 release 归档发布 |
| 7 | quickstart 15 分钟：启动 devnet → 创建 PLAY note → 开桌 → 完成一手 → 读取 settlement proof → 本地 verifier | 🟡 部分 | `/docs/getting-started/quickstart/` 全流程已写（克隆 → `cargo build --release --bin zchain` → `scripts/multi_node_e2e.sh 3` → loadtest 单桌演示 + E2E 一手 → 验证命令与预期输出样例）；note/开桌逐操作 CLI 待 wallet-core（页面已注明替换计划）。WEB-ACC-3 干净环境实测待做 |
| 8 | 示例不得默认使用 REAL 或真实外部地址 | ✅ | quickstart 与各示例全部使用 PLAY / 测试密钥；REAL 流程仅作边界说明 |
| 9 | `latest` 只指向已发布 release，草案进入 `next` | ✅（机制） | `/docs/changelog/versioning/`；当前无已部署网络，latest = v1.3.0-alpha，next 为空 |
| 10 | 版本化页脚 `docs v1.3.0-alpha (ABI v1.2.3)` | ✅ | docs 布局每页 kicker + 页脚注；版本集中在 `build.py SITE` |

## 备注

- `ABI_VERSION = v1.3` 为本站页脚约定值；仓库内 `poker-appchain/docs/ABI.md` 头部当前
  标注 v1.3（ABI_V2.md 为 v2-alpha 附录）。发布 release 前需同步核对一处：只改 `build.py SITE["ABI_VERSION"]`。
- 13 个板块全部存在且每个板块至少 1 页实质内容（getting-started 3 页、protocol 3 页、
  proofs 3 页、security 3 页、economics 3 页、developers 3 页、concepts 2 页、
  architecture 2 页、changelog 2 页、validators/operators/api-reference/legal 各 1 页）。
