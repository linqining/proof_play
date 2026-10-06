# 主网 STRK20 交易操作指引（TODO #28）

> 目标：在 Starknet **主网**完成 ≥1 笔 STRK20 交易，交易哈希回填 `strk20.json`。
> 该步骤需要**人工钱包操作**（私钥不出本机），脚本无法代办。
> 执行前重读 `docs/design/SETTLEMENT_PRIVACY_PLAN.md` §7 验证清单(历史迁移计划见 docs/archive/EXECUTION_PLAN.md)
> 「主网最小路径」：在「直接 STRK20 转账」与「PokerVault 主网最小部署」两案中
> **选最简者**。

## 方案对比

| 方案 | 动作 | 前置 | 成本 |
| --- | --- | --- | --- |
| A. 直接 STRK20 转账（推荐先行） | 钱包内发起一笔 STRK 转账（可自转账） | 主网钱包 + 少量 STRK（转账额 + gas） | 最低 |
| B. PokerVault 主网最小部署 + deposit | sncast declare + deploy + deposit | 主网账户（deployer 私钥）+ gas | declare/deploy gas 较高 |

最小口径：deposit + withdraw 即可——方案 A 用钱包原生 STRK20 转账即可满足
「一笔主网 STRK20 交易」；若需要 Vault 买入闭环，再补方案 B。
（2026-09-07 主网全量合约已部署并完成真实交易回路，本指南保留作操作参考。）

## 方案 A：直接转账（约 5 分钟）

1. 用 Ready（或任一 Starknet 主网钱包）确保主网账户有少量 STRK
   （转账金额 + ~0.01 STRK gas 余量即可）。
2. 在钱包内发起一笔 STRK 转账：
   - 接收地址建议用项目方演示地址（与 sepolia 演示同源），自转账亦可；
   - 金额任意（演示用 1 STRK 足够）。
3. 等待交易 ACCEPTED_ON_L2，从钱包或
   <https://starkscan.co>（切主网）复制交易哈希。
4. 回填 `strk20.json`（见下节模板），并同步 `README`/`README.zh-CN` 的
   Deployment 章节一句话记录。

## 方案 B：PokerVault 主网最小部署（可选，闭环叙事）

复用 `poker_contracts/scripts/deploy_sepolia.sh` 的口径，仅换主网参数：

```bash
# env（绝不入库私钥；用临时 shell 变量或本地 .env.mainnet）
SNCAST_URL="https://starknet-mainnet.public.blastapi.io/rpc/v0_7"  # 任一主网 RPC
SNCAST_ACCOUNT="<主网 deployer 账户名>"   # sncast account add 导入
```

1. `cd poker_contracts && scarb build`；
2. declare `PokerVault`（**无需本地代币**——vault v3 起绑定 canonical STRK：
   sepolia 现网 `vault.token()` 即原生 STRK（本地 pSTRK 与 PokerSwap 均已
   退役/移除，买入直接使用 STRK）。主网部署以同一构造为准，执行前仍建议
   核对 `poker_vault.cairo` 的 token_address 构造参数）；
3. deploy `PokerVault` + `deposit` + `withdraw` 各一笔（最小闭环）；
4. 全部交易哈希回填 `strk20.json`。

> ~~方案 B 会把「本地测试代币」暴露到主网~~（已不成立：vault v3 绑定
> canonical STRK），但方案 A 仍是最简路径——先交付 A，B 仅作闭环叙事补充。

## strk20.json 回填模板

```jsonc
// token 节点：
"mainnet_address": "<主网 STRK：0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07271812f30d58d03>",
// 若方案 B：另补 contracts 节点的主网 address/class_hash 与 note。

// transactions（或顶层 demo）节点新增：
"mainnet_tx": {
  "network": "mainnet",
  "kind": "native_strk_transfer",   // 方案 B 填 "vault_deposit"
  "tx_hash": "0x…",
  "timestamp": "<ISO8601>",
  "note": "STRK20 mainnet transfer (hackathon step 3)"
}
```

## 验收

- [ ] `strk20.json` 记录主网交易哈希，starkscan 主网可查、状态 ACCEPTED_ON_L2；
- [ ] README（英/中）Deployment 章节更新一句话；
- [ ] TODO.md #28/#29 勾选。

---

## 密钥分级：operator ≠ owner（2026-10-01 代码级落地）

出处：`out/rollup-batch-submitter-survey.md` §9.4 建议 4——operator 热钱包
（只发 `register/settle`）与 owner（钉扎 program hash、升级合约）分开。
本轮只做**代码级**（配置槽位 + fail-closed 校验 + 本文档），**不动合约**
（合约侧 operator 地址白名单化与轮换接口留待后续）。

### 配置槽位（`texas/src/starknet/config.rs`）

| 槽位 | env | 语义 | 缺省 |
| --- | --- | --- | --- |
| operator | `STARKNET_OPERATOR_ADDRESS` / `STARKNET_OPERATOR_PRIVATE_KEY` | 结算热流提交方（register/settle/fold settle），余额按 ~3 天发帖成本监控 | 空（dev 模式） |
| owner | `STARKNET_OWNER_ADDRESS` / `STARKNET_OWNER_PRIVATE_KEY` | 程序哈希钉扎/合约升级类离线操作身份 | 空（= 未配置，行为与改造前一致） |

### fail-closed 校验（`StarknetConfig::validate`）

`from_env()` 构造期即校验，违例直接拒绝启动（exit 2）：

1. owner 两个槽位必须**成对**配置（同空同有）；
2. owner 地址 == operator 地址 → 拒绝；
3. owner 私钥 == operator 私钥（felt 归一化比较）→ 拒绝。

### 运维纪律

- **owner 私钥不常驻服务器**：仅在钉扎/升级操作时以临时 shell 变量或
  本地 `.env.mainnet` 注入（沿用上文「绝不入库私钥」惯例）；服务器环境
  只保留 `STARKNET_OPERATOR_*`。
- ⚠️ 现存风险：`deploy/texas-server.env` 目前 operator 与 owner 是同一把
  deployer 钥匙（且私钥明文在仓库内）。轮换步骤：
  1. 新建独立 owner 账户，链上 `set_combined_program_hash` 等 owner 操作
     改由新身份执行（合约侧尚无角色白名单，本步为流程约定）；
  2. 服务器 env 只留 operator；owner 槽位仅在校验一致性时临时注入；
  3. 从 git 历史外暴露过的私钥视为已泄露——迁移到新账户并转移资金/权限。
- batch-poster daemon（`batch-poster/src/bin/batch_poster.rs`）当前复用
  `STARKNET_OPERATOR_*` 装配发送面，属 operator 热流一侧；不得改用
  owner 私钥跑 daemon。

---

## 批量上链部署/运维入口（2026-10-01）

- 结算投递已改走 settle-queue WAL + batch-poster daemon：部署/监控/逃生
  一律见 `docs/BATCH_POSTER_OPS.md`（systemd 单元 `deploy/batch-poster.service`
  + env 模板 `deploy/batch-poster.env` + 告警脚本 `scripts/alert-batch-poster.sh`
  + 干跑冒烟 `scripts/batch-poster-smoke.sh`）。
- **env 命名决策（记录）**：texas 侧队列/sidecar 路径走
  `TEXAS_SETTLE_QUEUE_WAL` / `TEXAS_SETTLE_SIDECAR_DIR`（缺省
  `settle-queue/queue.jsonl`、`poster-sidecar`，与 poster 侧
  `TEXAS_POSTER_QUEUE_WAL` / `TEXAS_POSTER_SIDECAR_DIR` 缺省严格一致）；
  **texas 与 batch-poster 两进程必须指向同一绝对路径目录**——WAL 唯一
  写者=texas、sidecar 独写=poster，任一侧路径漂移即互相看不见对方状态。
- 跨仓 Monad 结算面（batch-poster 落盘信封 → zchain `monad_settlementd
  --mode settle` 消费）的部署速查在 zchain 仓
  `docs/monad-settlementd-deployment.md`。
- survey 引用规范已收敛为 §9.N 逐条章节号
  （`out/rollup-batch-submitter-survey.md`），后续文档引用保持该格式。
