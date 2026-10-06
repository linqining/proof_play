# BATCH_POSTER_OPS —— batch-poster 常驻上链 daemon 运维手册

> 组件立项：`out/rollup-batch-submitter-survey.md` §9（各建议锚点 9.1..9.8
> 见该文件）；crate 结构与驱动契约：`batch-poster/src/lib.rs` 模块文档。
> 本文是部署/监控面的操作手册，随波次二（2026-10-01）落地。

## 1. 部署拓扑（最重要：legacy 结算投递已改走队列）

**texas 不再直发 legacy 结算**——legacy 路结算投递已改走 settle-queue WAL +
batch-poster daemon。生产必须运行 batch-poster（`deploy/batch-poster.service`），
否则 WAL 里的结算任务无人投递。

两侧交接目录**必须同值**：

| 侧 | env | 缺省（相对 CWD） |
| --- | --- | --- |
| texas（唯一写者） | `TEXAS_SETTLE_QUEUE_WAL` | `settle-queue/queue.jsonl` |
| poster（只读） | `TEXAS_POSTER_QUEUE_WAL` | `settle-queue/queue.jsonl` |
| texas（只读 sidecar） | `TEXAS_SETTLE_SIDECAR_DIR` | `poster-sidecar` |
| poster（独占写） | `TEXAS_POSTER_SIDECAR_DIR` | `poster-sidecar` |

缺省相对路径同值：同机同 WorkingDirectory（`/opt/texas`，见 service 单元）
可省略；**多进程/多目录部署必须两测都配成同一绝对路径**。单写者协议详见
`settle-queue/src/lib.rs` 模块文档（WAL 唯一写者 = texas；sidecar 独占写者
= poster；交叉只读）。

## 2. 覆盖边界（架构现状，部署前必读）

- **queue 覆盖 Legacy 投递路**：texas 预构建 calldata 入 WAL，poster 两笔
  驱动（RegisterSent → settlement_digest view 可见 → SettleSent）；
- **Dual 生产路保留直发**（txmgr 面）：原子 bundle / 赢额回锁 / 离桌释放
  语义无法预构建为队列两腿 payload，不走 WAL；
- **enqueue_dual + 死信降级契约已就位**：dual 腿投递重试耗尽 → poster 写
  sidecar 死信 → texas 读后执行 Dual→Legacy 降级重投（WAL `Downgraded`
  事件，无 legacy 保底 payload 则投递期死信绝不冒充）——后续迁移把 Dual
  路也切到队列时本节同步更新。

## 3. texas 侧回执转发语义（消费面）

poster sidecar receipt → texas 转发为 settle_receipt 落账 / WS 广播 +
`flush_leave_releases` + session 续钟。入队元数据缓存重启即失——仅影响
展示与续钟，**不影响投递正确性**（投递以 WAL + sidecar 事实为准）。

## 4. 发送面与费率（starknet-txmgr 备注）

- 发送面复用 texas 同款账户装配（`STARKNET_RPC_URL` /
  `STARKNET_OPERATOR_ADDRESS` / `STARKNET_OPERATOR_PRIVATE_KEY`，缺一
  fail-closed 拒绝启动；`batch-poster/src/bin/batch_poster.rs`）。
- ProviderSend 的 nonce/view 读块位随账户配置（两宿主均 PreConfirmed，
  连续两腿不撞 nonce）——同句已补进 `starknet-txmgr/src/lib.rs` crate 文档。
- **可见性判据（2026-10 起）**：每条腿的终态 = txmgr **回执轮询**（回执
  包含即算落账，不再对链上状态做 view 读回；`ReceiptBlock::PreConfirmed`
  回执被接受——前提是账户块位钉 PreConfirmed，见
  `starknet-txmgr/src/provider.rs` 头注释）；两腿之间的 register 生效门
  保留 `wait_call_visible` view 轮询（45×1s，吸收 texas 旧 submit.rs
  语义，`batch-poster/src/lib.rs` 驱动契约）。
- 已知缺口：`TxManagerConfig` 资源上限缺省实际被 ProviderSend 的 estimate
  分支接管（starknet-rs 因 l1_data_gas 未设走全量估计），真机费率行为待
  sepolia 冒烟确认——上线前安排一次小额冒烟。

## 5. status 端点与告警（survey §9.7 监控最小集）

`batch-poster run --bind 127.0.0.1:7331` 起 HTTP 端点；`GET /` 返回
PosterStatus 扁平字段 + `alerts` 数组（`batch-poster/src/status.rs`）：

| 字段 | 语义 |
| --- | --- |
| `pending_tasks` | 队列已拾取未回执任务数 |
| `pending_batches` | fold 攒批中（未回执）批数 |
| `oldest_batch_age_secs` | 最老未决批年龄（对 created_at 取 **min** 再算龄——已复核为 min 语义，lib.rs `status()` 与 bin `read_only_status` 同口径） |
| `in_flight_txs` / `txmgr_halted` / `draining` | txmgr 面 / 逃生口状态 |
| `operator_balance` | 观测值（当前未接线，恒 null） |
| `alerts[]` | `{code, detail}`；空数组 = 健康 |

告警码与阈值（**env 直读 status.rs**，未设置 = 该项不告警）：

| 告警码 | 触发 | 阈值 env |
| --- | --- | --- |
| `txmgr_halted` | 熔断停发（硬告警，无需阈值，人工 resume） | — |
| `pending_tasks_high` | pending_tasks > max | `TEXAS_POSTER_ALERT_MAX_PENDING_TASKS` |
| `pending_batches_high` | pending_batches > max | `TEXAS_POSTER_ALERT_MAX_PENDING_BATCHES` |
| `oldest_batch_age_high` | 最老批年龄 > max | `TEXAS_POSTER_ALERT_MAX_BATCH_AGE_SECS` |
| `in_flight_txs_high` | in_flight_txs > max | `TEXAS_POSTER_ALERT_MAX_IN_FLIGHT_TXS` |
| `operator_balance_low` | 余额 < min（STRK wei，hex/十进制） | `TEXAS_POSTER_ALERT_MIN_BALANCE_WEI` |
| `operator_balance_unobserved` | 配了余额阈值但观测未接入/不可解析 | 同上 |

**operator 余额阈值校准（survey §9.7 原文口径：Arbitrum 按 ~3 天成本
告警）**：取上线后约一周的日均 gas 消耗（starkscan 账户流出折 STRK），
`min = 日均 × 3`，并加低值硬底线（低于续费余量即先告警再充值）。仓内无
实测锚，`deploy/batch-poster.env` 的示例值是占位，不算数。

拉取方式：`curl -fs http://127.0.0.1:7331/`（建议监控侧对非空 `alerts`
或 HTTP 失败告警）；只读快照可不依赖端点：`batch-poster status`（不打印
alerts——那是端点口径）。

## 6. fold 攒批运营参数（batch-poster/src/config.rs）

| env | 缺省 | 说明 |
| --- | --- | --- |
| `TEXAS_POSTER_FOLD_ENABLED` | `false` | 攒批总开关；启用前先跑干跑冒烟 |
| `TEXAS_POSTER_MAX_BATCH_HANDS` | `64` | K 上限（= stark-recursion `MAX_HANDS_PER_LEAF`，批尺寸须 1..=64 且 2 的幂——batch.rs `check_batch_size` 已强制，配置重复越界会被 `PosterConfig::validate` fail-closed） |
| `TEXAS_POSTER_MAX_WAIT_SECS` | `300` | 攒批时间窗（最老候选超时即按计划尺寸发，不满 K 也发） |
| `TEXAS_POSTER_MIN_BATCH_HANDS` | `1` | 时间窗到期的触发下限（1 = 单手可成批，保 liveness；想摊薄出证成本可调 2/4） |
| `TEXAS_POSTER_PROVE_SCRIPT` | `../proving-tool/prove-batch.sh` | 两阶段出证腿入口 |
| `TEXAS_POSTER_PROVE_BASE_INPUT` | 空 | **启用 fold 必填**：基础手输入 JSON（102 词/手、全席非零参与者语料；缺失时 prove-batch.sh 自身 fail-closed 报错） |
| `TEXAS_POSTER_PROVE_WORK_DIR` | `/tmp/zgame-batch-poster` | 出证工作目录（K=64 实测峰值 ~3.7GiB 内存，机器内存 ≥6G 余量） |
| `TEXAS_POSTER_MAX_PROVE_ATTEMPTS` | `3` | 出证有界重试；耗尽 → 批死信、成员退回逐手驱动 |

真机出证（`prove-batch.sh`，实测 ~51.6s/批 @K=64、431k steps）是**手动
验收项**，不进自动化冒烟——见 `scripts/batch-poster-smoke.sh` 头注。

### 6.1 balance rollup（escape 地基，2026-10-01 M2）

| env | 缺省 | 说明 |
| --- | --- | --- |
| `TEXAS_BALANCE_ROLLUP_STATE` | 空（关） | 余额树 state 路径；**非空即启用**。fold 攒批启用时强制（`validate` fail-closed——逃生无地基不得真上链） |
| `TEXAS_BALANCE_ROLLUP_CHECKPOINTS` | `poster-sidecar/balance-checkpoints.jsonl` | checkpoint 审计语料（JSONL 追加，逐手 prev→new 根） |
| `PRIVACY_PROFILE` | 隐式推导 | `transparent`/`shielded`（缺省按语句面旧值别名；决定余额叶格式——docs/design/PRIVACY_PROFILE.md §5） |

行为：每手回执先入树（幂等，非零和/下穿 fail-closed 停驱动）→ 批
Receipted 时把累计根写批记录（`balance_root` 字段）+ spool 伴随工件
`<batch_key>.balance.json`（`keccak_root` 关联读；不动 Monad 信封跨仓
契约）。status 端点新增 `balance_root_head` / `balance_applied_hands`。
M4 真链启用前须以 vault 快照播种开局面（`BalanceRollup::seed_balances`，
仅创世可用）；树当前为**结算负债面**（买入/出金腿后置，见设计文档 §4）。

## 6.2 DA L0/L1（2026-10-02，M2 真链前置硬门槛）

**DA L0——异地快照备份（`da-backup` crate/bin）**：

| 操作 | 命令 |
| --- | --- |
| 单次快照（cron/timer 形态） | `da-backup run --config da-backup.json` |
| 常驻循环（第二块盘推式） | `da-backup watch --config da-backup.json [--interval 300]` |
| 快照完整性复核 | `da-backup verify <snapshot_dir>` |
| 恢复演练（打印 RTO 实测） | `da-backup restore <snapshot_dir> --into <dir>` |

manifest 形态（`da-backup.json`；覆盖面按部署实际裁剪）：

```json
{
  "dest_dir": "/mnt/backup-disk/poker",
  "retention": 7,
  "sources": [
    {"name": "queue",        "path": "settle-queue/queue.jsonl"},
    {"name": "sidecar",      "path": "poster-sidecar"},
    {"name": "appchain-wal", "path": "/tmp/texas-appchain"},
    {"name": "spool",        "path": "poster-sidecar/monad-spool"}
  ]
}
```

行为与边界：快照目录 `snap-<时间戳>-<pid>/`（零填充，字典序 = 时间序），
逐文件 SHA-256 写 `MANIFEST.json`（原子写），retention 轮换删最旧；
`verify` 对快照内部逐字节复核（篡改/缺失 fail-closed）；恢复演练输出
RTO 实测——排期 §3「DA L0 恢复演练 RTO>24h 或异地存储月成本超预算」
押后触发点以本命令为测量面。快照是崩溃一致性近似：拷贝期间源在追加，
JSONL 尾部可能撕裂——恢复安全性由各 WAL 重放的撕裂尾行修复兜底。
prove_log 为进程内存态（单一状态架构，无落盘文件），不在备份面；其
对账事实的持久化等价物是 queue WAL + sidecar（均在覆盖面内）。

**账本镜像（escape-ledger，2026-10-02 推荐形态落地）**：rollup 启用即
随批维护第二棵树——账本面（bytes20 地址 / u64 / SHA-256，规格逐字节镜像
zchain `EscapeHatch.sol`：domain `zchain.vault.balance_root.v1`、空叶补
齐、索引式逃生证明）。每批封印落盘 `<spool>/<batch_key>.ledger-root.json`
（`{spec_version, batch_key, ledger_index, root, leaf_count, hash_spec,
leaves 全量}`——逃生者取自己的 address/amount/leaf_index 离线重算兄弟
证明）。映射：钱包 felt 低 20 字节截断（= vault/结算 calldata 既定
address 派生）；单位 = poker wei ÷ `TEXAS_BALANCE_LEDGER_UNIT_WEI`
（缺省 1e15 = chips，与 texas `WEI_PER_CHIP` 同值锚）；尘额/下穿
fail-closed 停驱动。**规格冻结锚在合约侧**——改哈希/域/编码须先改
EscapeHatch.sol 并跨仓同步 SPEC_VERSION。

| env | 缺省 | 说明 |
| --- | --- | --- |
| `TEXAS_BALANCE_LEDGER_STATE` | `poster-sidecar/ledger-state.json` | 账本镜像 state（rollup 启用即跟随） |
| `TEXAS_BALANCE_LEDGER_UNIT_WEI` | `1000000000000000` | wei → 账本单位除数（与 texas `WEI_PER_CHIP` 同值锚） |

**DA L1——批 statements 伴随工件**：每批出证落盘
`<spool>/<batch_key>.statements.json`（信封同目录同键前缀）：字段
`{keccak_root, batch_fact, acc_prev, program_hash, members, statements}`
——批 fact 的 preimage 全量公开，任何人不依赖 operator 即可离线重算
`keccak_batch_root(statements) == keccak_root`（groth16-wrap 同式、
zchain SettleBatch 逐字一致）完成 fact ↔ 语句面绑定复核，防抵赖。
链上 calldata 公开腿随 M4/M5（与 balance_root 登记腿同节奏）。

## 7. 逃生与日常操作

```bash
systemctl status batch-poster            # 单元状态
curl -fs http://127.0.0.1:7331/ | jq .alerts   # 告警面
batch-poster status                      # 只读快照（WAL/sidecar 事实汇总）
batch-poster drain                       # 逃生：停拾新任务、在途清空后退出
                                         # （systemd 下 Restart=always 会拉起，
                                         #  持续停机用 systemctl stop）
```

- `txmgr_halted` 告警 = 熔断停发（fail-closed）：先对账（sidecar receipts
  vs 链上 settlement_digest），人工确认后重启进程恢复（resume 纪律见
  `starknet-txmgr/src/lib.rs`）。
- 崩溃恢复：poster 重启自动 WAL 全量重放 + sidecar 对账（回执幂等跳过、
  未终态批重出证——批键幂等保证不重复上链）。
