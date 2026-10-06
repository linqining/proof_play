# 双仓统一工程排期：真链与逃生主线

- 日期：2026-10-01
- 范围：`poker_texas_air` + `zchain`
- 产出方式：排期工作流汇总（对话敲定事项 + `out/`、`docs/` 落盘文档 + `/tmp/poker-air-e2e-findings.md`）。本文档为本路径既有排期稿的结构化重排与定稿，口径不变。
- 产能口径：单开发者、单机串行；估时单位为 dev 人日（含联调缓冲），日历缓冲单独记账、不计产能。

---

## 0. TL;DR

- **关键路径**：M1 → M2 → M3 → M4 → M5 → M6 = 3 + 6.5 + 6.5 + 3.5 + 11.5 + 7.5 = **38.5 dev 人日 ≈ 8–9 周日历到 M6**。
- **全口径总承诺**：38.5 + M7 6 + M8 7 + M9 9 = **60.5 dev 人日 ≈ 12–13 周日历**（含 M9 审计外部 2–6 周）。
- **单机互斥约束**（发现 7，e2e:39）：run4 独占窗（2 日历日）内同机禁止重证明/构建，以依赖边表达——M3←M2、M4←M3。M4 = 3.5 人日 + 3.5 日历缓冲，缓冲只进日历不计产能。
- **真链前必做硬门槛**（M2）：balance_root 地基 + DA L0/L1 + env 密钥轮换全部前置，M4 真实提交不得早于 M2。

**最近三个里程碑**：

| 顺序 | 里程碑 | 触发 | 估时 |
|---|---|---|---|
| 1 | M1 仓务收口：两仓入库与文档对账 | 立即（W1） | 3 人日 |
| 2 | M2 真链前置硬门槛（balance_root 地基 + DA L0/L1 + 密钥轮换） | M1 完成后立即；fold 真链提交之前必须完成 | 6.5 人日 |
| 3 | M3 e2e 语料线：看护重建与 run4 收官 | M2 完成后启动准备（faucet + 看护重建）；run4 独占窗置于 M2 构建结束后 | 6.5 人日 |

DAG 一览：M7（合规切片）为并行根、起 W1 持续穿插；M8（运营增强）依赖 M1、按缓冲穿插；M9（主网部署前置）从 M5 分支（M5 完成后启动审计准备）；主线 M6 与分支 M9 共享 M5 完成点。

---

## 1. 待办总清单

**优先级口径**：

- **P0**：立即执行（M1/M2——关键路径前置与真链硬门槛）
- **P1**：主线必做（M3–M6、M9 主线）
- **P2**：缓冲穿插（M7/M8）
- **押后**：挂起项，见 §3 再评估触发点
- **持续**：持续义务/跟踪/红线，不占排期槽位

**出处缩写**：`followup` = out/rollup-components-followup.md；`survey` = out/rollup-batch-submitter-survey.md；`TODO` = docs/TODO.md；`e2e` = /tmp/poker-air-e2e-findings.md；`z-monad` = zchain docs/monad-l2-settlement.md；`z-arch` = zchain docs/plan-multi-settlement-architecture.md；`z-tec` = zchain docs/plan-token-economy-compliance-v1.md；`z-road` = zchain docs/roadmap-schedule.md；`z-app` = zchain docs/plan-appchain-v1.md；`chat` = 对话敲定（无文件载体）。

| 来源 | 事项 | 优先级 |
|---|---|---|
| chat | 两仓未提交改动过目入库 ◐ 2026-10-01（poker 已入库；zchain 2 处待用户过目） | P0 · M1 |
| followup | snforge 全量回归（poker_contracts）✅ 2026-10-01（scarb 2.15.0，130/0，含 Sepolia fork；附带修复 HEAD 合约不可编译断裂，见 followup 条目 11） | P0 · M1 |
| followup、chat、e2e:3-8 | fold 真链全链路真实提交（prove-batch 两阶段 + spool 交接 + Monad envelope） | P1 · M4 |
| chat、本设计 | 隐私分档与泄露面设计文档落盘（docs/design/PRIVACY_PROFILE.md）✅ 2026-10-01 | P1 · M2 |
| chat、本设计 | PrivacyProfile 配置骨架（链中立键位，兼容旧 env 别名）+ balance_root 叶子随档 ✅ 2026-10-01（privacy-profile/balance-rollup 两 crate + 队列/批接线 + 随批伴随工件；边界见设计文档 §4 M2 行） | P1 · M2 |
| chat、本设计 | 电路语句面加固：digest 加盐（L2）+ cm 基座 blind（L4） | P1 · M5 |
| chat、本设计 | SOUNDNESS.md 隐私声明按档改窄 | P2 · M5 |
| chat、本设计 | 结算负债面→账本面映射登记器（poker 侧转换器：balance-rollup::ledger 规格镜像 EscapeHatch.sol + 随批 ledger-root 工件）✅ 2026-10-02 | P1 · M4 |
| chat、本设计 | 账本根登记调用方（registerBalanceRoot 按 batchIndex 消费 ledger-root 工件；daemon/独立执行器形态待定） | P1 · M4 |
| chat（2026-10-03 量化复跑） | wrap 电路 16→17 形状跟随迁移（真实 prove-hand 产物 17 felts vs OUTPUT_LEN=16——HAND_BINDING_INDEX 位移 + 约束数重测；发现与复跑数据见 monad-snark 报告 §10.1 附注；**M4 真实语料 wrap 路径前置**） | P1 · M4 |
| chat（2026-10-03 量化复跑） | wrap 粒度改造：按批 fact 包（语句 = fold_program_hash + keccak_root + batch_fact 三输入重陈述，约束量级远小于单手 4.58M）——摊销 ~0.5s/手 @K=64（0.25 @K=128）、verifyProof 216k/批 = 3.4k gas/手，全包内 ≈1.3s/手；与 16→17 迁移同批做 | P1 · M4 |
| chat（2026-10-03 量化对话） | fold 批 K 提档 64→128（钉扎程序常量 chain.rs:63——三处重钉 + 语料重出；证明摊销对 K 基本平坦：固定头 ~50k steps + ~6k/手、log 因子吃掉固定摊销收益，~0.8s/手不变；仅每批固定成本摊销收益，且当前速率下 300s 窗口先于 K 上限触发） | 押后（触发 = 300s 窗口实际批尺寸持续触顶 64，即 ≥25 手/分钟） |
| chat、本设计 | 树规格收敛约定（哈希各自原生/主体映射/每批增量根——PRIVACY_PROFILE §3 附注定稿；**须与运行中的 M5 逃生合约工作流对齐冻结**：EscapeHatch.sol 为规格锚，poker 侧只实现不拥有） | P0 · M4（先行，M4 登记腿前置） |
| chat、本设计 | Shielded 资金腿实盘启用（匿名腿强制） | 押后（触发 = shielded-v1 电路项落地 + M4 成本/延迟数据，与 zchain 角色决策联动） |
| followup、docs/MAINNET_TX_GUIDE.md:78,:105-109 | texas-server.env 私钥明文与 operator==owner 轮换 | P0 · M2 |
| chat | 逃生合约地基：balance_root 随 fold 批上链 | P0 · M2 |
| chat、followup | 逃生合约主体：forcedWithdraw + freeze + escape 三入口 | P1 · M5 |
| chat | forcedSettle 被迫纳批 | P1 · M6 |
| chat、survey | 哨兵监控程序 + 逃生演练（含 §9.7 残项告警） | P1 · M6 |
| chat | DA L0：WAL/收据/队列 WAL 异地备份 ✅ 2026-10-02（da-backup crate/bin：快照/轮换/verify/restore 演练带 RTO；prove_log 为内存态不入备份面，覆盖面=queue WAL/sidecar/appchain WAL/spool，见 BATCH_POSTER_OPS §6.2） | P0 · M2 |
| chat | DA L1：批 statements 语料 calldata 公开化 ✅ 2026-10-02（批 fact preimage 随批落盘 spool `<batch_key>.statements.json`，离线重算 keccak_batch_root 复核防抵赖；链上 calldata 公开腿随 M4/M5 与 balance_root 同节奏） | P0 · M2 |
| chat、followup | zchain 角色决策（venue 层保留 vs 降级） | 押后（触发 = M4 成本/延迟数据） |
| e2e:1,:47、chat | run4 1000 手 e2e 续跑与总报告 | P1 · M3 |
| e2e:46,:31 | dev bot 充值与玩家上筹码通道（发现 11 + 发现 5 合并）✅ 2026-10-02（texas `/api/dev/faucet`——嵌入模式直铸 PLAY 余额，REAL/非嵌入 fail-closed 拒绝，同 /dev/bot 门控；play_hands.sh 改 funder 代充 deposit_for + 空 depositTxHash 余额校验，bot 钱包退出部署关键路径） | P1 · M3 |
| e2e:42 | 发现 10 复现性观察（随 run4） | P1 · M3（0 额外人日） |
| e2e:40 | supervisor 停滞进程内升级策略（发现 8）✅ 已实现（zchain 工作树 scripts/poker_air_browser.mjs——连续 3 次 stall 警告 exit 3 交 supervisor 重启；待用户过目入库） | P1 · M3 |
| e2e:28 | 发现 4：GUI 会话直跑 supervisor 验证扩展路径 | P1 · M3（环境依赖） |
| e2e:32 | 发现 6：CDP 主线程阻塞 worker 化 | 押后 |
| e2e:27 | 发现 3：CfT 154 后台网络全断（环境级） | 押后 |
| e2e:11 | bug 1 残留：batch-poster daemon 报错文案 ✅ 2026-10-01（装配失败三类分报，exit 3 不变） | P0 · M1 |
| followup | followup 未解决核查发现落盘 ✅ 2026-10-01（3 条全闭环，明细入 followup「收尾状态」） | P0 · M1 |
| TODO:322-362 | TODO #50 勾选同步与尾注补注出处 ✅ 2026-10-01 | P0 · M1 |
| TODO:125-152 | TODO #38：释放权威证明化与序无关化 | 押后（随 P4） |
| TODO:154-169 | TODO #39：derive_settlement_plan 损坏两起待回填 | 押后（blocked-on-user） |
| survey:191 | survey §9.4 合约侧：operator 白名单化与轮换 | P1 · M5 |
| survey:192、proving-tool/prove-batch.sh:57 | survey §9.5：程序哈希管理（清单 + CI + 链上核对 + timelock） | P1 · M5 |
| survey:189 | survey §9.2 残项：丢弃交易重新 estimate fee 续发确认 | P2 · M8 |
| survey:193 | survey §9.6 残项：积压反向节流与费率滑窗 | P2 · M8 |
| survey §9 | survey §9 建议清单总览（已分解） | 不单独排期（已分解至 #3/#6/#8/#24–#27 等条目） |
| z-monad | monad_e2e 链上验收（人工领水后执行） | P1 · M4 |
| z-monad | 合约正式审计 + authority 多签 + golden 向量 | P1 · M9 |
| z-monad | monad_settle_batch 手动执行器收编 | P2 · M8 |
| z-monad | checkpoint BFT finalized 信号自动化 | P2 · M8 |
| z-monad | L2 sequencer 侧 ingest 端点 | P2 · M8 |
| z-monad | daemon 代领提现（claim relayer） | P2 · M8 |
| z-monad | Monad 上链上验 ZK 证明（刻意押后） | 押后 |
| z-arch | wallet-app 结算层常量接线 | P2 · M8 |
| z-arch | Phase 3 Solana 接入 | 押后 |
| z-arch | Phase 4 sequencer 去中心化立项 | 押后 |
| z-arch | SettleDispatcher fact-bridge 第二通道 | 押后（骨架立项） |
| z-arch | DaBackend 宿主 calldata / Celestia | 押后 |
| z-arch | Monad 主网结算合约部署与买入门位 | P1 · M9 |
| z-tec | C-M1：法务聘任 + 牌照申请 + geo_policy v1 | P2 · M7 |
| z-tec、z-road | C-M2 缺口三项（= 合规框架落地缺口，同源合并） | P2 · M7 |
| z-tec | C-M3 REAL 域小流量开跑 | 押后（依赖 C-M1） |
| z-tec | C-M4 欧盟牌照 / 美国 B2B | 押后（择一待拍板） |
| z-tec | TE-D5：EU GAME 币购买通道决策 | 押后（M7 仅备决策材料） |
| z-tec | 季度监管观察项复核（硬日期） | 持续 · M7（硬日期） |
| z-road | Cairo 递归桥 PoC 前置（FRI 降 q + OOD + economics） | 押后（CONDITIONAL） |
| z-road | Starknet Vault verifier 正式接入 | 押后（XL 立项项） |
| z-road | 储备证明（STARK） | 押后（XL 立项项） |
| z-road | stwo 递归证明聚合 | 押后（随上游排期） |
| z-road | 洗牌/发牌证明链阶段 1 | 押后（XL） |
| z-app | canonical AIR 纳入 v2 owner | 押后（待办登记） |
| z-app | v1 提现负债声明与 rebuy/addon 生产硬禁用 | P1 · M5 |
| z-app | Phase 2/3 宣称红线（持续约束） | 持续（红线生效中） |
| z-app | ACC 余 4 项部分达成 | 押后（外部依赖） |
| followup | GPU 加速（followup 条目 10 残项） | 押后（阈值已定） |
| e2e:39 | 发现 7：e2e 与重证明/构建同机互斥约束 | 已生效（DAG 约束边：M3←M2、M4←M3） |
| e2e:47、chat | e2e 巡检看护核实与重建 ✅ 2026-10-02（scripts/e2e_patrol.sh——run 级体检/进度台账/停滞处置，与 mjs 会话内 stall-watch + browser-supervisor 三层互补；用法见脚本头注） | P1 · M3（先行） |
| TODO:266 | TODO #5（遗留）：set_authorized_helper owner 单点（冷存储/时间锁） | P1 · M5 |
| TODO:382 | TODO #31：债券/罚没合约（主网化前提，Phase 3） | 押后（M9 门位决策点） |
| TODO:369-373 | TODO #12–15：sidecar 链（维持推迟） | 押后 |
| TODO:375 | TODO #26：STRK20 官方 SDK 跟踪（持续） | 持续（不排期） |
| TODO:378 | TODO #21：独立 prover 服务 | 押后（条件触发） |
| TODO:380 | TODO #23：Layer 3 递归协议 | 押后（条件触发） |
| TODO:268 | TODO #24⑤：错误分类（低优持续项） | 持续（低优，不排期） |

---

## 2. 里程碑

### 2.1 M1 仓务收口：两仓入库与文档对账

- **触发条件**：立即（W1）。
- **依赖**：无。
- **估时**：3 人日。
- **工作项**：
  - ◐ 两仓未提交改动过目入库（2026-10-01：poker 侧排期文档 + 两笔修复已入库；zchain 工作树余 2 处待用户过目入库——`scripts/poker_air_browser.mjs` stall 主动退出（先存改动）+ `monad-settlement/tests/envelope_fixture.rs:59` 失效行号锚修正（本轮补改），原「仅余 1 行」记录因后者更新）
  - ✅ followup 未解决核查发现落盘（2026-10-01：源记录 = 工作流 dwfrun-ad7881e6 核查产出；3 条全闭环——未解决项已随 zchain cef45e5 入库属「所有者认领」，失效锚补改，明细落盘 followup「收尾状态」）
  - ✅ TODO #50 勾选同步与尾注补注出处（2026-10-01：代码锚点核对成立——settle_wiring.rs / submit.rs txmgr 切换 / hooks.rs 三件套删除；尾注改注 survey 已随 cba99b68 入库；docs/TODO.md #50 已 [x]）
  - ✅ bug 1 残留：batch-poster daemon 报错文案（2026-10-01：production_send 装配失败三类分报——env 缺失 / env 格式错 / RPC 不可达（带 URL 与底层错误），exit 3 语义不变；四条退出路径实测 + cargo test -p batch-poster 7/0）
  - ✅ 结算负债面→账本面映射登记器（2026-10-02，推荐形态：balance-rollup::ledger 规格镜像 EscapeHatch.sol（SHA-256/bytes20/u64 LE/补齐索引式/leafCount），felt→address 低 20 字节截断（vault 既定派生），wei→chips 除数双仓同值锚，尘额/下穿 fail-closed；批封印随批落盘 `<batch_key>.ledger-root.json`（全量叶+规范序+规格自述——逃生者离线重算兄弟证明）；集成测试断言工件/叶集/规格串；登记调用方归 M4；**规格冻结锚在合约侧——与 M5 逃生工作流对齐为 P0 先行项**）
  - ✅ snforge 全量回归（poker_contracts）（2026-10-01：scarb 2.15.0，130 passed / 0 failed / 0 ignored，含 Sepolia fork 实测；发现并修复 HEAD 合约全工具链不可编译断裂——SNIP-36 路径 TxInfo v2/v3 错配 + 工具链门限（snforge 0.63 需 scarb ≥2.13.1，两 API 实测 cairo ≥2.15 才有），见 followup 条目 11）

### 2.2 M2 真链前置硬门槛（balance_root 地基 + DA L0/L1 + 密钥轮换）

- **触发条件**：M1 完成后立即；fold 真链提交之前必须完成（run4 独占窗开始前编码构建须结束）。
- **依赖**：M1。
- **估时**：6.5 人日。
- **工作项**：
  - 逃生合约地基：balance_root 随 fold 批上链（每批登记全体玩家余额 Merkle 根，fold 真上链前必须进，否则逃生验证无地基；含与 HEAD 93eda3af settlement prover 联动）
  - ✅ DA L0：WAL/收据/队列 WAL 异地备份（2026-10-02：da-backup crate/bin——快照/轮换/verify/restore 演练带 RTO 实测口径，第二块盘/对象存储挂载点推式；**修正**：prove_log 为进程内存态（单一状态架构）不入备份面，实际覆盖面=queue WAL/sidecar/appchain WAL/spool，manifest 按部署裁剪；撕裂尾行由各 WAL 重放容忍兜底；「RTO>24h 或月成本超预算」押后触发点以 restore 命令为测量面）
  - ✅ DA L1：批 statements 语料 calldata 公开化（2026-10-02：批 fact preimage 随批落盘 spool `<batch_key>.statements.json`——离线重算 keccak_batch_root(statements)==keccak_root 复核 fact↔语句面绑定，防抵赖；集成测试断言锚与条数；链上 calldata 公开腿随 M4/M5，与 balance_root 登记腿同节奏）
  - texas-server.env 私钥明文与 operator==owner 轮换（代码级——独立键位槽 + validate fail-closed——已完成；轮换为人工运维动作，步骤在 docs/MAINNET_TX_GUIDE.md:78 密钥分级节、:105-109 轮换步骤；2026-10-02 复核 runbook 在位——轮换三步 + 私钥已入库视同泄露的迁移警示；**待用户执行**）
  - ✅ PrivacyProfile 隐私分档配置骨架（2026-10-01：链中立键位 `PRIVACY_PROFILE=transparent|shielded` 一次选定语句面/资金腿/balance_root 叶子三层；兼容读 STARKNET_* 旧名别名；非法组合 fail-closed——docs/design/PRIVACY_PROFILE.md §5/§6）+ ✅ balance_root 叶子格式随档（transparent=明文叶 / shielded=承诺叶）：balance-rollup 随每手回执幂等推进（非零和/下穿 fail-closed），批 Receipted 根随批登记（批记录 + spool 伴随工件，链上入口腿随 M4/M5；边界=结算负债面 + vault 快照播种，见设计文档 §4）

### 2.3 M3 e2e 语料线：看护重建与 run4 收官

- **触发条件**：M2 完成后启动准备（faucet + 看护重建）；run4 独占窗（2 日历日，同机禁止重证明/构建，发现 7 约束）置于 M2 构建结束后。
- **依赖**：M1、M2。
- **估时**：6.5 人日（含看护重建与 supervisor stall 升级合计 1.5 人日；若核实看护实际仍在，看护项收敛为 0.5 核实、回收余量）。
- **工作项**：
  - ✅ e2e 巡检看护核实与重建（2026-10-02：`scripts/e2e_patrol.sh` 重建——进程面/日志活性体检 + bridge 进度台账（patrol.log）+ 跨会话停滞判定，`--kill-browser-on-stall` 可选处置（发现 7 恢复手法）；run 级、与会话内 mjs stall-watch 及 browser-supervisor 分工互补；后续占用 ~0.5–1 人日/周照旧）
  - ✅ dev bot 充值与玩家上筹码通道（2026-10-02，发现 11 + 发现 5 统一修复）：texas `POST /api/dev/faucet`（嵌入模式 Operation::Deposit 直铸 PLAY 余额 note 并立即证明化；REAL/非嵌入 fail-closed 503；同 /dev/bot 门控 debug||TEXAS_DEV_BOT_ENABLED=1；scenario 测试盖 PLAY 铸入/幂等/REAL 拒绝三面）+ `play_hands.sh` funder 代充（`.env.dev` 已部署账户 `vault.deposit_for(bot)` + 空 depositTxHash 走纯 chip_balance 校验——bot 钱包不再需自部署/approve/deposit，devnet 重建陈旧钱包的断腿整类消除；legacy 0 手路径打通）
  - ✅ supervisor 停滞进程内升级策略（发现 8 已实现：zchain 工作树 `scripts/poker_air_browser.mjs`——stallWarns 连续 3 次（45min）exit 3 交 supervisor 重启，重置逻辑随行；**待用户过目后随 zchain 入库**）
  - run4 1000 手 e2e 续跑与总报告（验收 = bridge target 1000 + exit 0；run4 中止于 580 手、未达标；看护重建后方可续跑）
  - 发现 10 复现性观察（随 run4，0 额外人日；扩展 popup CDP 通道 ~2.75h 劣化是否复现，相近时长复现即为可复现 bug）
  - 发现 4：GUI 会话直跑 supervisor 验证扩展路径（系统 Chrome 154 实测 `--load-extension` service worker 正常；待执行，环境依赖）

### 2.4 M4 fold 真链真实提交（Monad envelope）

- **触发条件**：M2 完成且 run4 独占窗结束（互斥依赖边）；zchain 测试钥领水到位（外部等待 1–3 天）。
- **依赖**：M2、M3。
- **估时**：3.5 人日 + 3.5 日历缓冲（缓冲只进日历不计产能）。
- **工作项**：
  - monad_e2e 链上验收（测试网 7/7 完成；单命令 monad_e2e 需先官方水龙头人工领取 MONAD_TESTNET_KEY）
  - fold 真链全链路真实提交（prove-batch 两阶段 + spool 交接 + Monad envelope；e2e:3-8 记录三层真跑已通过——K=2 真出证、spool 落盘、zchain monad_settlementd 消费；dry 边界 = 提交腿 starknet-devnet dummy operator 卡头；剩余 = 真实提交腿 + 成本/延迟数据采集。合并 followup 条目 4/8 与对话 fold 真链项。本项交付物同时触发 §3 的 zchain 角色决策与 GPU 阈值判定）
  - wrap 电路跟随迁移 + 粒度改造（2026-10-03 新增，合计 ≈1.5 人日）：① 16→17 形状跟随（真实产物 17 felts vs OUTPUT_LEN=16，HAND_BINDING_INDEX 位移 + 约束数重测——monad-snark 报告 §10.1 附注）；② 批 fact 级 wrap（语句 = fold_program_hash + keccak_root + batch_fact 三输入重陈述，替代按手包——摊销 ~0.5s/手 @K=64、verifyProof 216k/批 = 3.4k gas/手，全包内 ≈1.3s/手；信任边界不变=operator 背书重陈述，报告 §11）。①为 ②与 M4 真实语料 wrap 路径的共同前置

### 2.5 M5 逃生合约主体与提交面加固

- **触发条件**：M4 完成后（真链已开跑）第一迭代——口径与 dependsOn 统一。
- **依赖**：M4。
- **估时**：11.5 人日（上调：审计对象合约 + timelock 即合约改动）。
- **工作项**：
  - 逃生合约主体：forcedWithdraw + freeze + escape 三入口（StarkEx 模板三入口，服务窗口 7 天、押金防垃圾、无许可冻结；M4 完成后第一迭代；M9 审计对象）
  - survey §9.4 合约侧：operator 白名单化与轮换（isBatchPoster 式合约侧白名单化 + 轮换；原「不动 .cairo」排除已由逃生主线解除，与 env 轮换联动）
  - survey §9.5：程序哈希管理（清单 + CI + 链上核对 + timelock；现状仅 EXPECTED_PH 钉扎 proving-tool/prove-batch.sh:57 与 pin 脚本；timelock 两步切换本身含合约改动——pending hash 槽 + 激活入口）
  - TODO #5（遗留）：set_authorized_helper owner 单点（冷存储/时间锁；docs/TODO.md:266，开放 P1 项，M5 即合约运维窗口）
  - v1 提现负债声明与 rebuy/addon 生产硬禁用（前提现属多签/托管须如实声明；rebuy/addon 生产硬禁用实施确认）
  - 电路语句面加固：digest 加盐（L2）+ cm 基座 blind（L4）——泄露面审计 2026-10-01（docs/design/PRIVACY_PROFILE.md §1/§4），审计对象同批带走；SOUNDNESS.md 隐私声明按档改窄（transparent/shielded 两档叙事，M9 审计叙事前置）

### 2.6 M6 哨兵、逃生演练与 forcedSettle

- **触发条件**：M5 完成后；forcedSettle 工程先行、启用点 = REAL 桌启动。
- **依赖**：M5。
- **估时**：7.5 人日。
- **工作项**：
  - 哨兵监控程序 + 逃生演练（含 §9.7 残项告警；演练「运营方失踪 24h」全流程，托管用户逃生触发权交哨兵/多签；吸收 §9.7 未落地的 nonce 档位与链上事件停涨告警）
  - forcedSettle 被迫纳批（REAL 桌启动时做，逐手独立证明作弹药；载体 proving-tool/prove-hand.sh 已核实存在；被迫纳批引入乱序/缺手批面，须与 TODO #38 hand_id 序依赖联动评估或约束在单桌一次性提交口径内）

### 2.7 M7 合规工程切片（geo_policy / KYC watcher / EU 弃权）

- **触发条件**：起 W1 持续穿插；geo_policy v1 争取在 fold 真链前上线；轻活时段执行（如 run4 独占窗内做 TE-D5 决策准备）。
- **依赖**：无（并行根）。
- **估时**：6 人日。
- **工作项**：
  - C-M1：法务聘任 + 牌照申请 + geo_policy v1（律师聘任/申请/geo_policy v1 上线未完成；出口 = 受理函 + geo_policy 上线；阻塞 C-M2 剩余/C-M3）
  - C-M2 缺口三项（= 合规框架落地缺口，同源合并；watcher 钱包筛查接线、EU 14 天撤回弃权流程、法务评审；工程制动位已挂）
  - 季度监管观察项复核（硬日期：库拉索 2027-06、GENIUS 2027-01-18 USDC-only、UKGC 2026-02；季度复核义务）
  - TE-D5：EU GAME 币购买通道决策（法币 PSP vs 稳定币 + CASP 未拍板；M7 仅做决策准备材料，拍板押后）

### 2.8 M8 daemon/结算运营增强

- **触发条件**：M1 完成后按缓冲穿插（避开 run4 独占窗与 M4 出证）。
- **依赖**：M1。
- **估时**：7 人日。
- **工作项**：
  - monad_settle_batch 手动执行器收编（MonadSettleDispatcher + `--mode settle` 已落地首实现，手动执行器收编为后续阶段）
  - checkpoint BFT finalized 信号自动化（daemon 只消费 M8 checkpoint 文件，「finalized→导出→拾取」待全自动）
  - L2 sequencer 侧 ingest 端点（daemon 已支持 `--ingest-url` POST，sequencer 侧 HTTP ingest 待排期）
  - daemon 代领提现（claim relayer；leaf/proof 可由 builder API 导出，permissionless claim 不受影响）
  - survey §9.2 残项：丢弃交易重新 estimate fee 续发确认（持久化队列已落地；对账续投走死信回读 + 降级重投，「重新 estimate fee」细节未确认）
  - survey §9.6 残项：积压反向节流与费率滑窗（cadence 已定版 K=64/300s/min=1；op-batcher 积压反向节流与 Scroll skipSubmitByFee 未实施）
  - wallet-app 结算层常量接线（SETTLEMENT_L1/CHAIN_ID devnet 占位改注册表 JSON 读取；真实买入/提现密钥隔离路径接线）

### 2.9 M9 主网部署前置：审计 / 多签 / 门位

- **触发条件**：M5 完成后启动审计准备；审计外部 2–6 周；门位开启前置 = 审计通过 + #61 债券/罚没合约处置确认（实现或书面降级二选一）。
- **依赖**：M5。
- **估时**：9 人日（显式含 3 人日审计整改预留，回收型、无发现则回收）。
- **工作项**：
  - 合约正式审计 + authority 多签 + golden 向量（主网前置门槛未启动；authority 生产多签（Safe）+ daemon 多签队列；WithdrawalLeaf golden 向量 foundry 固化）
  - 审计整改预留（回收型，无发现则回收）
  - Monad 主网结算合约部署与买入门位（bridgeAddress null 门位关闭；部署前置 = 审计通过 + #61 处置确认）

---

## 3. 押后项与再评估触发点

全部触发点可判定（事件或阈值/日期）：

| 押后项 | 再评估触发点 |
|---|---|
| zchain 角色决策（venue 层保留 vs 降级） | M4 fold 真链真实成本/延迟数据到手（M4 交付物） |
| Shielded 资金腿实盘启用（匿名腿强制） | shielded-v1 电路项（M5）落地且 M4 成本/延迟数据到手（与 zchain 角色决策联动，docs/design/PRIVACY_PROFILE.md §2/§8） |
| GPU 加速（followup 条目 10 残项） | M4 实测单批 prove 时间 > cadence 窗 300s（现值 ~52s/批@K=64，proving-tool/prove-batch.sh:24，余量 ~5.7×） |
| Cairo 递归桥 PoC 前置（FRI 降 q + OOD + economics） | M4 数据落定后立专项；以「FRI 降 q≈72M 步可行性取得实测数据」为立项判据 |
| Starknet Vault verifier 正式接入 | 递归桥 PoC 三前置全部实测通过并达成 CONDITIONAL GO |
| 储备证明（STARK） | Vault verifier 完成 + 报表输入就绪 |
| stwo 递归证明聚合 | 上游 stwo 递归 API 排期公布 |
| 洗牌/发牌证明链阶段 1 | 上游阶段 1 wire 格式冻结（可核查发布事件） |
| canonical AIR 纳入 v2 owner | 上游 stwo v2 电路口径确定 |
| Monad 上链上验 ZK 证明（刻意押后） | 递归桥 PoC 三前置（FRI 降 q≈72M 步 / OOD scope / 聚合 economics）任一取得实测数据 |
| Phase 3 Solana 接入 | Monad 主网门位开启且 C-M4 市场优先级拍板 |
| Phase 4 sequencer 去中心化立项 | C-M4 谈判启动且对方尽调要求数中心化叙事，或主网门位开启后满 6 个月复评（取先到） |
| SettleDispatcher fact-bridge 第二通道 | zchain 角色决策 = 保留第二结算腿 |
| DaBackend 宿主 calldata / Celestia | DA L0 恢复演练 RTO>24h 或异地存储月成本超预算线（M2 上线后首季演练定值） |
| 发现 3：CfT 154 后台网络全断（环境级） | CfT/Chrome 版本升级或环境变更后重试 |
| 发现 6：CDP 主线程阻塞 worker 化 | run4 总报告显示仍影响语料质量，或看护重建后仍频繁楔死 |
| TODO #38：释放权威证明化与序无关化 | P4（多桌化）立项动工；M6 forcedSettle 若先行须带其序无关边界评估 |
| TODO #39：derive_settlement_plan 损坏两起待回填 | 用户回填核查结论（blocked-on-user） |
| ACC 余 4 项部分达成 | 对应外部依赖/决策门到位（M4-ACC-5 / M6-ACC-5 / M9-ACC-1 / M9-ACC-3） |
| C-M3 REAL 域小流量开跑 | C-M1 出口判据（牌照受理函 + geo_policy v1 上线）达成 |
| C-M4 欧盟牌照 / 美国 B2B | 商业侧择一拍板 |
| TE-D5：EU GAME 币购买通道决策 | 与 C-M4 联动（M7 仅备决策材料，拍板本身押后） |
| TODO #31：债券/罚没合约（主网化前提，Phase 3） | M9 主网门位开启决策点：须完成实现或出具书面降级决策（二选一，M9 部署项前置） |
| TODO #12–15：sidecar 链（维持推迟） | 官方 STRK20 Privacy SDK 上 npm 且 v2 escrow 输家扣款/现金出口修复启用（docs/TODO.md:369-371 原文解锁条件） |
| TODO #26：STRK20 官方 SDK 跟踪（持续） | SDK 上 npm 即核对 tryComposeInvoke（持续项，无排期） |
| TODO #21：独立 prover 服务 | 上链验证路线（#22/M3）需要第三方可复现证明 |
| TODO #23：Layer 3 递归协议 | #22 缺口收口 + #21 启动（docs/TODO.md:380 原文前置） |
| TODO #24⑤：错误分类（低优持续项） | 外部输入边界事故驱动（自 declared 低优持续项，不排期） |
| fold 批 K 提档 64→128 | 300s cadence 窗口实际批尺寸持续触顶 64（≥25 手/分钟）——证明摊销对 K 平坦（~0.8s/手），收益仅每批固定成本（锚定 tx/批工件 IO）摊销；钉扎程序常量三处重钉 + 语料重出为代价（§1 押后行） |

---

## 4. 关键假设与理由

1. **单开发者、单机串行**：全部估时为人日（含联调缓冲），并行只存在于机器运行面。
2. **并行口径已修正**：第一轮「并行线靠墙钟」的口径已被发现 7（e2e:39）证伪；本轮改为互斥依赖边（M3←M2、M4←M3），run4 独占窗（2 日历日）内同机禁止重证明/构建，dev 只做轻活（M7 决策准备挪入独占窗）。
3. **e2e 看护（修正）**：巡检自动化已删除（e2e:47，对话口径失效），M3 先花 1.5 人日重建（含 mjs stall 主动退出）；重建后占用 ~0.5–1 人日/周。
4. **真链前必做口径**：balance_root 地基 + DA L0/L1 + env 轮换全前置进 M2，M4 真实提交不得早于 M2。
5. **两本账**：关键路径 M1→M2→M3→M4→M5→M6 = 38.5 dev 人日 ≈ 8–9 周日历到 M6；全口径总承诺 3 + 6.5 + 6.5 + 3.5 + 11.5 + 7.5 + 6 + 7 + 9 = 60.5 人日 ≈ 12–13 周日历（含 M9 审计外部 2–6 周）；M4 = 3.5 人日 + 3.5 日历缓冲，缓冲只进日历不计产能。
6. **估时修正**：balance_root 3.5（含与 93eda3af settlement prover 联动）；M5 上调 11.5（审计对象合约 + timelock 即合约改动）并显式留 3 人日审计整改预留（回收型）；forcedSettle 3.5（逐手载体 proving-tool/prove-hand.sh 已核实存在但接线未确认，含 #38 序依赖边界评估）。
7. **冲突处理**：对话与文件冲突以可核查文件为准并保守排期（巡检重建，若核实仍在则回收 1.0）；TODO #39 / C-M4 / TE-D5 等用户与商业决策项不硬编，只留可判定触发点（事件或阈值/日期）。
8. **2026-10-03 增量**：wrap 电路 16→17 跟随迁移 + 批 fact 粒度改造并入 M4（合计 ≈1.5 人日，M4 3.5 → 5；全口径 60.5 → 62）；K=128 提档入 §3 押后（证明摊销对 K 平坦的量化：固定头 ~50k steps + ~6k/手，log 因子吃掉固定摊销收益——monad-snark 报告 §10.1 附注同源数据）。

---

## 5. 变更纪律

- 本文档由排期工作流产出，是排期唯一事实源；**条目完成时回写状态**：在 §1 表与 §2 对应工作项处标注 ✅ 与完成日期，不删除条目、只改状态。
- 里程碑完成时回写实际完成日期与偏差原因；估时若修正，在 §4 留痕。
- 新增待办先入 §1 总清单并定优先级，再决定进 §2 里程碑或 §3 押后；每个押后项必须带可判定触发点（事件或阈值/日期）。
- 用户/商业决策项（TODO #39、C-M4、TE-D5、TODO #31 等）只随 §3 触发点推进，不硬编日期。
- 对话口径与可核查文件冲突时，以文件为准并保守排期。
- 本文档随正常仓库文档流程入库（本次写入不做 git commit）。
