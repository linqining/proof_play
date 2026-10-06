# 批量上链组件后续任务清单（rollup-components follow-up）

> 来源：双仓组件补充工作流（run `dwfrun-20c694c6`，2026-10-01 完成），已落盘于两提交：
> poker_texas_air `cba99b68 feat: replay`（settle-queue / starknet-txmgr / batch-poster + 文档）、
> zchain `8b1826f feat: monad settlement`（SettleDispatcher / EvmTxManager / MonadSettleDispatcher / FactQueue + 文档）。
> 7 个组件均已通过受影响 crate 的 `cargo check + cargo test` 门控；以下为本阶段明确未做或遗留的项，按优先级排列，稍后实施。

## 收尾状态（2026-10-01，波次二完成后更新）

判定依据（由工作流门控与核查提供，本文件更新者未复跑全量）：

- **首轮门控**：poker = `cargo test -p texas` / `-p settle-queue` / `-p starknet-txmgr` / `-p batch-poster` 全部通过；zchain = `cargo test --workspace` 全部通过。
- **全量回归**：poker = `cargo test -p stark-recursion`（RUST_MIN_STACK）/ `-p hand-verify-native` / `-p texas` / `-p batch-poster -p settle-queue -p starknet-txmgr` / heavy `fold_batch_test --release --ignored` 全部通过；zchain = `cargo test --workspace`（全量回归）全部通过。
- **核查发现 3 条**（2026-10-01 M1 收口落盘；源记录 = 工作流 dwfrun-ad7881e6「批量上链后续任务实施」核查员产出，此前明细未随本文件落盘）：
  1. ✅ 已闭环（原「未解决」项）：zchain `poker_l1/tests/live_game_e2e.rs:542-547,644-659` 存在未被任何实施自述认领的实质改动——硬编码钉扎程序哈希 `0x744d16d3…`（#18 Phase C slice-2 电路，电路迁移后失配）替换为 `program_hash_of_artifact(proof_json)` 自出证工件 public_outputs.json 派生。核查时既未认领也未还原（疑似停止实例 dwfrun-177a3cd1 遗留，复核仍未解决）；2026-10-01 已随 zchain `cef45e5 feat: monad settlement` 入库，属「所有者认领」，触发点关闭。
  2. ✅ 如实记录（判无功能影响）：`proving-tool/prove-batch.sh` +6 行（:24-29 文档性注释），与分工排除项「不动 prove-batch.sh」字面冲突；EXPECTED_PH（现 :57）与 `batch-poster/src/config.rs` 钉扎值逐字符同值、语义零变化；现随 HEAD 93eda3af 在库（树净）。
  3. ✅ 已修复（2026-10-01）：zchain `monad-settlement/tests/envelope_fixture.rs:59` 注释引用失效行号锚「prove-batch.sh:51」（poker 仓六处 :51 锚已改，zchain 副本漏网）——M1 收口在 zchain 工作树补改为 :57，与 `scripts/poker_air_browser.mjs` 改动一并待用户过目入库。
- **排除项（保持原样）**：真机 Monad RPC E2E（环境不可得，以跨仓 envelope fixture 测试替代覆盖交接面）；snforge 全量（✅ 2026-10-01 M1 收口已执行——scarb 2.15.0，130 passed / 0 failed / 0 ignored，含 Sepolia fork 实测，见条目 11）；prove-batch.sh 真跑（50s+/批，列手动项）；条目 10（followup 自述出范围）；合约改动（条目 5 只做代码级，不动任何 .cairo——M1 收口的编译修复为唯一例外，见条目 11）；全量回归不由实现者自行执行（门控脚本统一跑）。

## P0 — 接线与回归（组件就位，生产链路尚未切换）

### 1. texas 入队接线到 settle-queue（最大缺口）✅ 已完成
- 本轮 `texas/src` 零改动：入队源应是 `prove_log::take_settle_input`（`texas/src/starknet/prove_log.rs:434` 附近），接 `settle_queue` WAL（append 入队）。
- 消除进程内结算状态 `PENDING_SETTLE` / `SETTLE_OK` / `SETTLE_ATTEMPTS`（`texas/src/starknet/hooks.rs:19-58`，重启即丢）。
- poster sidecar 死信回读 → texas 执行 Dual→Legacy 降级重投（写 WAL `Downgraded` 事件；单写者协议见 settle-queue crate 文档）。
- `prove_log` 保留为对账事实源，队列只管投递。

> 完成纪要：`texas/src/starknet/settle_wiring.rs` 落地（文件头自锚「follow-up 条目 1」：WAL 入队/构建期死信/Dual→Legacy 降级 + sidecar 回执/死信回读）；hooks.rs:8 注明进程内三件套已删除（:385/:809 旧语义归并说明）；legacy 投递改走队列见 docs/BATCH_POSTER_OPS.md §1；`cargo test -p texas` 门控通过。

### 2. texas 发送面切换到 starknet-txmgr ✅ 已完成
- `texas/src/starknet/submit.rs` 的 `submit_settlement` / `submit_dual_settlement` 两笔发送换走 txmgr（calldata 构建不动）。
- `wait_register_visible`（submit.rs:307-323）与 `is_register_replay` / `is_settle_replay`（submit.rs:296-303）的语义已吸收进 txmgr 的 `visible.rs` / `replay.rs`，切换后删除旧实现。

> 完成纪要：submit.rs:6-7 注明「2026-10-01 起发送面换 txmgr」并引入 `TxManager/ReplayVerdict/SendOutcome`（:29-30）；:303 注明旧重放判定语义吸收进 txmgr replay.rs（rollup-components 条目 2）；旧 `wait_register_visible` 已删（batch-poster lib.rs 头注同口径）；`cargo test -p starknet-txmgr` 与 `-p texas` 门控通过。

### 3. 两仓全量回归（本轮门控只覆盖受影响 crate）✅ 已完成（snforge 除外）
- poker_texas_air：`cargo test -p stark-recursion`（需 `RUST_MIN_STACK=16777216`）、`-p hand-verify-native`（heavy 用 `--release --test fold_batch_test -- --ignored`）、`-p texas`、snforge（须在 `poker_contracts/` 内跑）。
- zchain：`cargo test --manifest-path /Users/mac/projects/zchain/Cargo.toml --workspace`。

> 完成纪要：首轮门控与全量回归两轮均全部通过（判定依据见顶部「收尾状态」，由门控脚本/核查执行；本文件更新者未复跑全量）；snforge 为唯一剩余项，按排除项归最终核查员——2026-10-01 M1 收口已补执行（scarb 2.15.0，130/0 全绿，见条目 11）。

### 4. 跨仓 spool 交接 E2E 演练 ◐ 部分（真机 E2E 排除，顺手项已完成）
- `TEXAS_MONAD_SPOOL_DIR`（poker 侧 batch-poster 落盘 `MonadProofEnvelope`）→ zchain `monad_settlementd --mode settle --settle-inbox <dir>` 真机跑通一轮。
- 顺手项：zchain `settle_dispatch.rs:301-308` 的 `scan_inbox` 对解析失败文件静默跳过（`Err(e) => { let _ = e; }`）——schema 已对齐修复，但这里应加日志/告警，避免再次出现「同名不同形」静默丢件。

> 完成纪要：真机 E2E 按排除项不做（环境不可得），交接面以 `monad-settlement/tests/envelope_fixture.rs`（poker 真实序列化产物 + 冻结键集断言）替代覆盖，随 `cargo test -p monad-settlement` 通过；顺手项已完成——daemon `run_settle` 现对解析失败文件显式记日志「settle inbox REJECTED <path>: <reason>」（monad_settlementd.rs run_settle 循环，不静默跳过），告警规则落 docs/37-11-batch-settlement-ops.md §3。

## P1 — 运维与安全（survey §9 对应项）

### 5. 密钥分离 ✅ 已完成（代码级；合约未动）
- poker：operator 热钱包（只发 register/settle）与 owner（钉扎 program hash、合约升级）分账户。
- zchain：settle 与 anchor 通道**分密钥/分进程**运行（`monad-settlement/src/evm_txmgr.rs:15`、`settle_dispatch.rs:37` 明确的迁移前约束；两套本地 nonce 账本）。

> 完成纪要：poker `STARKNET_OWNER_ADDRESS`/`STARKNET_OWNER_PRIVATE_KEY` 槽位 + `StarknetConfig::validate()`（成对校验、owner==operator 地址/私钥 felt 归一化判等即 exit 2，`from_env` 构造期强制）+ docs/MAINNET_TX_GUIDE.md「密钥分级」节（含 texas-server.env 同钥反面现状与轮换步骤）；zchain `--settle-key-env`/`--settle-key-file` 独立键位槽 + `parse_args` 对键同源（同 env 名）/同值（派生 EOA 相同）fail-closed 拒启 + docs/37-1-node-deployment.md §8 runbook；`cargo test -p texas starknet::config` 与 `cargo test -p monad-settlement` 通过。未解决遗留：deploy/texas-server.env 仍为 operator==owner 且私钥明文入库（轮换是人工运维动作，步骤已写入 MAINNET_TX_GUIDE）。

### 6. AnchorSubmitter → EvmTxManager 迁移（zchain 后续阶段）✅ 已完成
- `monad-settlement/src/anchor.rs` 本轮未动（本地 nonce `:121`、一次性重取 `:176-178` 保持现状）。
- 迁移时以对拍测试守护行为等价（`settle_dispatch.rs:10` 的既定做法）。

> 完成纪要：`AnchorSubmitter<B: Broadcast = L1RpcBroadcast>` 发送面已迁 `EvmTxManager`（nonce 账本/每轮首笔保序/RBF 梯度/在途上限 8），等价性由 `monad-settlement/tests/anchor_txmgr_parity.rs` 对拍守护（nonce 序列/交易字节/状态机逐字节一致，显式差异仅 fail-closed 改进），随 `cargo test -p monad-settlement` 通过；evm_txmgr.rs 头注释「现状与迁移边界」已同步为迁移后陈述。

### 7. 部署与监控 ✅ 已完成
- `batch-poster` 与 `monad_settlementd` 的 systemd/docker 部署单元（参照笼内 fold-mt-* 单元先例）。
- status 端点接告警：pending 批数、最老未决批年龄（注意 lib.rs 已修为取 min）、in-flight、operator 余额（参照 Arbitrum 按 ~3 天发帖成本阈值告警）。

> 完成纪要：poker `deploy/batch-poster.service` + `deploy/batch-poster.env`（模板，私钥不入库）+ `scripts/alert-batch-poster.sh`（拉 status 端点 `alerts` 数组，0/1/2=OK/WARN/CRIT，四条退出路径实测）+ `docs/BATCH_POSTER_OPS.md`（部署拓扑/告警阈值 env 表与校准/逃生操作）；告警判定在 daemon 侧（status.rs `AlertThresholds` env 直读 + `evaluate_alerts`/`to_alerted_json`，含 operator_balance_unobserved 监控缺口告警）；zchain `deploy/monad-settlementd@.service` 模板单元（实例名=mode，分进程分密钥）+ `scripts/monad-settlementd-run.sh`（同钥预检等四 guard 实测 exit=2）+ `docs/monad-settlementd-deployment.md` 部署速查 + docs/37-11 日志告警规则；两个单元文件本机无 systemd-analyze（macOS），以 configparser 严格 INI 结构校验替代。

## P2 — 调参与收尾

### 8. fold 攒批运营参数 ✅ 已完成（真跑列手动项）
- cadence / K 值默认（`batch-poster/src/config.rs` 的 fold 开关；K≤64 且 2 的幂，`batch.rs:23` 对齐 `stark_recursion::chain::MAX_HANDS_PER_LEAF`）。
- `prove-batch.sh` 两阶段腿（ScriptProofSource 包装）真机冒烟，program_hash 对拍锚 `prove-batch.sh:51 EXPECTED_PH`。

> 完成纪要：运营默认值定版于 `CadenceConfig::default`（K=64/窗 300s/min=1）与 `FoldConfig::default`（enabled=false 刻意缺省、钉扎哈希、重试 3）；env 槽位补齐 `TEXAS_POSTER_MIN_BATCH_HANDS`、`TEXAS_POSTER_MAX_PROVE_ATTEMPTS`；`scripts/batch-poster-smoke.sh` 干跑冒烟端到端 PASS（--lib 单测 15 通过 + EXPECTED_PH↔FoldConfig 钉扎对拍 + status 只读探测，不触发真实出证）；`prove-batch.sh` 真机冒烟按排除项保持手动验收（50s+/批）。

### 9. 核查发现 5 复核（预计已随提交失效）✅ 已完成（零修改关闭）
- `settle-queue/src/lib.rs:4`、`batch-poster/src/lib.rs:4` 引用的 `out/rollup-batch-submitter-survey.md` 已随 `cba99b68` 入库，悬空引用应已失效；核对引用章节号仍准确即可关闭。

> 完成纪要：`git ls-files out/rollup-batch-submitter-survey.md` 确认已入库；§9.1（独立 crate）/§9.2（prove_log 升级状态表）/§9.3（交易管理层不要裸写）/§9.6（cadence）/§9.7（监控最小集）/§9.8（逃生机制）引用逐一对照原文核验成立，§9 下无 ### 子节——引用全部准确，零修改关闭。

### 10. 更远期（方案 risks 声明的范围）— 未开始（出范围，保持原样）
- 真实链上提交全链路（当前为骨架+状态机+单测级别）。
- escape hatch / 强制操作机制（若走向 appchain/settlement 服务化，参照 StarkEx「用户强制操作 → 冻结 → Merkle escape」模板，见 survey §1.4）。
- GPU 加速（todo.md 既有第 1 项，与批量上链并行推进）。

### 11. M1 仓务收口附加项（2026-10-01，排期文档 M1-5 执行中发现并处置）

- **发现**：poker_contracts 于 HEAD 93eda3af 在**任何工具链下均不可编译**（被「snforge 除外」门控排除长期遮蔽）：
  - scarb 2.11.4（机内现行版）：依赖解析即失败（registry 无法满足 `starknet ^2.19.4`），且 snforge 0.63.0 硬门限 scarb ≥2.13.1——回归根本无法启动；
  - scarb 2.13.1（snforge 最低门限）：合约源编译 3 error——SNIP-36 预埋消费路径引用的 `get_execution_info_v3_syscall` / `TxInfo.proof_facts` 在 2.12–2.14 corelib 中不存在（Scarb.toml 原「≥2.12 可用」注释有误，2026-10-01 逐版本探测 corelib 修正：**两 API 实测 cairo ≥2.15 才可用**）；
  - scarb 2.15.0：仅余 `starknet::TxInfo`（=v2 再导出，无 proof_facts）与 v3 syscall 返回类型的错配（corelib `info` 模块私有，v3::TxInfo 无公开路径）。
- **修复（最小、零行为变化）**：`poker_dual_settlement.cairo` 删除 `let tx_info: TxInfo` 的类型标注改推断落 v3（连带删除该导入）；`Scarb.toml` 头注更正为「≥2.15 + snforge 门限 ≥2.13.1 → 工具链取 scarb 2.15.0+」。
- **回归结果**：snforge 全量（scarb 2.15.0）**130 passed / 0 failed / 0 ignored**，含 SEPOLIA_LATEST fork 实测（publicnode，block 15925488）。
- **遗留提示**：机内 scarb 仍为 2.11.4（本仓合约工作需 PATH 指向 scarb ≥2.15.0 或升级 `~/.local/bin/scarb`）；此 .cairo 改动建议 M5 审计窗口一并复核（纯类型标注删除，不改变 sierra 语义面以外任何逻辑——sierra 由 2.15 编译器重新生成，后续 Rust 侧 artifact 消费者如钉扎 casm 哈希需同步重钉）。
