# STARK 递归结算引擎工程报告（v2，经独立复审修正）

日期：2026-09-29 ｜ 分支：`feat/prove_perf`（poker_texas_air）/ `feat/monad`（zchain）
范围：poker_l1 DAG vertex 存储缺陷修复 · STARK 递归聚合终证主链（禁 Groth16）· stark 服务器资源/磁盘隔离 · Monad(10143) E2E 批量结算演练

**版本锚点（复审时实查，`git status`/`git log`/`git show --stat`）**
- poker_texas_air：递归交付物已全部提交于 **bc69a8b2**「feat:stark recursion」（2026-09-29 13:49:30）——`stark-recursion/`（含 stark_final.rs、onchain.rs、chain.rs、budget.rs、groth16-baseline feature 的 Cargo.toml）、`proving-tool/`（含 settlement_batch_private.cairo、prove-batch.sh、params/）、`fact-verify/src/lib.rs`、`scripts/check_stark_recursion.sh`、Keccak channel 本地补丁 3 文件（`git ls-files` 确认 `third_party/proving/crates/{common/src/prover_params.rs, prover/src/prover.rs, cairo-serialize/src/serialize.rs}` 在库且属于 bc69a8b2）、`out/resource-isolation/`。工作树遗留：`scripts/check_final_batch_settlement.sh` **+29/−17 未提交**（bc69a8b2 已含其 228 行版本；未提交 delta 为演练后账单口径等细化），`out/` 本报告与证据副本 untracked。
- zchain：**工作树已 clean**——存储修复与合约交付已提交于 **6bc7cb1**「stark recursion」（2026-09-29 13:50:14），文件清单见 §2.3（初版报告「未提交」的披露已过时，此处更正）。

## 0. 证据口径

- 报告主体由工作流各步骤实跑记录汇编；各门禁命令与退出码出自对应步骤原样执行记录。
- 撰写人本轮（v2 复审）独立实查项：
  1. **K=64 复测**（裁决两轮口径矛盾）：`cd proving-tool && /usr/bin/time -l ./prove-batch.sh 64 /tmp/batch-e2e/L0_inputs.json /tmp/k64-rerun 0x0` → **exit 0**，`[OK] 电路↔宿主逐字一致`；steps=**602,199**（`run_b/summary.json`，与演练台账一致）；keccak_root `0xebf03899…` 与 batch_fact `0x06af1065…` 与演练 `batch_k64/manifest.json` **逐字节一致**（同输入确定性复现）；峰值 RSS **3,702,898,688B ≈ 3.45GiB**；全 log 留档 `out/k64-rerun.log`。
  2. **源码实读**：`stark-recursion/src/chain.rs:36-60`（K 政策常数）、`:294-331`（聚合腿公式与 acc 链）；`stark-recursion/src/stark_final.rs:14-30,84-110,280-310,420`（电路镜像/两公式分离）；`proving-tool/src/settlement_batch_private.cairo:21,231-248`（电路内公式）；`zchain/contracts/monad/src/StarkVerifier.sol` **全文 128 行**（revert 语句实读在 **:113**，非材料所记 :110；`onlyAuthority` 在 :102）；`zchain/poker_l1/src/node/mod.rs:2100-2115`（`get_by_round` 唯一生产调用点）；`poker_l1/src/storage/dag_vertex_store.rs:361,192-212,253-352,440-460,491-503,532-609`（行号抽查于初版已做）。
  3. **金向量出处**：`third_party/proving/crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root.proof`——**vendored 上游递归树 crate 自带的测试金向量（four_leaves）**，随 vendored 导入入库（初版未写出处，此处补）。
  4. **查询顺序调用方审计**：全仓 `grep -rn get_by_author|get_by_round poker_l1/src` → 生产调用点仅 1 处（`node/mod.rs:2107`，equivocation 检查：同 (epoch,round) 内按 author 比对内容哈希，成员语义、与顺序无关）；其余 2 处均为 vertex_pruner 测试。
  5. **易失证据落盘**：`out/monad-final-batch.json`、`out/poker_l1_gate_final.log`、`out/k64-rerun.log`、`out/e2e-artifacts/k64-{drill,rerun}-manifest.json`（均从 /tmp 拷贝，建议随下次 commit 入库）。
  6. 算术复核（python3，见各节）：边际 steps、K_max 外推、占比、gas 换算、配额占比、5200M 推导差额。
- 未由撰写人执行/无法执行项，正文如实标注「未测/未记录/不可核验」；复审逐项处置对照见附录 A。

---

## 1. 结论先行

| # | 里程碑 | 状态 | 核心证据（详见对应章节） |
|---|--------|------|--------------------------|
| 1 | 存储缺陷修复（poker_l1 DAG vertex 索引/裁剪） | 完成 | `cargo test -p poker_l1` GATE_EXIT=0，20 个 test target 全绿（lib 1940 passed）；已提交 6bc7cb1；变更控制见 §2.3 |
| 2 | 递归方案盘点 | 完成 | vendored stwo-cairo 2.4.0 已含 SHARP 式全套递归栈；**上游自带金向量**（four_leaves root.proof）喂 Cairo 电路验证器 exit=0（5,311,944 steps）；电路递归层实测超内存线（叶 19.4G/折叠 7.4G）→ 不进主链 |
| 3 | 递归聚合实现（终证主链） | 完成（链下出证/验证腿） | 批程序 K=1/4/8/32/64 链下出证与验证 verify OK；K=64 本轮复现（steps 602,199、根/batch_fact 逐字节复现）；Groth16 移出终证路径；双门禁 exit 0。**链上结算腿未验证**（FRI 核心二期，见里程碑 5） |
| 4 | 服务器资源与磁盘隔离 | 完成 | `check_resource_isolation.sh` 对 stark 真跑 exit=0（7 组断言）；texas.service 服务面 active/NRestarts=0、内存面无扰动证据；**CPU 争抢维度未测**（§4.4） |
| 5 | E2E 批量测试（终证路径） | 完成（**fail-closed 演练口径**） | 链下全跳 + 部署/锚定/负例/fail-closed + 终检 13 组断言 EXIT=0；**status=0x1 + FinalSettled 未成立**（链上从未成功验证过任何证明，按合约当前交付态不可成立） |

**里程碑 3/5 的验收口径（复审后明示）**：① 计划内可成立的门禁全部以退出码实证（跳 0-3、跳 5 的部署/锚定/负例/fail-closed、跳 6、终检脚本）；② 唯一不可成立项——链上 FinalSettled——按合约骨架期设计（`StarkVerifier.sol:113` 对**包括 authority 在内的一切提交** revert）物理不可成立，以全量真证 eth_call revert + 两笔真实负例 revert + 零状态变更实证 fail-closed 语义。即：**完成的是 fail-closed 演练，不是链上结算**；「链上验证过证明」这一事件在本期发生次数为 0。

三句话总结：

1. **主链（链下部分）已通**：终证 = 单个 STARK 批证明（`settlement_batch_private.cairo`，K≤64 手共享一次出证），电路内累加链 `batch_fact = poseidon([acc_prev, root_hi, root_lo, k] ++ 16k 手段)`（源码实读口径，§3.5.1）；K=64 steps=602,199 复现，同输入峰值 RSS 三轮实测 2.70–3.69GiB 包络；Groth16 已全部移出终证路径。
2. **唯一关键缺件**：链上 FRI 验证核心（骨架期一律 revert，fail-closed 已实证）；批证明 wire 1,023,373B 按纯 calldata 地板价（×16 gas/B）≈16.37M gas ≈1.67 ETH/批——这是**地板价估算而非真实链上估值**（节点拒绝 revert 调用估价），FRI 验证自身计算 gas 未计入，「交付后成本同量级」为推断非实测。
3. **生产面**：内存与服务零扰动证据在案（texas.service MemoryCurrent 读数 + active + NRestarts=0）；CPU 争抢维度未测，自设的「texas 受扰则降 CPUQuota」触发条件从未被执行过（§4.4）。

---

## 2. 存储修复（poker_l1 DAG vertex store）

### 2.1 缺陷与修复

**②③已修复并过门禁；①（vertex 内嵌 tx_list ≤256KB）只做设计记录未实现**——记录于 `poker_l1/docs/vertex-pruning.md` §1「一期明确不做」（二期参照 Sui blob/Narwhal batch-vertex 分层把 tx_list 换成 `(blob_id, tx_count, tx_merkle_root)` 承诺）。**裁定出处披露：执行步骤记「按 ask 裁定」，但裁定文本/编号未在在手材料中给引据，本报告无法给出可核验的裁定出处**（列 §6 遗留）。

**缺陷③（索引重写放大）→ 索引 v2 前缀序 key，`put()` 纯追加**
- author_index 行 key = `author_to_bytes() || epoch_le(8) || round_le(8) || vertex_hash(32)`（value 恒空）；round_index 行 key = `epoch_le || round_le || hash`（`dag_vertex_store.rs:192-212`）。
- `put()` 一次 WriteBatch 写 vertices + 2 索引行，无任何既有 key 读-改-写（`dag_vertex_store.rs:361` 起，撰写人实读入口确认）；出处注释标注 Solana blockstore 复合序 key 设计（`dag_vertex_store.rs:19-45`）。
- 查询语义：`get_by_author`/`get_by_round` 仍取回全部 vertex，顺序从插入序变为确定的 (epoch,round,hash) 字典序（集合不变）。**调用方影响已审计（复审实查）**：生产代码调用点仅 1 处——`node/mod.rs:2107` 的 equivocation 检查（遍历同 (epoch,round) vertex，按 author 比对内容哈希，成员语义、顺序无关，实读 :2100-2115 确认）；另 2 处为 vertex_pruner 测试。**未发现依赖旧插入序的调用方**；此审计仅覆盖 poker_l1/src 当前代码，外部消费方（若有）不在审计范围。
- 旧格式兼容：`open()` 时 `ensure_index_v2` 自动迁移（旧条目可无歧义识别，每条旧目一个原子 WriteBatch 先写 v2 行同批删旧，崩后幂等续跑，悬挂引用跳过+warn，`dag_vertex_store.rs:253-352`）。

**缺陷②（只进不出）→ VertexPruner runner 接线**
- 新增 `poker_l1/src/storage/vertex_pruner.rs`：`VertexFinalitySource` trait；`VertexPruner::run_tick` 计算 `watermark_height = finality_height − vertex_prune_after_blocks`，解析该高度区块 DagCommitCertificate 得 (epoch, round) 边界，调 `store.prune_vertices_below` 限速删除（run_tick 在 `vertex_pruner.rs:109-166`）。
- 删除路径（`dag_vertex_store.rs:532-609`）：候选 round 按 (epoch,round) 数值升序（BTreeSet，最旧优先，Aptos pruner 口径）；每 round 一个原子 WriteBatch——先 `prune_vertex()` 转 PrunedVertex 承诺写入 pruned_vertices CF，再 vertices 点删 + round_index 行删 + author_index `delete_range`（Solana PruneBySlot 范围删除口径），watermark 推进与删除同批落盘；round 粒度 all-or-nothing；删后可选 manual compaction（默认 false）。

**节点接线**（`poker_l1/src/node/mod.rs`）
- `NodeConfig.pruning: PruningConfig`（`#[serde(default)]`，node/mod.rs:176-178）；`run_pruning` 调 `run_vertex_pruning_with`（node/mod.rs:2406-2432）；接线点在出块路径 block put 之后（node/mod.rs:2295-2299，失败仅 warn 不阻断出块）。
- 开关：`vertex_prune_enabled`（默认 true）、`vertex_prune_max_batch_vertices`（默认 512，0=暂停）、`vertex_prune_compaction`（默认 false）；`pruning.rs:122-172`（默认窗口 10000 不变，`pruning.rs:51`）。角色门控：仅 Full/Validator 执行，**Archive 永不裁剪**；watermark 持久化于 vertex_meta CF（`dag_vertex_store.rs:491-503`+`594-598`），与删除同批原子。

**finality 语义（复审修正——初版「保守上界」方向性有误）**
- `NodeVertexFinalitySource` 以 BlockStore tip 为 finality 代理。**方向性如实陈述：watermark = finality − 窗口，finality 估值偏高 ⇒ watermark 偏高 ⇒ 裁得更多——在裁剪安全维度上这是不保守的方向**。该实现的安全前提是一个未论证的假设：「入库 block 必带 2/3 cert ⇒ tip 高度即不可回退」。若该等价性不成立（发生 reorg 且回退点深于窗口量级，或 cert 不构成不可逆承诺），已裁 vertex 可能仍被需要；此时数据侧残留 PrunedVertex 承诺（设计上可重建），但**重放/恢复路径未设计**（`indexer/mod.rs:438` 的 reorg 幂等重放注释只覆盖 indexer 索引，不覆盖 vertex 重放）。10000 默认窗口是为吸收 tip 与真实 finality 差值的设计意图，非证明。列 §6 遗留。

### 2.2 同类链参考（设计出处映射，全文见 `poker_l1/docs/vertex-pruning.md`）

| 本实现 | 参考链口径 |
|--------|-----------|
| 复合序前缀 key（author‖epoch‖round‖hash） | Solana blockstore 复合序 key 设计 |
| author_index 按 round 前缀 `delete_range` | Solana PruneBySlot 范围删除 |
| watermark + 限速删除、最旧 round 优先 | Aptos pruner watermark+限速 |
| epoch/round 边界解析 | Sui Mysticeti epoch 级 DAG 裁剪 |

文档另含：key 格式表、配置项表、扩盘后恢复参数建议、故障排查表。该文档已随 6bc7cb1 提交（不再是工作树易失物）。

### 2.3 变更控制与提交状态（复审实查更正）

初版口径「仅 3 个 storage 目标文件」**只覆盖 src/storage/ 生产代码面**，不完整。复审实查（`git -C zchain status`（clean）/ `git show --stat 6bc7cb1`）：

- 完整 poker_l1 变更面（6bc7cb1 内，`git show --stat 6bc7cb1 | grep poker_l1`）：
  - 生产：`src/storage/dag_vertex_store.rs`（855 行级变更）、`src/storage/mod.rs`（19）、`src/storage/pruning.rs`（45）、`src/node/mod.rs`（171）
  - 新增：`src/storage/vertex_pruner.rs`（391）
  - 测试 fixture：`tests/live_game_e2e.rs`（6）、`tests/phase6_integration.rs`（13）
  - 文档：`docs/vertex-pruning.md`（203）
- 该提交为**混合提交**（同 commit 还含 `contracts/monad/` 递归交付物：StarkVerifier.sol、StarkVerifierGolden.t.sol、SettleBatch.sol、Groth16 对照栈等），commit message「stark recursion」未区分存储修复与递归交付，fixture 改动亦未在 commit message 中披露——披露依赖本报告 §2.4 与 docs §6.1。
- `consensus/` 零改动、其他 CF（block_store/object_db/object_db_snapshot/bridge_registry_store/object_backend）零改动：执行步骤当时以 `git diff --quiet` 逐文件核验（记录在案），且 6bc7cb1 的 stat 中无这些文件，口径保持成立。
- 门禁：`cd /Users/mac/projects/zchain && cargo test -p poker_l1` → GATE_EXIT=0（20 个 test target 全绿：lib 1940 passed/32.71s；集成目标 243/73/49/31/26/26/25/25/22/16/12/12/5/1/1/1/0/0 passed；1 个 target 5 ignored 属既有 live-gate），定向回归 34 项同日志确认。原始日志副本：`out/poker_l1_gate_final.log`。
- 未运行：服务器侧（ssh stark）部署验证。

### 2.4 披露

1. **附带 fixture 修复——根因归因为执行步骤的判断，非已证事实**：`cargo test -p poker_l1` 在修复前即有 2 个集成目标红（git stash 后干净工作树复现确认——**这只证明「先在性」，即红与本修复无关，不能证明根因是「fixture 未跟上共识校验收紧」而非生产回归**）。把期望改到测试侧（live_game_e2e.rs 2 处 cert epoch 0→1、phase6_integration.rs cert 补 epoch:1 + 2 个 vertex epoch 0→1（标注 SEC-C1 epoch 绑定）、43_7_a/b dummy_tx→signed_dummy_tx()）使门禁变绿，「期望应该改而非生产行为错了」这一方向未做独立评审。列 §6 遗留（需独立评审确认 epoch=1/验签口径是生产正确语义）。
2. **runner 形态与 ask 措辞差异**：ask 写「后台任务」；Node 无后台线程基础设施（node/mod.rs 无 thread::spawn），runner 接在出块路径每 block 一个限速 tick，并暴露 `run_vertex_pruning_with(source)` 供外部调度器。
3. **裁剪吞吐与积压：无任何实测数字**。vertex 存量、历史积压规模、每 tick 删除量与耗时、追平所需时间、单 tick 对出块延迟的影响——全部未测。「默认 512/tick 自然追平」「回填期 vertex_prune_enabled=false」是运维建议性断言，**不是证据**。列 §6 遗留。

---

## 3. 递归架构与实现

### 3.1 盘点结论（递归方案盘点步骤）

vendored stwo-cairo 2.4.0 已含 SHARP 式全套递归栈（`third_party/proving`）：leaf_prover（`crates/leaf_prover/src/prove_leaf.rs:64-247`）、`stwo_run_and_prove_recursive_tree`（N 叶二进制内两两折叠成单根，`src/lib.rs:1-28,93-123`；fold.rs:91-187）、multiverifier + canonical_small 注册表（min=max trace 2^20），target/release 有预编译二进制。

**L4 验证腿单跳实证——金向量出处（复审补）**：被验对象是 **vendored 上游 crate 自带测试金向量** `crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root.proof`（4 叶递归树证明，随 vendored 导入入库；`git ls-files` 确认）。scarb 2.19.4 `--profile proving execute -p stwo_circuit_verifier --features qm31_opcode` → exit=0，5,311,944 VM steps / range_check 512,647 / output 8。即：验证腿跑通的是**上游测试数据**，不是本产品批次证明的终证——它证明电路验证器工件可执行、可验递归树证明，不构成产品证明链的端到端证据。

### 3.2 上链路线裁决（按用户裁定，Groth16 全出局）

- **主链（稳定上线，本期交付链下部分）**：K≤64 手 → `settlement_batch_private` 单跑单证（一个 cairo-air STARK 批证明）→ 电路内累加链：`batch_fact = poseidon([acc_prev, root_hi, root_lo, k] ++ K×16 手段)`，其中 root_hi/lo = keccak 批根（`groth16_wrap::batch::keccak_batch_root`，与 zchain SettleBatch.sol 逐式一致）拆分，acc_prev/批根作为批程序公开入参 → 提交 Monad STARK 验证合约。**累加链头 = 电路内 batch_fact**（裁决依据见 §3.5.1）。
- **压缩层（二期）**：N 个批证明 → leaf-prover → 递归树 → stwo_circuit_verifier 终证（常数尺寸）→ 同一合约验一次。
- 路线排除依据与初版一致（Stone 零依赖、通用 EVM verifier 数人月排除、Cairo 链式递归外推爆炸不进主链）；固定参数化 verifier 先例（Permissionless Technologies ~1900 行/~20M gas）**开源与审计状态仍未核实**。

### 3.3 与 SHARP 概念对照

| SHARP 概念 | 本栈对应 | 状态 |
|-----------|---------|------|
| task pie → 单证明 | 批程序 `settlement_batch_private` 单跑单证（L1 批证明腿） | 主链已交付（链下） |
| proof aggregation（递归树） | `stwo_run_and_prove_recursive_tree` N 叶折叠成单根 | 代码在盘；prove 腿二期（内存超限） |
| recursive verifier（Cairo 内验证明） | `stwo_circuit_verifier` 可执行工件 | **上游金向量单跳实证**（exit=0，5.31M steps）；产品链端到端未验 |
| 上链「验证一次、承诺复用」 | Monad `StarkVerifier.sol` 固定参数验证合约 | 骨架期 fail-closed，FRI 核心二期 |

### 3.4 内存/耗时实测（≤6G 如实结论）

电路递归层实测超限，稳定上线不走该层（`stark-recursion/src/budget.rs:23-30` 实测锚点常量，撰写人实读）：

| 层 | 实测峰值 | 来源 |
|----|---------|------|
| 叶证明腿（leaf-prover） | **19.4GB**（20,819,279,872B） | budget.rs:24 引 /usr/bin/time 实测 |
| 折叠腿（recursive tree） | **7.4GB**（7,909,834,752B） | budget.rs:26 引 test_fold_two_leaves 实测 |
| 叶+折叠同进程 | 20.4GB（21,931,687,936B）——同进程形态被此数否决 | budget.rs:28-30 |
| circuit-params（仅建拓扑） | 3.2GB 峰值 RSS | 盘点步骤实测 |
| 叶电路 qm31_ops 自然量 | 材料记录为「~2^22.3（77% of 2^23）」——**两数算术矛盾**（复审核）：2^22.3=5,163,794=2^23 的 61.6%；77% 对应 2^22.62。自然量在 2^22.3–2^22.62 之间，取保守读数 **2^22.62（77%）**；两种读数下结论一致：自然量已超 2^22，2^23 是下一个 2 的幂，即填充下限砍不动 | 盘点步骤实测 |
| L1 批证明（canonical_small，K=64 同输入三轮） | **2.70GiB / 3.45GiB / 3.69GiB**（2,900,845,248B 演练直测；3,702,898,688B 本轮复测；3.69GiB 为实现步骤早轮、**输入出处未记录**）——RSS run 间漂移 ~28%，steps 确定性不变（602,199 复现）。设计包络取最坏观测 **≤3.7GiB** | /usr/bin/time -l |
| L1 批证明小档 | K=1 1.87-1.94 GiB；K=8 2.13 / K=32 2.85 GiB（实现步骤）；K=8 本轮复测同输入见 §5.3 | /usr/bin/time -l |
| canonical（对照组，543M cells） | 9.55-12.9 GiB —— 超界弃用 | 实现步骤实测 |
| L4 终证执行腿 | 5.31M steps（≈2^23 行）exit=0（上游金向量）；prove 步内存 4-8GB **估算、未实测** | 盘点步骤 |

### 3.5 实现交付（递归聚合实现步骤，全部以实跑为据）

1. **`settlement_batch_private.cairo`**（主链终证程序）：`main(k, acc_prev, root_hi, root_lo, data)`；电路内 corelib HashState sponge（rate-2、耗尽补 1、末置换取 s0，与 groth16-wrap `poseidon_hash_many` 同构造，`settlement_batch_private.cairo:231-248` 注释与实现）计算
   **`batch_fact = poseidon([acc_prev, root_hi, root_lo, k] ++ K×16 手段)`**（:21、:231-233）。
   公开输出形状 `[len] ++ segments(16·K) ++ [acc_prev, root_hi, root_lo, batch_fact]`（`stark_final.rs:14`）。
   钉扎 program_hash `0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803`（K=1/4/8/32/64 + keccak 通道一致，参数无关；prove-batch.sh 内有钉扎校验）。
2. **累加链——权威公式（复审按源码裁定，两层级两公式）**：
   - **主链（链上累加链头，StarkVerifier 尾四字校验对拍基准）**：电路内 `batch_fact`，宿主镜像 `expected_batch_fact(acc_prev, root_hi, root_lo, k, segments)`（`stark_final.rs:84-97`，`poseidon_hash_many` 与 corelib HashState 构造等价由 groth16-wrap/src/poseidon.rs 随机对拍钉死）。链接规则：`acc_n = batch_fact_n`（acc_prev 已绑定进 preimage；`stark_final.rs:25-30`；`chain.rs:323-331` `acc_next`）。**裁决理由（源码注释原文，stark_final.rs:26-27）**：不取 final_fact 作链头，因 EVM 无 poseidon 预编译、链上重算不经济；真双批 E2E 实证归纳闭环。
   - **聚合腿（二期 root 电路语句层）**：`derive_batch_fact = poseidon_hash_many([aggregator_program_hash ‖ 根输出 8 felts ‖ acc_prev ‖ keccak根hi ‖ keccak根lo])`（`chain.rs:294-319` 实读；「根输出 8 felts」= 叶电路公开输出保留词 ROOT_OUTPUT_WORDS=8，**不是** keccak 批根——初版 §1/§3.2 把它误转述为「批根 8 felts」并与主链公式混写，此处更正）。
   - **final_fact 定义（初版未定义，复审补）**：`final_fact = poseidon([program_hash ‖ 全部公开输出])`（`stark_final.rs:106`）——fact-registry 口径的全输出哈希，与 batch_fact **两公式分离**，测试 `stark_final.rs:420` 以 `assert_ne!(acc_next_val, final_fact(...))` 钉死分离；FinalEnvelope 两者并载（:280-310）。
3. **stark-recursion 去 Groth16 化**：`stark_final.rs`（语句层 + `verify_final_output` 六重 fail-closed 闸门 + FinalEnvelope）；`onchain.rs` 增 `submitFinalProof` 提案 ABI 编码器 + 金字节测试；ark 系转 optional，旧 Groth16 路径收进 `groth16-baseline` feature。
4. **Keccak256 channel 本地补丁**：39 行插入，均带 LOCAL PATCH 注释（`prover_params.rs`/`prover.rs`/cairo-serialize `serialize.rs`）；已随 bc69a8b2 提交（`git ls-files` 实查）。K=1 keccak 通道出证/验证 OK（1.91s，2.06 GiB）。
5. **fact-verify 批程序钉扎**：`PINNED_BATCH_PROGRAM_HASH` + 第二套独立 poseidon 实现对拍；真实工件测试 5/5；三实现（电路 HashState ↔ groth16-wrap 复刻 ↔ starknet-crypto）交叉验证闭环。
6. **zchain `StarkVerifier.sol`（骨架，128 行，复审全文实读）**：`BATCH_PROGRAM_HASH` 常量（:44-45）；`latestFact`/`settledFact` 状态（:53-56）；`submitFinalProof` **`onlyAuthority whenNotPaused`（:102）** + 前置检查 accPrev==latestFact（:103）/根一次性（:104）/空 proof（:105）；FRI 核心交付位注释（:107-111）；**骨架期一律 `revert FRIVerifierNotDelivered()`（:113）**；状态写入代码仅以注释形式存在（:115-118，FRI 交付后启用）。forge 金向量测试 7/7，zchain 全套 35/35。
7. **双门禁**：`bash scripts/check_stark_recursion.sh` exit 0（29 lib + 2 final_k2）；`--baseline` exit 0（追加真 Groth16 出证 roundtrip 378s，对照基线）。工件落盘 `proving-tool/output/settlement-batch/`。

### 3.6 K 上限与安全余量——复审裁决（初版三套口径矛盾，此处统一）

**「195 手上限」的来源与证伪**：`chain.rs:39-46` 政策常数（撰写人实读）：`MAX_HANDS_PER_LEAF=64`、`TRACE_FLOOR_LOG2=20`、`MEASURED_STEPS_PER_HAND=5374`（注释引 proving-tool/output/settlement/summary.json:22，即**批程序 K=1 总 steps**）、`TRACE_HEADROOM_FACTOR=3`（注释：bootloader/H1/段开销的设计系数）。初版材料记「2^20 ÷ 5374 ÷ 3 = 195」——**算术不成立**：2^20/5374 = **195.12**（即 195 是**漏乘 ÷3** 的结果）；带 ÷3 应为 **65.0**。且 195×6,100 = 1,189,500 > 2^20=1,048,576，195 手连零余量都放不下（复审原文正确）。

**以实测阶梯重新推导（本轮口径）**：
- 批程序边际每手 steps（K=8→K=64 差分）：(602,199−75,503)/56 = **9,405.3 steps/手**；截距 ≈261 steps。三个「每手」数字并存且语义不同：5,374=K=1 批程序总量；6,100-6,109=单手程序（settlement_private）steps；9,405=批程序边际。规划常数用的是最小的 5,374，比实测边际低 43%。
- K=64 实测 602,199 steps = 2^20 的 **57.4%** → **steps 维度真实余量 1.74×，不是 3×**。
- 外推上限：K_max@2^20 = (1,048,576−261)/9,405.3 ≈ **111 手**；K=128 ≈ 1,204,000 steps > 2^20 超预算 → **K≤64 政策成立**（是 ≤111 内最大的 2 的幂），但「已留 3× 余量」的说法**错误**。
- 模型视角（解释为何政策仍算稳健）：按代码模型预算 = K×5,374×3，K=64 占模型预算 98.4%（模型内余 1.6%）；实测边际超模型 75%（9,405/5,374=1.75），被设计系数 3 吸收后净余 1.74×。即：**3× 是设计系数，1.74× 才是实测余量**；若未来单手 steps 上涨（如手段数变化），K=64 触顶先于 K=111 外推值，届时按 §5.3 门（≤5G、≤30min）+ steps 占比复测降档。
- 内存维度余量另算（见 §5.3/§5.7）：同输入三轮 2.70–3.69GiB，对 4600M 单元上限占 60–82%（余 18–40%）。

---

## 4. 服务器资源与磁盘隔离（stark，x86_64 4C/7.3G）

### 4.1 部署事实（本轮 = 复核+补验+门禁，栈为上一轮已部署）

- **cgroup 隔离**：`zchain-recursion.slice`（CPUQuota=300%、CPUWeight=60、MemoryMax=5200M、MemorySwapMax=0、IOWeight=60）；`monad-leaf@/monad-fold@`（Slice=同 slice、MemoryMax=4600M、SwapMax=0、CPUQuota=300%、Nice=5、RequiresMountsFor 防产物落根盘）。systemctl show + 内核双视角交叉核验：`cpu.max='300000 100000'`、`memory.max=5452595200`、`memory.swap.max=0`、`io.weight='default 60'`。
- **磁盘隔离**：6G 回环镜像 /dev/loop0 → /opt/zchain-monad/chain-data（ext4 rw,nosuid,nodev,noexec,relatime），fstab loop+nofail，用量 1%。
- **守卫**：磁盘守卫 90% 水位停递归单元、白名单绝无 texas、每 5 分钟 timer、journal 实跑证据在案。
- 探针残留（oom-kill 只杀笼内）为 caging 实证，保留为审计记录；迁移说明文档在服务器侧。

### 4.2 与架构师资源规格对账（按「只增不删」保留并如实报告差异）

| 项 | 规格值 | 部署值 | 差异说明 |
|----|--------|--------|---------|
| MemoryMax | 5G (5120M) | **5200M** | 相对规格 +80M(1.6%)。文件内推导「leaf/fold 各 4600M 串行 + 512M 编排」**算术和为 5112M，与部署值差 88M，材料未解释**（复审核：4600+512=5112≠5200）。安全账：7459M 总−5200M 笼顶−1029M texas ≈1230M 系统余量 |
| MemorySwapMax | 2G 缓冲 | **0** | ask 正文「压到最低防 swap 风暴」为更晚更具体指令；超顶即 cgroup OOM（探针实证只杀笼内） |
| CPUQuota | 「50%（4核让2核）」自相矛盾 | **300%**（=4 线程中 3 线程，cpu.max 实证） | systemd 官方语义（单核百分比）下字面 50%=半核；**实质偏差：prover 上限 3 核 vs 括号意图 2 核**。缓解：CPUWeight=60+Nice=5；「若 texas 受扰降 200%」为单行收紧预案——**该触发条件的实测从未执行（§4.4）** |
| MemoryHigh | 4G | 未设（memory.high=max） | SwapMax=0 下宁可 OOM-kill 重试不做节流长停 |
| CPUWeight/IOWeight | 40/50 | 60/60 | 均 <默认 100，相对让路 texas |
| 单元命名 | texas-prover-monad.service 单单元 | monad-leaf@/monad-fold@ 模板对 | 按负载分模板 + slice 兜底强制串行，满足 req1 意图 |

### 4.3 门禁（执行步骤：服务器隔离步骤）

`scripts/check_resource_isolation.sh`（6 节 7 组断言，含 systemd show 与内核 cgroup 交叉核验、守卫 dry-run、白名单纪律、盘余量）经 stub-ssh 本地全绿后于 12:40:32-45 对 stark 真跑：**exit=0，ALL PASSED**；root avail=11511MB≥3072MB。执行环境：本机出口对 SSH 协议间歇性 DPI 重置（github 同样复现，非服务器故障），以 banner 探针+连接复用在放行窗口完成；门禁脚本自身两个 bug（子 shell 退出逃逸 set -e、全角标点并入变量名）已修复留痕。留档 `out/resource-isolation/`。

### 4.4 生产影响——证据维度如实陈述（复审改写）

- **有证据的维度**：texas.service 服务面（active、NRestarts=0）与内存面（MemoryCurrent=1,078,358,016B 在 12:13 survey 首尾、12:20 detail、12:40 门禁首尾五次读数数值相同；guard journal 每 5 分钟记录 active——27 分钟窗口）。**采样方式材料未记录**（五次同值是独立采样巧合还是同一计数器原样回读，无法确认，如实标注）；E2E 轮另有 MemoryCurrent 1,078,358,016→1,077,538,816（-0.08%）。
- **无证据的维度**：**CPU 争抢从未被测**——无 texas CPU 占用、无出块延迟/出块间隔指标。在 prover 配额存在实质偏差（3 核 vs 括号意图 2 核）的前提下，「内存读数相同」不能证明 CPU 无争抢；自设的扰动判定条件「若 E2E 实测 texas 受扰，降 CPUQuota→200%」**实际从未被执行**。故「生产零扰动」仅对内存与服务存活维度成立，**CPU 维度未知**。列 §6 遗留（需在下次 prover 负载窗口采 texas CPU% 与出块延迟）。
- 本轮对服务器零写入（/root/.zmonad-tmp/ 一份未执行成功的模板副本为只增不删保留物）。

---

## 5. E2E 批量结果（终证路径，禁 Groth16）

链路：8 手真实牌局 → 逐手 STARK 出证 → K=8 批单证 → appchain 受理 → stark 隔离单元复证 → L1Inbox 上锚 → Monad StarkVerifier 部署 + fail-closed 实证。全量台账：`out/monad-final-batch.json`（已从 /tmp 落副本）。

### 5.1 跳线概览

| 跳 | 内容 | 结果 |
|----|------|------|
| 0 基线 | `cargo test -p stark-recursion` | 31 passed / 0 failed，exit 0 |
| 1 K=8 批终证 | 两阶段出证 | verified=true，steps=75,503，prove=3,945ms，verify=17ms；批公开段==8 手单证 public_output 前 16 felt 逐位相等（8/8）；电路内尾==宿主镜像逐字 |
| 2 链下验证 | fact-verify 钉扎 + fact 对拍 + 批根第三路径复算 | exit 0；cast keccak 独立复算==manifest 根==电路尾回显，三方一致 |
| 3 K 阶梯 | K=32/K=64 | 均 EXIT=0 电路↔宿主逐字一致；门（峰值≤5G 且 prove≤30min）全过；**K=64 本轮复现**（§5.3） |
| 4 压缩层 | leaf-prover→递归树→终证 | **未跑（二期/需大内存机）**；上游金向量验证器单跳先例（§3.1） |
| 5 Monad 10143 | 部署/锚定/终证提交/负例 | 部署+锚定 status=0x1；终证 fail-closed（§5.5）；两笔负例 revert 实证 |
| 6 回归 | `check_resource_isolation.sh` | exit 0（两次）；texas NRestarts==0 |

真实 8 手受理：explorer-gateway :18900 分页核对（journal total=3082），8/8 binding 命中 level=soft_accepted，frame 10778..10822（=throughOp 口径）。**披露（复审补）**：`soft_accepted` 的语义/等级定义未在材料中给出；且 8 手为上轮真实牌局重放（9-28 后无新局），同一批 binding 上轮已受理、本轮锚定 index=8 再次 8/8 soft_accepted——**同一手牌跨批重复结算的语义（appchain journal 是否按 binding 去重、结算层如何防同一手牌重复入账）未在材料中说明、本轮未验证**，按未审计风险列 §6。

### 5.2 逐手出证（8/8 verified=true；数据源 out/monad-final-batch.json batch.hands）

| idx | hand_id | steps | prove_ms | 峰值 RSS |
|-----|---------|-------|----------|---------|
| L0 | 1790634800 | 6100 | 2542 | 1.17 GiB |
| L1 | 1790634817 | 6109 | 1638 | 1.09 GiB |
| L2 | 1790634859 | 6109 | 1778 | 1.03 GiB |
| L3 | 1790634881 | 6109 | 2638 | 1.09 GiB |
| L4 | 1790634897 | 6100 | 2213 | 1.07 GiB |
| L5 | 1790634921 | 6100 | 2472 | 1.14 GiB |
| L6 | 1790634937 | 6109 | 2412 | 1.00 GiB |
| L7 | 1790634961 | 6109 | 1574 | 1.10 GiB |

### 5.3 批量阶梯：内存/耗时表（含复审复测）

| K | steps | prove | 峰值 RSS（实测） | 手来源 | 备注 |
|---|-------|-------|-----------------|--------|------|
| 8 | 75,503 | 3.9s | 1,656,870,400B ≈ 1.54 GiB（本地）；隔离单元 1,523,499,008B ≈ 1.42 GiB（cap 4,600M 的 31.6%） | 8 手真实牌局 | 演练台账 |
| 32 | 301,207 | 3.0s | 1,913,658,048B ≈ 1.78 GiB | 合成（自 L0 基底派生） | prove-batch.sh EXIT=0 |
| 64 | **602,199** | 4.1s | 2,900,845,248B ≈ 2.70 GiB | 合成（同上） | 演练台账 |
| **64（本轮复测，2026-09-29 14:25）** | **602,199（复现）** | 12.74s wall（含 batch-inputs 构建，不可与直跑直比） | **3,702,898,688B ≈ 3.45 GiB** | **与演练同输入**：keccak_root `0xebf03899…`、batch_fact `0x06af1065…` 与演练 manifest 逐字节一致 | 撰写人实跑，`out/k64-rerun.log` |

**两轮口径裁决（复审）**：Cairo VM steps 由程序+输入决定——本轮以同 base（/tmp/batch-e2e/L0_inputs.json）、acc=0x0 复测，根与 batch_fact 逐字节复现、steps 精确复现 602,199 ⇒ **steps=602,199 为可复现权威值**。实现步骤早轮的 555,223 steps / 3.69 GiB 一轮**输入出处未记录**（材料未写），steps 差 8.5% ⇒ 该轮输入与演练不同源，**降级为不可复现参考值**。RSS 则相反：steps 确定、RSS 漂移——同输入三轮 2.70/3.45/（未知输入）3.69GiB，**权威口径=steps 取 602,199、RSS 包络取最坏观测 ≤3.7GiB**，容量论证一律按包络值而非单点。

### 5.4 链上 gas/账单表（Monad testnet 10143，gasPrice=102 gwei 节点价）

| 笔 | 方法 | est | limit(=est×1.1+1) | gasUsed | status | 费用 | 块高/tx |
|----|------|-----|-------------------|---------|--------|------|---------|
| StarkVerifier 部署 | deploy | 535,304 | 588,835 | 588,835 | 0x1 | 0.06006117 ETH | 66,604,547 / 0x5265…48dec |
| L1Inbox 锚定 | submitBatch(8, root, 10822) | 81,990 | 90,190 | 90,190 | 0x1 | 0.00919938 ETH | 66,604,741 / 0x85f7…40e01 |
| 负例① 篡改 acc | submitFinalProof accPrev=1≠latestFact=0 | 39,311（forge 金向量 revert gas 为基） | 43,243 | 43,243 | 0x0（AccChainMismatch 0x01a8a2af） | 0.00441079 ETH | 66,605,262 / 0x3638…44c6a |
| 负例② 伪证 | 全真头 + 32B 假 proof | 51,885（同上口径） | 57,074 | 57,074 | 0x0（FRIVerifierNotDelivered 0xc575cb47） | 0.00582155 ETH | 66,605,269 / 0xbdde…f68ee9 |

- 四笔 Σ=0.079492884 ETH；负例两笔隔离窗口余额差 == Σ(limit×price) 逐 wei。计费口径：Monad 实测按 gas_limit×price 计费（四笔 gasUsed==gasLimit）；外部入账使全窗口余额差口径失效，账单门禁改三重口径（已 PASS）。
- **16.4M gas / 1.7 ETH 的推导（复审补）**：批证明 wire 1,023,373B × **16 gas/B（EVM calldata 非零字节地板价）= 16,373,968 gas ≈ 16.37M**；× 102 gwei = **1.6701 ETH ≈ 1.7 ETH**。**口径限定**：这是纯 calldata 地板价估算——节点对 revert 调用拒绝 eth_estimateGas（error 3），无真实链上估值；FRI 验证自身的计算 gas 未计入。故「FRI 核心交付后链上验证成本同量级」是**推断，不是实测**。
- 部署读回：BATCH_PROGRAM_HASH==钉扎值、l1Inbox/authority 一致、latestFact=0；锚定事件 topic1=0x8、data=root‖10822 逐字段一致，batchCount==9。forge StarkVerifierGolden 7/7。

### 5.5 fail-closed 实证与 FRI 缺位期信任模型（复审展开）

- `submitFinalProof`（selector 0xe8faf285）带 1,023,373B 真实全量 proof wire eth_call → **reverted 0xc575cb47 FRIVerifierNotDelivered**（revert 语句实读 **`StarkVerifier.sol:113`**）；真实 tx 未广播：节点拒绝为 revert 调用估价（error 3）且 ~16.37M gas×102gwei≈1.67ETH > 当时余额 0.337ETH。两笔负例后 `latestFact`/`settledFact(root)` 均==0（**零状态变更**）。
- **FRI 缺位期的链上信任模型（按合约源码实读）**：
  - `submitFinalProof` 带 `onlyAuthority whenNotPaused`（:102）——permissioned，仅 authority 可提交（与 L1Inbox/SettleBatch 同口径，合约注释 :36）。
  - **骨架期任何人（含 authority）都无法推进 latestFact**：函数体在三序前置检查后无条件 revert（:113），状态写入只存在于注释（:115-118）。即链上结算在 FRI 交付前**完全停摆**，latestFact 恒 0——不存在「authority 单方面推进」的通道。
  - 「链下过渡期把关」的实际含义（合约注释 :29-35 自认）：由 operator 运行链下 fact-verify（stwo verify_cairo + 程序哈希钉扎），**operator 背书口径与 SettleBatch.sol 相同**——fact-verify 结果不与链上状态绑定（链上无状态可绑），消费方对账靠 L1Inbox `BatchAnchored` 锚 + settledFact(keccakRoot)（恒 0）与 inbox 锚的一致性核对。**过渡期的安全边界 = operator 诚信 + 链下审计，无密码学强制**——这是合约注释明确自认的临时口径，非本报告推断。

### 5.6 终检与产出

`scripts/check_final_batch_settlement.sh` 已按禁 Groth16 路径重写（原 Groth16 版备份 /tmp/groth16-baseline-backup/；该脚本 bc69a8b2 已含 228 行版本，工作树另有 +29/−17 未提交细化），`bash scripts/check_final_batch_settlement.sh` → **CHECKER_EXIT=0，13 组断言全过**。

### 5.7 未跑/不可成立项（如实）

1. FinalSettled status=0x1：本期不可成立（FRI 核心二期；链上验证证明的次数为 0）。
2. 压缩层（跳 4 全流程）：需大内存机，未跑。
3. **K=64 在 stark 笼内从未实测**：笼内仅 K=8（1.42GiB=4600M 的 31.6%）。按包络 3.69GiB 对 4600M 单元上限占 **82.1%（余 17.9%）**、对 5200M slice 占 72.7%（余 27.3%）；若取 2.70GiB 则余 39.9%——**容量口径按 §5.3 包络（余 17.9–40% 区间），初版「已在 7.3G 内」以宿主机总量说事、未对齐笼上限，已废弃**。上线前须笼内实测 K=64。
4. 8 手为上轮重放，跨批重复结算语义未验证（§5.1）。
5. poker_l1 存储诊断三项不在 E2E 轮范围，未改动。

---

## 6. 稳定上线遗留清单

| # | 遗留项 | 性质/前提 |
|---|--------|----------|
| 1 | **StarkVerifier FRI 验证核心**（`_verifyStarkProof`：FRI/OOD/PoW + output 还原 + keccak==outputCommit + 尾四字校验） | 唯一关键路径缺件，数人月级；最小 FRI PoC → canonical_small 固定形状全量 |
| 2 | 压缩层=链上成本必选项（wire 地板价 ≈16.37M gas/批；**真实链上验证 gas 未实测**，FRI 计算 gas 未计） | 二期；需大内存机或 Linux 峰值复测；FRI 交付后逐笔 estimateGas 实测 + 单批费用上限门 |
| 3 | **CPU 争抢实测**（§4.4）：prover 负载窗口采 texas CPU% 与出块延迟，决定 CPUQuota 300%→200% 是否收紧 | 自设触发条件从未执行 |
| 4 | **K=64 笼内实测**（§5.7.3）+ texas MemoryCurrent 漂移<10% 探针门禁 | 上线前必做 |
| 5 | fixture 期望变更独立评审（§2.4.1）：确认 epoch=1/现行验签是生产正确语义 | 「先在性已证，归因未证」 |
| 6 | 裁剪吞吐/积压实测（§2.4.3）：vertex 存量、每 tick 删除量与耗时、追平时间、出块延迟影响 | 「自然追平」现为断言 |
| 7 | finality 语义加固（§2.1）：论证或替换「tip=不可回退」假设；设计 reorg 后 vertex 重放/恢复路径 | 不保守方向已识别 |
| 8 | 跨批重复结算语义（§5.1）：soft_accepted 定义、journal 按 binding 去重与否 | 未审计风险 |
| 9 | fact-verify `--aggregated` 聚合腿钉扎 | 需 scarb 2.18 + 终证工件；聚合腿公式已按 chain.rs:294-319 钉定口径 |
| 10 | 缺陷①（tx_list 内嵌）设计记录的**裁定引据补全**（§2.1） | 材料无出处 |
| 11 | Keccak channel 39 行本地 patch 的上游跟踪 | 已提交 bc69a8b2，需防上游同步丢失 |
| 12 | `submitFinalProof` 提案 ABI 字节级复核 + StarkVerifier 实部署时 authority/暂停权限的运维定义 | forge 金向量已钉 |
| 13 | 终证腿版本钉扎（scarb 2.19.4 跑通 pin 2.18；verifier 工件哈希+编译器版本钉进 fact-verify 与合约） | 防漂移 |
| 14 | Permissionless Technologies 参考实现开源/审计状态核实 | 如实标注 |
| 15 | 证据入库：`out/`（本报告、monad-final-batch.json、poker_l1_gate_final.log、k64-rerun.log、e2e-artifacts/）建议随下次 commit 提交 | /tmp 易失 |
| 16 | texas.service MemoryMin=1G 反向兜底（需运维确认）；/root/.zmonad-tmp 清理（维护窗）；SSH DPI 环境问题 | 运维项 |
| 17 | 单手 steps 若上涨（手段数变化等），K=64 触顶先于外推值——复测口径见 §3.6 | steps 占比纳入例行门禁 |

---

## 7. 复现命令

```bash
# —— 版本锚点 ——
git -C /Users/mac/projects/poker_texas_air log --oneline -1        # bc69a8b2 feat:stark recursion
git -C /Users/mac/projects/zchain log --oneline -1                 # 6bc7cb1 stark recursion

# —— 存储修复门禁（zchain）——
cd /Users/mac/projects/zchain && cargo test -p poker_l1            # GATE_EXIT=0，原始日志 out/poker_l1_gate_final.log

# —— 递归主链双门禁（poker_texas_air）——
cd /Users/mac/projects/poker_texas_air
bash scripts/check_stark_recursion.sh                              # exit 0
bash scripts/check_stark_recursion.sh --baseline                   # exit 0（真 Groth16 对照 roundtrip ~378s）

# —— K=64 批终证复测（复审已跑，exit 0，steps=602,199，out/k64-rerun.log）——
cd proving-tool && /usr/bin/time -l ./prove-batch.sh 64 /tmp/batch-e2e/L0_inputs.json /tmp/k64-rerun 0x0
#   钉扎 program_hash：0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803
#   阶梯：同式换 K ∈ {8,32}；RSS 门 ≤5G、prove ≤30min

# —— 链下验证（钉扎 + 第二套 poseidon 对拍）——
# fact-verify <proof.json> --expect-program-hash 0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803

# —— 服务器隔离门禁 ——
bash scripts/check_resource_isolation.sh                           # 7 组断言，exit=0

# —— E2E 终证路径终检 ——
bash scripts/check_final_batch_settlement.sh                       # CHECKER_EXIT=0（13 组断言）

# —— zchain 合约金向量 ——
cd /Users/mac/projects/zchain && forge test --match-contract StarkVerifierGolden   # 7/7

# —— 压缩层验证腿单跳（上游金向量；二期/大内存机前提）——
# scarb 2.19.4 --profile proving execute -p stwo_circuit_verifier --features qm31_opcode
#   向量：third_party/proving/crates/stwo_run_and_prove_recursive_tree/test_data/goldens/four_leaves/root.proof
#   exit=0，5,311,944 steps
```

**审计留档**（`out/`，建议随 commit 入库）：`stark-recursion-engineering-report.md`（本报告）、`monad-final-batch.json`（E2E 台账副本）、`poker_l1_gate_final.log`（门禁原始日志副本）、`k64-rerun.log`（K=64 复测全 log）、`e2e-artifacts/k64-{drill,rerun}-manifest.json`、`resource-isolation/`（服务器门禁留档）、`proving-tool/output/settlement-batch/`（证明工件与内存实测表）。

---

## 附录 A：独立复审 21 项处置对照

| # | 复审意见 | 处置 |
|---|---------|------|
| 1 | K 上限三口径矛盾、195 算不出 | 已裁决（§3.6）：195=2^20/5374 漏乘 ÷3（带 ÷3 为 65）；实测边际 9,405.3 steps/手；K=64 余量 **1.74×**（非 3×）；K_max≈111，K≤64 政策成立、「3× 余量」说法废弃 |
| 2 | 两轮 K=64 差异未解释、口径混用 | 已裁决（§5.3）：同输入复测 steps=602,199 精确复现、根/batch_fact 逐字节一致 ⇒ steps 权威；3.69GiB 轮输入出处未记录，降级参考；RSS 包络 ≤3.7GiB，全文统一按包络 |
| 3 | 累加链公式两处不一致 | 已按源码统一（§3.5.2）：主链=电路内 `poseidon([acc_prev,root_hi,root_lo,k]++16k 段)`；聚合腿=chain.rs:294-319（aph‖根输出 8felts‖acc‖hi‖lo）；初版「批根 8 felts」系误转述已更正；权威版本=源码 |
| 4 | 零扰动缺 CPU 维度 | 已改写（§4.4）：内存/服务面有证据、CPU 未测、触发条件从未执行、采样方式未记录 |
| 5 | 里程碑 5「完成」与 revert 收尾张力 | 已改写（§1 表 + 验收口径段）：完成的是 fail-closed 演练，「链上验证过证明」次数为 0；「全链 E2E verify OK」改为「链下出证/验证腿」 |
| 6 | 变更控制「仅 3 文件」与 fixture 矛盾 | 已更正（§2.3）：完整 poker_l1 变更面 9 文件列全；已提交 6bc7cb1（混合提交、message 未分披露，如实记录） |
| 7 | fixture 根因断言缺证据 | 已降级（§2.4.1）：先在性已证、归因为判断未证、期望改测试侧未独立评审 → 遗留 #5 |
| 8 | 金向量出处未说明 | 已补（§3.1）：vendored 上游 four_leaves 测试金向量，git ls-files 实查在库 |
| 9 | 16.4M gas 推导缺失 | 已补（§5.4）：1,023,373B×16=16,373,968 gas、×102gwei=1.6701 ETH；纯 calldata 地板价、FRI 计算 gas 未计、「同量级」为推断 |
| 10 | 关键证据仅存易失位置 | 已落盘（§0.5、§6 #15）：out/ 下 4+2 份副本；zchain docs 已随 6bc7cb1 提交 |
| 11 | 缺陷①裁定出处无引据 | 如实标注（§2.1）+ 遗留 #10 |
| 12 | 裁剪吞吐无数字 | 如实降级（§2.4.3）+ 遗留 #6 |
| 13 | tip 作 finality 上界方向性存疑 | 已更正（§2.1 finality 语义段）：承认偏高⇒多裁的不保守方向、假设未论证、reorg 恢复未设计 → 遗留 #7 |
| 14 | 查询顺序调用方未审计 | 已审计（§2.1）：生产调用点仅 node/mod.rs:2107，成员语义顺序无关（实读确认） |
| 15 | 8 手重放跨批重复结算语义 | 如实披露（§5.1）+ 遗留 #8：soft_accepted 未定义、去重机制未验证 |
| 16 | 服务器容量口径偷换 | 已更正（§5.7.3）：按 4600M/5200M 笼上限计算（余 17.9–40%），「7.3G 内」口径废弃；笼内 K=64 未实测 |
| 17 | qm31_ops 占比算术不一致 | 已标注（§3.4）：2^22.3=61.6%、77%=2^22.62，取保守 2^22.62；填充下限结论不受影响 |
| 18 | 5200M 推导差 88M | 已如实标注（§4.2 表）：4600+512=5112≠5200，差 88M 材料未解释 |
| 19 | 本仓递归交付提交状态未交代 | 已补（版本锚点段）：bc69a8b2/6bc7cb1 提交清单实查；本仓仅 checker +29/−17 未提交、out/ untracked |
| 20 | FRI 缺位期信任模型未展开 | 已展开（§5.5）：onlyAuthority（:102）、骨架期含 authority 均无法推进 latestFact（:113）、过渡期=operator 背书无密码学强制（合约注释自认） |
| 21 | final_fact 未定义 | 已定义（§3.5.2）：`poseidon([ph‖全部公开输出])`（stark_final.rs:106），与 batch_fact 两公式分离由测试 :420 钉死 |
