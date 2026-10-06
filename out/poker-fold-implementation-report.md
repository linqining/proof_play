# poker-fold 实施报告

- 日期：2026-09-30
- 分支/工作区：`feat/prove_perf` @ `a7ef893d`（batch verify）。**本次全部实施改动均在工作树、未 commit**——`git status --porcelain`（本会话实跑）显示 6 个修改文件（`fold_batch.cairo`、`foldagg.rs`、`fold_batch_test.rs`、`poker_dual_settlement.cairo`、`chain.rs`、`stark_final.rs`）+ 2 个未跟踪新件（`cairo/src/fold_batch/`、`tests/fold_parity_test.rs`）。
- 输入材料：`out/poker-fold-proposal.md`（立项报告，下称【提案】）、`out/fold-spec.md`（冻结规格，下称【规格】）、**【实施材料】= 工作流编排方随任务下发的实施会话记录**（电路/合约/链与对拍/测试/Lean/评审/门禁七路 JSON；未落盘本仓库、无路径可给——其可复核断言按 §4 分级，以仓库文件与本报告会话命令交叉核证）。本报告会话对关键断言做了实读与实跑复核，级别划分见 §4。
- 体例：对齐【提案】——结论先行、逐项对照、证据分级。

## 术语表（外部读者用；正文首次出现处不再展开）

| 术语 | 含义 |
|---|---|
| steps | Cairo VM 执行步数（证明运行的程序步数轴，T7 表主列） |
| 桶（2^19 桶） | STARK 以 2 的幂行数的 trace 档出证；397,415 steps 落在 2^19=524,288 行档，下一档 2^20；出证时间/内存随档阶梯、档内近似常数（【提案】§3.1 诚实边界 2） |
| EC_OP / poseidon（表列） | 出证 summary 的面板计数：trace 中椭圆曲线运算面板（EC_OP）与 poseidon 面板的行数（T1 打印 `outcome.ec_ops`）；随 K 的增长关系本报告未推导 |
| fact / fact 门 | fact = poseidon([程序哈希 ‖ 公开段全词])；fact 门 = 合约检查该 fact 已在 owner/prover-gated 的 `settlement_facts` 登记（`register_settlement_fact` :990-999 面），未登记即 revert |
| 分槽哈希 | `fold_program_hash` 与 `combined_program_hash` 是合约两个独立存储槽；fact 公式各绑各的哈希 ⇒ 跨链 fact 重算必不等（D3c 第 2 层禁混批闸） |
| ald | action_log_digest——动作日志链摘要；settle wire[36]，公开段 word 15 |
| settle wire / 98 词 | 每手结算语句输入 wire（settlement_stmt.cairo 布局：hand_id@0、registered_digest@1、n@2、binding@3、玩家 4..11/符号 12..19/金额 20..27/承诺 28..35/ald 36/计数 37/日志词 38..97） |
| 五步断言链 | 电路五步：①roster 满阶编码（on-curve+非恒等+z̄<n）②电路内 keyagg + roster_digest 重算 ③roster_digest 入公开输出 ④c、M_h 电路内重算 ⑤单方程 z̄·G−c·P̄−R̄==O |
| 域标签五件套 | `fold_batch.cairo:104-108`（本会话实读）：keyagg/roster/msg/sig/claim 五个 'poker/fold-batch/*.v1' 域分隔标签 |
| 链尾 4 词 | 批程序顶层输出 `[len]++K×17++尾4` 的尾 4 词 = [acc_prev, root_hi, root_lo, batch_fact]（stark_final.rs:202-205 实读） |
| verified=true/388 | 攻击复审出证 summary 字段：verified 与该次运行的 **steps 数**（388/587 均为 steps） |
| BDN ROM plain-PK | Bellare–Neven（CCS'06）多签系数构造：随机预言机（ROM）模型、无公钥认证（plain-PK）——μ_i 仅经 RO 依赖各自 pk，rogue-key 退化为 RO 不动点难度（无 PoP 时的安全等级） |
| 笼 / 笼内复测 | 内存受限（5,200 MiB）产证机复测环境；C3 门禁 = steps / 峰值 RSS / MemoryCurrent（【提案】C3，沿用工程报告 §5.7.3） |
| keyagg 锚 1,628 | keyagg 层每批固定 steps（【提案】§3.1 注：404 + 8 玩家×153），一批只付一次 |
| combined 基线 12,160 | combined 9 人每手 steps（【提案】§3.1 同机复测口径；2p 7,204 见 `docs/combined-perf-2026-09-29.md:14`） |
| host parity 门（T4 语义） | 出证前 host 期望侧重算比对——只钉公式/布局漂移，**对 soundness 零证明力**（【规格】§5-5 转引 fold_batch_test.rs:92-95 注释原文） |
| KAT | 已知答案测试：host 按公式独立重算 μ/M_h/c/roster_digest 并与钉死十六进制常量比对（T8） |
| heavy / #[ignore] | 真出证测试：默认门禁跳过，`cargo test --release … -- --ignored --nocapture` 运行 |
| --check-only | prove-hand 独立复验模式：对已产出证明仅做验证、不出证 |

---

## 0. 结论先行

**判定：核心路径完成（【提案】§4.3 工作项 1–4 代码与测试落地，门禁全绿；其中工作项 4 的 D3b 程序哈希钉扎已于 2026-09-30 经 `scripts/pin_fold_program_hash.sh` 自动落库，见 §5.2），带收尾条件。**

一句话理由：立项时 gate 住上线的两大硬条件 **C1（roster_registry 合约消费面）与 C2（生产版 fold 电路）已实现并通过全部在库测试**——debug 门禁本会话复跑全绿（`cargo test -p hand-verify-native`，**13 个 target 全部 0 failed**，枚举见 §2.1）；heavy 切片门禁 10 passed/0 failed（含 T9–T12 攻击负例与 T7 K=1/8/32/64 扫描；**实施会话实跑，本会话未复跑**）；合约 snforge 126 passed/0 failed（**实施会话实跑，本会话未复跑**）；链层 38 lib（本会话复跑）+ 2 integration（实施会话，本会话未复跑）；【规格】D1–D5 与四条冲突裁定（K-1～K-4）逐项落地。但以下事项中，除 C3 已于 2026-09-30 补测闭合外，其余四项未闭合（详见 §5）：

1. **工作树未 commit**，且 `cairo/src/fold_batch/settlement_stmt.cairo` symlink **未被 git 跟踪**（本会话 `git ls-files` 实证；`combined/` 侧同名 symlink 已入库）——照当前状态提交后新克隆无法编译生产 fold 电路，D3b 钉扎的「复现程序哈希」路径即断（评审发现，本会话复现确认）→ **已闭合（a87f5bb1 提交：symlink 以 120000 模式入库，fold_parity_test.rs 同批入库）**；
2. **D3b 钉扎未落库** → **已于 2026-09-30 自动钉扎闭合**：`FOLD_BATCH_PROGRAM_HASH_HEX = 0x02a42b516184d923ebddb0c3cf1221d62faa380e86a9592709657fbc85e6ba54`（K=1 真出证实测；`cargo test -p stark-recursion --lib` 38/0 复验）——发布再钉扎由 `scripts/pin_fold_program_hash.sh` 幂等自动处理，详见 §5.2；
3. ~~C3 笼内复测未做~~ → **已于 2026-09-30 补测闭合（三门禁全绿，K=64 保持）**：笼内 steps 397,415 与本机逐字一致、峰值 RSS 3,222 MiB（4600M 单元帽 70%）、零 OOM、texas.service 全程 active 且 MemoryCurrent 漂移 0.00%——完整记录见 §5.3；
4. **C5/C6 未开始**：声明域文档、聚合协议外部评审 + poseidon-as-RO 论证；
5. **工作项 5（EVM/Monad）未开始**（不在本批实施范围——本批 = 【提案】工作项 1–4 及其配套测试与 Lean 复核——属剩余条件）。

硬条件状态总览（详对照见 §1）：

| # | 条件 | 立项时现状 | 实施后状态 |
|---|------|------|------|
| C1 | `register_roster` + `roster_registry` + fold 入口 `segment[16]` 对照 | 未实现（grep 0 命中） | ✅ 实现并测试（snforge 126/0；**未 commit、未部署**） |
| C2 | 生产版 fold_batch.cairo（98 词 settle wire + M_h 真槽 + 16→17 词） | 切片版占位槽 | ✅ 实现并测试（heavy T1/T7 全过） |
| C3 | K=64 笼内复测（steps/RSS/MemoryCurrent） | 未入笼 | ✅ **2026-09-30 补测全绿**（K=64 保持，无需退档）：笼内 steps 397,415 = 6,209/手（与本机 T7 逐字一致）、峰值 RSS 3,222 MiB（4600M 单元帽 70%）、texas 漂移 0.00%、oom_kill=0；记录见 §5.3 与 out/c3-cage-retest/ |
| C4 | ExecEval.lean 修复 + lake build 全根 | 审方实测 HEAD 即不可编译 | ⚠️ **阻塞前提被推翻**：HEAD（a7ef893d）可编译，损坏属上一版 575d0d66；整仓全根未跑（依据【实施材料】Lean 实跑记录，本报告会话未复跑 Lean） |
| C5 | 声明域纪律文档 | 文档义务，随部署交付 | ❌ 未开始 |
| C6 | 聚合协议外部评审 + poseidon-as-RO 实例化论证 | 未开始 | ❌ 未开始 |

---

## 1. 硬条件对照表（C1/C2 与提案工作项 1–4 逐项）

### 1.1 硬条件 C1 / C2

| 条件 | 做了什么 | 证据 | 状态 |
|---|---|---|---|
| **C1** 合约消费面 | `PokerDualSettlement` 新增：`roster_registry: Map<felt252,bool>` 存储（`poker_contracts/src/poker_dual_settlement.cairo:593`）、owner-gated 一次性 `register_roster`（:1364——链上重算 `poseidon(['poker/fold-batch/roster.v1', n]++pks)`，标签与电路 `fold_batch.cairo:105` 同名常量（核验手段见证据列）；digest 已注册拒绝 ：1384；`RosterRegistered` 事件含 pks 全文 ：1388）、`set_fold_program_hash`/`fold_program_hash` view（:1397-1404，复刻 `set_combined_program_hash` 模式）、`roster_registered` view（:1392）、fold 入口 `verify_and_settle_dapv_fold_private`（:1479——段长 17 检 ：1491 + `segment[16] != 0 && roster_registry.read(...)` 对照 ：1511 + fact 门绑 `fold_program_hash` 分槽哈希 ：1515）、`DualProofSettledFold` 事件（:1541）。fact 门复用既有 `settlement_facts`，不新增 ACL；combined 入口与 fallback 零改动（`SETTLEMENT_SEGMENT_LEN=15` :302 / `COMBINED_SEGMENT_LEN=16` :304 原样）；`PokerTableRegistry` 零改动（【规格】§4.7：permissionless 不承 soundness） | 「零改动」= **git 对照证据**（本会话实跑）：`git diff --numstat -- poker_dual_settlement.cairo` → **541 增 / 0 删**（纯新增，既有行——含 combined 入口与两个段长常量——零触碰）；`git status --porcelain -- poker_table_registry.cairo` → 空（无改动）。roster 标签一致性（本会话实跑 `grep "poker/fold-batch/roster.v1"`）：合约 ：310（实现常量）/ ：2160（测试常量）与电路 ：105 三处字符串逐字相同——**跨「合约↔电路」无自动化测试，靠字面常量比对**（如实标注）；合约内公式自洽由 snforge 测试钉住（`roster_digest_of` 同标签链上重算、正例接受）。snforge 126 passed/0 failed【实施材料】，`settlement_fold_private_tests` **11 条 = 2 正例 + 9 负例**（正例 = 注册+RosterRegistered 事件逐字段断言、17 词诚实段结算+事件断言；负例 = 未授权 register_roster、未授权 set_fold_program_hash、重复注册、pks 长度错、n 窗外、segment[16] 未注册、16 词段、combined 哈希 fact、重放——本会话 grep 测试函数名清点）+ combined 回归 + `combined_rejects_17_word_fold_segment` | ✅ 代码+测试完成（**已随 a87f5bb1 commit**；D3b 哈希已钉 `0x02a42b…`；**未部署**——部署时 owner 调 `set_fold_program_hash`） |
| **C2** 生产版 fold 电路 | `fold_batch.cairo` 并入 98 词 settle wire（`SETTLE_WORDS=98` :111，cm 槽 `28..=35` :112），`mod settlement_stmt` 复用语句全链约束（:83，经 `fold_batch/settlement_stmt.cairo` symlink shim）；M_h 换真槽（【规格】D2：m1=wire[1] registered_digest、m2=wire[2] n_expected、cm_digest=poseidon(wire[28..=35]) 8 词压缩；ald 按代码现状走语句内传递绑定 D2a——电路头注释 ：52-60 本会话实读）；输出改 K 段 17 词平铺（:261，布局 = `[acc]++语句段15++[roster_digest@16]`，word 0–15 与 combined 信封同位）；`ROSTER_LABEL='poker/fold-batch/roster.v1'`（:105；五件套 ：104-108 本会话实读）与五步断言链/域标签五件套未动（公式保持由 T8 host 重算机器钉住，见 §2.4）；`foldagg.rs` 镜像逐位同步（`build_batch_wire` :463、`prove_fold_batch` :622 出证后 roster→acc→语句段门序 + 段 word 1..=15 对 host `expected_segment` parity 门 ：701-705） | heavy T1 P=2/5/8×K=8 = 47,449/49,278/51,139 steps 全过（verified + 段形状 + 双 parity + `--check-only`）【实施材料】；debug 门禁含 `wire_layout_matches_circuit_contract`（fold_batch_test.rs:302，钉 98 词摊平与 hand_id@0/digest@1/n@2/binding@3/cm@28..=35）与 `mh_slots_derive_from_settle_wire`（:324，m2=n_expected≠roster 人数实证槽语义独立）——两者本会话复跑 ok | ✅ 完成（工作树未 commit） |

**链上如何消费 17 词段（回应「链上只信 roster digest 是否足够」——fold 入口 ：1479-1560 本会话实读）**：

1. **word 0–15 的语义不经链上重放语句，而经 fact 门整体承诺**：`fact = fact_for_segment(fold_program_hash, segment)` = poseidon([程序哈希 ‖ 17 词全段])，须已在 owner/prover-gated 的 `settlement_facts` 登记——改 0–15 任何一词 ⇒ fact 不同 ⇒ 未登记即 revert。「该程序哈希确属生产 fold 程序」由 owner 设置 + D3b 钉扎纪律保证，合约本身不验程序语义——钉扎未落库前此承诺悬空（§5.2）。
2. **同源交叉锚**：seg[3] == 链上 `read_registered_digest(hand_binding)`、seg[15] == 链上 `action_logs.read(hand_binding)`、seg[1] == MAGIC、seg[2] == hand_id、seg[5] == hand_binding、n = seg[4] ∈ 2..=8（与 combined 入口同款检查序列）。
3. **派奖消费**：total = seg[14] → vault escrow；seg[6..13]（8 个 cm 承诺）写入 `claim_cms`；seg[0]（批终 acc）与 roster_digest 随 `DualProofSettledFold` 事件披露供链下核对——acc 链的密码学闭环在证明系统侧，合约不重放（与 combined 入口同构）。
4. **host parity 门不是链上闭环的一部分**：它是出证前 host 期望侧重算（公式漂移检测，T4 语义，零 soundness 证明力）；链上闭环 = fact 承诺 + 同源锚 + roster 对照三层。

### 1.2 提案工作项 1–4（§4.3 估算表）

| # | 工作项 | 做了什么 | 证据 | 状态 |
|---|---|---|---|---|
| 1 | 生产版 fold_batch.cairo + foldagg.rs 镜像同步 | 与 C2 同体（见 §1.1）；另含 Q-1 定案落码：段 slot 0 = **批终 acc 复制**（K 段同值），钉进电路头注释（fold_batch.cairo:25-30 本会话实读）与 host 批级锚——规格授权「实现时先钉后码」 | heavy T1/T7【实施材料】；debug 门禁本会话复跑全绿 | ✅ 完成 |
| 2 | 测试扩展（settle-wire 正例、生产槽位 T9–T12 复跑、合约层 roster 负例） | `fold_batch_test.rs`：布局契约测试（:302）、M_h 槽派生测试（:324）、T8 KAT 生产槽重钉（`KAT_M1`/`KAT_CM_DIGEST`/`KAT_MH`/`KAT_C` :223-225 本会话实读；`KAT_MU0`/`KAT_ROSTER_DIGEST` :221-222 沿用切片轮钉值——本会话 git diff 实证常量行零改动、与 HEAD 切片版逐位一致（核验链详见 §2.4））、T1–T12 全套带 `_attack_A1/_attack_A2` 等标签；合约层 snforge 测试 11 条（**2 正例 + 9 负例**，超【规格】D5-6 的 4 条负例最低配） | heavy 10 passed/0 failed（T9 真出证后 roster parity 门拒、T10 同、T11/T12 电路 panic 正控）【实施材料】；snforge 126/0【实施材料】 | ✅ 完成 |
| 3 | Starknet 合约 | 与 C1 同体（见 §1.1） | 同 C1 | ✅ 完成 |
| 4 | chain.rs / stark_final.rs 16→17 与链尾解析 + 双跑对拍 | `chain.rs` **新增**常量/类型：`FOLD_OUTPUT_LEN=17`（:336）、`FOLD_MAGIC_INDEX=1`（:342）、`FOLD_BINDING_INDEX=5`（:343）、`FOLD_ROSTER_INDEX=16`（:346）、`FoldHandEntry`（:355）/`FoldBatchPlan`（:379，镜像 CombinedBatchPlan 五连检 + 批常量三检）；`stark_final.rs`：`FOLD_SEGMENT_LEN=17`（:83）、`FOLD_BATCH_PROGRAM_HASH_HEX` 空串 + fail-closed（:67/:215-218）、`parse_fold_final_output`/statements（`[len]++K×17++尾4`）；`SEGMENT_LEN=16`（:79）、`BATCH_PROGRAM_HASH_HEX`、`COMBINED_*` 共享常量全部未动（**git 对照证据**，本会话实跑：`git diff -U0 -- stark_final.rs` 对两常量零删除行，且新增测试钉住 `assert_eq!(SEGMENT_LEN, 16)` 与 combined 钉扎非空在役——stark_final.rs:650-651；`git diff -- chain.rs` 无 `COMBINED` 删除行）；`expected_batch_fact` 原样复用（diff 中该函数定义无改动行，fold 侧仅新增调用）；D5 对拍落新文件 `tests/fold_parity_test.rs`（host 形 ：152 默认门禁 + heavy `t13` :334 `#[ignore]`） | `cargo build -p stark-recursion` → 0 errors（本会话复跑）；`cargo test -p stark-recursion --lib` → 38 passed/0 failed（本会话复跑；integration 2 条为【实施材料】）；`fold_parity_test` debug 1 passed（本会话复跑）；t13 heavy：同一 8 手 98 词 wire 双吃，combined 逐手 8 证 + fold 一批 51,115 steps，跨腿 word 1..=15 逐词相等 + acc/roster 锚出证后对照 + `--check-only`【实施材料】 | ✅ **代码完成，钉扎已落库（2026-09-30 补录）**：`FOLD_BATCH_PROGRAM_HASH_HEX = 0x02a42b…`（K=1 实测，发布自动化 `scripts/pin_fold_program_hash.sh`），D3b/D3c 第 2 层闸链侧通电 |

**本批实施范围 = 工作项 1–4 及其配套测试与 Lean 复核**；工作项 5–9 不在本批交付（5 EVM/Monad、6 笼内复测、8 PoP、9 外部评审均未开始；7 见下），归入 §5。

### 1.3 特别项：C4 / 工作项 7（ExecEval.lean）——阻塞前提被推翻

- **诊断**：立项 C4 引用的「审方实测 HEAD 575d0d66 即不可编译（:381/:387/:412）」在实施会话被复核实证为**版本错位**：HEAD `a7ef893d` 的 `src/airs_lean/AirsLean/ExecEval.lean` 本身可编译（toolchain v4.32.0：`lake env lean AirsLean/ExecEval.lean` exit 0 仅 1 条 unused-variable 警告；删除 olean/ilean/trace 后强制重 elaboration `lake build AirsLean.ExecEval` → Built，44s，0 error；「8661 jobs」= lake 对该次构建输出的**任务条目数，覆盖 ExecEval 自身 + 全部传递依赖，非整仓全部模块**）；对照组从 `git show 575d0d66:` 导出旧版实编译，**复现出与评审报告（Lean 复核会话输入，路径未随材料提供）逐一吻合的三处错误**（:381:93 unsolved goals、:387:74 unexpected token ')'、:412:17 unknown identifier `hinit`）——损坏已在 HEAD 提交重写 fund_move_eval 证明时修复，无需再改。【实施材料；复现命令 = `git show 575d0d66:src/airs_lean/AirsLean/ExecEval.lean` 导出后 `lake env lean` 实编译，本报告会话未复跑】
- **C4 剩余**：仓库顶层全根 `lake build` 未跑——与上述模块级构建的差别 = 全根覆盖仓库默认目标全集（含 Fold/Chain/Settlement/KeyAgg 四层共存的字面验收），模块级构建只覆盖 ExecEval 依赖链；缺口即此。
- 级别：材料转引，本报告会话未复跑 Lean。

---

## 2. 门禁与攻击负例结果

### 2.1 门禁

| 门禁 | 命令 | 结果 | 复核级别 |
|---|---|---|---|
| debug 全量 | `cargo test -p hand-verify-native` | **全绿，13 个 target 全部 0 failed**（本会话实跑枚举 Running 行）：lib 30 / main 2 / empty_batch_test 1 / fold_batch_test 20（10 passed+10 ignored，heavy 留门禁）/ fold_formal_props 12 / fold_parity_test 2（1 passed+1 ignored）/ combined_perf、combined_test、compose_test、perf、recurse_test、Doc-tests 各 0（combined_test 全 #[ignore]） | ✅ **本会话复跑**；【实施材料】旧记「12 个 target」，以本会话实数 13 为准 |
| heavy 切片 | `cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture` | **10 passed / 0 failed**，构成 = **10 条 #[ignore] 测试**（本会话 `grep -c '#[ignore'` 实证 10 条属性行；debug 门禁同文件 10 ignored 互证）：T1×**1 条**（一条测试内跑 P=2/5/8 三档 = 47,449/49,278/51,139 steps）+ T2/T3/T5/T6/T9/T10/T11/T12×**8 条** + T7×**1 条**（一条测试内扫 K=1/8/32/64 = **7,859/51,139/199,543/397,415** steps；K=64 = 2^19 桶 ≤2^20，平均 6,209/手 = 397,415/64），门 = K=1 ≤ 12,160+1,628 且边际 ≤ combined 12,160/手，全过 | 【实施材料】两次全量记录（10/0）；本会话未复跑 release 出证 |
| 链层 | `cargo build -p stark-recursion`；`cargo test -p stark-recursion` | build 0 errors（本会话复跑）；38 lib passed（本会话复跑）+ 2 integration passed【实施材料】 | 混合 |
| 合约编译 | `scarb build`（scarb 2.19.4，PATH 前置 `~/.local/opt/toolchains/scarb-2.19.4/bin`） | Finished dev profile，仅既有 warning（secp256k1 deprecated feature、:17 unused import），无 error | 【实施材料】 |
| snforge 全量 | `PATH=… scarb-2.19.4/bin:$PATH snforge test`（snforge 0.63.0） | **126 passed, 0 failed, 0 ignored**（含 sepolia fork 测试） | 【实施材料】；fork 测试依赖外网 publicnode RPC，首跑曾瞬时网络错误 exit 2、重跑过（CI 波动源，见 §5.1） |

另：`grep -n 'hand-verify-native' stark-recursion/Cargo.toml` → 无结果（本会话实跑，exit 1）——stark-recursion 不依赖本 crate，foldagg API 变更无跨 crate 影响。

### 2.2 攻击负例矩阵（全部活跃，attack 标签防语义漂移）

| 负例 | 拒绝面 | 拒因实证 | 复核级别 |
|---|---|---|---|
| T2 z̄+1 | 电路 panic，无 proof 产出 | heavy ok；切片轮 prove-hand 手动复核同形 | 【实施材料】 |
| T3 跨手重放 | 电路 panic（hand_binding ∈ c） | heavy ok | 【实施材料】 |
| T5 forged prev_acc | **出证后** acc parity 门拒 | heavy ok | 【实施材料】 |
| T6 off-curve/恒等 pk | 电路 panic（fail-closed）+ host 形负例 | debug 门禁本会话复跑 ok（host 形）；heavy ok【实施材料】 | 混合 |
| T9 = attack_A1（攻击者钥自签 roster） | **真出证成功后** roster parity 门拒（out/t9-forge0/ 产出 proof.json+summary.json） | `t9_forge0 -- --ignored --nocapture` → ok【实施材料】 | 【实施材料】 |
| T10 = attack_A2（整组换 roster，n=1） | 真出证后 parity 门拒 | ok【实施材料】 | 【实施材料】 |
| T11/T12（A1/A2 输入的**正控**：伪造 roster **再加 z̄+1**） | 电路 panic | 构造 = A1/A2 同款伪造 roster 输入 + 攻击者把 z̄ 改为 z̄+1（连签名方程也违反；`fold_batch_test.rs:559-596` 本会话实读）——目的：证明「即使攻击者彻底破坏方程，电路也 panic」这条保险活跃，**防 T9/T10 的「出证成功」是电路检查本身坏掉导致的假阳性**；与 T9/T10（签名方程合法、仅 roster 伪造 → 电路放行、消费面拒）形成两条拒绝路径的交叉对照 | prove-hand 直跑确认程序内 `An ASSERT_EQ instruction failed: 0 != 1` + Cairo traceback，out 目录仅 executable.json/inputs.json **无 proof.json**——排除环境性非零退出假阳性【实施材料】 |

**分层语义（规格 D5/K-2 的正确形态，非缺陷）**：T9/T10 **不电路 panic**——A1/A2 攻击复审已实证电路对 wire pks 自由（换钥照样出证），fold 的 soundness 闭合点在**出证后的注册面锚对照**（`foldagg.rs:701-705` roster→acc→语句段门序），即 `roster_registry` 的 host 模拟；T11/T12 才是电路内 panic 面（z̄ 范围）。

### 2.3 双跑对拍（D5，T13）

- 轻量 host 形 `fold_combined_parity_same_settle_corpus_host`（fold_parity_test.rs:152）：默认门禁内，**本会话复跑 passed**——3a 跨腿 word 1..=15 逐词相等 / 3b 批 acc 两路径一致 / 3c slot 16 锚 / D2 槽位钉死 / D2a ald 传递绑定。
- heavy `t13_fold_combined_parity_heavy_prove_roundtrip`（:334，`#[ignore]`）：同一 8 手 98 词 wire 语料双吃（语料 = `build_corpus`：**P=8 人 roster × K=8 手**、席 0/1 赢席 2..7 均摊输、空动作日志——`fold_parity_test.rs:60-63,100-110` 本会话实读），combined 腿逐手 `prove_combined_layer` 8 证 + fold 腿 `prove_fold_batch` 一批；【实施材料】记录 51,115 steps / EC_OP 32 / reverify 33ms，全断言过。
- **51,115（t13）与 51,139（T1 P=8）为何不等**：两语料独立构造（fold_parity_test `build_corpus` vs fold_batch_test `honest_batch`，种子与金额模式不同），且两数出自不同会话的两次运行（实施期间工作树处于并行改动态）；24 步（0.05%）差异未在本会话复跑归因——不影响任何门（两数 next_power_of_two 同为 65,536 = 2^16 桶、EC_OP 同值 32）。EC_OP = 出证 summary 的椭圆曲线运算面板行数（T1 表列字段 `outcome.ec_ops`，见术语表）。
- **明确不断言**（【规格】D5-4）：两链 acc 跨链相等——claim 公式不同源（combined 无域标签 vs fold 三词 CLAIM_LABEL），是有意的两个对象。

### 2.4 KAT 交叉钉值

T8（`t8_kat_labels_mu_mh_c_pinned_attack_T8`，默认门禁内本会话复跑 ok）。**证据链（回应「注释自证不构成证据」）**：重算侧独立——T8 由 host 按公式**独立重算** μ₀/roster_digest/M_h/c 并与钉值比对，测试即机器核验；钉值侧——KAT_MU0/KAT_ROSTER_DIGEST 沿用切片轮钉值，本会话 `git diff` 实证两常量行**零改动**（与 HEAD a7ef893d 的切片版逐位一致）；M1/cm_digest/M_h/c 为生产 fixture 重钉（`fold_batch_test.rs:221-225`）。**边界（如实标注）**：钉值本身未由本会话独立重新生成，「沿用」的正确性依赖切片轮生成时同公式的前提 + 上述 diff 证据。

---

## 3. 与提案/规格的偏离

**裁定性偏离（【规格】§0 冲突裁定，按「以代码为准」执行）**：

1. **K-1 否决【提案】§4.1 改共享常量方案**：三处共享常量（`COMBINED_OUTPUT_LEN`/`SEGMENT_LEN`/`COMBINED_SEGMENT_LEN`）都是在役 combined fallback 承重件，改共享即报废【提案】§4.2 自己要求的 fallback——一律**新增** `FOLD_*` 常量与独立类型（本会话 git diff + grep 实证：FOLD_* 为新增行、共享常量零删除，见 §1.2 工作项 4 证据）。
2. **K-2 M_h 按已实现 3 槽公式钉死**，ald（wire[36]）走语句内传递绑定（D2a），非【提案】「wire[36] 入 M_h」的 4 槽读法；若升 4 槽属公式变更，留开放点 Q-4 给安全评审。
3. **K-4 cm 槽按实际布局钉 `wire[28..=35]` 8 词**（【提案】「wire[28..35]」半开记法少一词）。
4. K-3（提案「fold 文件未 commit」已过时）为状态陈旧记录，本报告会话 `git log --oneline -- <四文件>` 复证（输出仅 `a7ef893d` 一条，命令见附录 A；本次生产版改动是其后新的未提交增量）。

**规格开放点的实现期定案**：

5. **Q-1 定案**：每段 slot 0 = **批终 acc 复制**（K 段同值）——本程序只有一次 acc 折叠、无逐手 prev_acc 输入，K 段同值使每手段独立成 fact 都钉住整批链状态；电路与 host 镜像、chain.rs 侧注释一致钉同值（规格授权「先钉后码」）。
6. **Q-2 KAT 重钉**：cm_digest 8 词压缩的十六进制钉值已随生产 fixture 落库（KAT_M1/KAT_CM_DIGEST/KAT_MH/KAT_C）；切片 2 词占位（poseidon([cm0,cm1])）未迁移。

**形态偏离（规格未逐字规定或超规格）**：

7. **T7 验收门重钉**（门定义原文见 `tests/fold_batch_test.rs:600` T7 文档注释）：切片门（≤2.2k steps/手）在生产形状下**无解，依据可算而非「必然」断言**——生产形状 K=1 单手实测 7,859 steps（【实施材料】T7），已是切片门的 3.6×；增量主体为每手新增的结算语句层：切片→生产 K=64 差 365,062 steps ≈ **5.8k/手**，来自每手 settlement_statement 全量约束（98 词 wire 上的 digest 折叠/零和/计数/动作链重放/认领承诺）+ 每手 3 次 poseidon + 单方程 EC 检查。膨胀方向与【提案】§3.1 生产估算 ≈11.3k/手同量级且实际更低（该估算的 9,405/手结算边际实测自含 keccak 批根的链级批程序，fold 电路不做 keccak，构成不同不可直比）。新门 = 生产口径：K=1 ≤ combined 每手 **12,160**（9 人每手 steps，【提案】§3.1 同机复测口径；2p 7,204 见 `poker_contracts/hand-verify-native/docs/combined-perf-2026-09-29.md:14`）+ keyagg 批固定层 **1,628**（【提案】§3.1 注：404 + 8×153，一批只付一次）；批量边际 ≤ 12,160/手（实测平均 6,209/手）。
8. **D5 对拍落独立新文件** `tests/fold_parity_test.rs`（【规格】D5 允许的两处之一）；合约负例实际 11 条，超【规格】D5-6 的 4 条最低配。
9. **新增 symlink shim** `cairo/src/fold_batch/settlement_stmt.cairo`（指向 `../settlement_stmt.cairo`，非新逻辑）：`mod settlement_stmt;` 解析路径要求子目录存在，仓库既有先例 `combined/` 同款；不建则电路无法编译，复制语句体则有 soundness 逻辑分叉风险。**该 symlink 未入 git**（§5.1）。
10. **T7 四档未裁剪**（实施范围允许裁剪、实际不需要）：K=64 生产尺寸实测通过。
11. **工作项 4 的钉扎留白**：`FOLD_BATCH_PROGRAM_HASH_HEX` 钉空串 fail-closed——生产 fold 程序尚未编译出证，无法凭空造哈希；钉扎动作与 Q-2 同批随生产程序落库（纪律同 `BATCH_PROGRAM_HASH_HEX` 注释，stark_final.rs:62-65 本会话实读）→ **已闭合（2026-09-30）**：`scripts/pin_fold_program_hash.sh` 出证提取实测哈希自动钉扎（`0x02a42b…`），钉扎纪律注释同步改为指向脚本（发布自动、不手填）。

**过程与范围如实记录**：

12. **并行会话撞车与合并态**：实施期间工作树出现多会话对同一规格 D1/D2/D4 的并行实现，最终工作树是各路改动的合并态；【规格】会话「grep roster_registry 0 命中」的结论相对当前树已过时（本会话 grep 全命中）。规格「以代码为准」原则吸收了该漂移。
13. **范围外发现（未修，如实上报）**：`combined.rs:127-131` 的动作日志链根折 entry 双词，而 `settlement_stmt.cairo:118` 电路重放只折 log 词——count>0 时两式必然分歧。**「未暴露」前提的核验（本会话实跑，修正【实施材料】原表述）**：`grep -rn build_settle_statement` 清点全部在库调用点——**走电路出证的语料全部空日志**（`foldagg.rs:800` mint_fold_hands/T1 语料、`fold_batch_test.rs:78` settle_wire/KAT 与攻击负例、`combined_test.rs:63`、`combined_perf.rs:65` 均传 `&[]` ⇒ count=0，两式同归 poseidon([DOMAIN])）；但 **host 层两处带非空日志**：`fold_formal_props.rs:320` proptest 传 `&entries`、`fold_parity_test.rs:280` D2a 演示传一条日志——两处均不出证、不经电路重放（host 公式内部自洽，host-vs-电路分歧不被行使）。故「全部 fixture 均 count=0」的原表述过宽，准确结论 = **全部出证语料 count=0**，「未暴露」成立。属 combined/settlement_stmt 既有面，修复不在本批授权内。
14. **首次 snforge 全量曾 4 failed**，均为测试写法问题（should_panic 需单引号 felt 形式——OZ 1.0.0 `assert_only_owner` panic 为 felt252 短串；事件断言需本地镜像枚举），非合约逻辑——已修复复跑至 126/0，过程如实记录。

---

## 4. 证据分级

| 级别 | 内容 |
|---|---|
| **本报告会话实跑**（撰写轮 + 修订轮，命令全单见附录 A） | git 对照组：`git status --porcelain` / `git branch --show-current` / `git log --oneline -3`（6 修改 + 2 未跟踪、feat/prove_perf、a7ef893d）；`git ls-files …/fold_batch/` → 空（**symlink 未入库**）对照 `…/combined/` → 含 settlement_stmt.cairo；`git log --oneline -- <fold 四文件>` → 仅 a7ef893d；`git diff --numstat -- poker_dual_settlement.cairo` → **541 增/0 删**；`git diff -U0 stark_final.rs` 对 SEGMENT_LEN/BATCH_PROGRAM_HASH_HEX/expected_batch_fact **零删除行**；`git diff -- chain.rs` 无 COMBINED 删除行；`git status --porcelain -- poker_table_registry.cairo` → 空；`git diff -- fold_batch_test.rs` 中 KAT_MU0/KAT_ROSTER_DIGEST **常量行零改动**。符号/布局组：grep 实证 `chain.rs`（FOLD_OUTPUT_LEN=17:336、三索引 :342-346、FoldHandEntry :355、FoldBatchPlan :379）、`stark_final.rs`（FOLD_BATCH_PROGRAM_HASH_HEX="" :67、SEGMENT_LEN=16 :79、FOLD_SEGMENT_LEN=17 :83、fail-closed :215-218、共享常量钉住测试 :650-651）、`poker_dual_settlement.cairo`（三段长常量 :302/:304/:308、存储 :593/:596、事件枚举 :617-618、register_roster :1364、set_fold_program_hash :1397、fold 入口 :1479、segment[16] 对照 :1511）、roster 标签两文件逐字相同、`_LABEL` 五件套 :104-108、`grep -c '#[ignore'`（10/1）、`grep -rn build_settle_statement` 调用点清点。构建/测试组：**`cargo test -p hand-verify-native` 复跑两轮全绿 0 failed**（修订轮枚举 13 个 target）；`cargo build -p stark-recursion` → 0 errors；`cargo test -p stark-recursion --lib` → 38 passed（并复现 `warning: function synth_fold_final_output is never used`）；`grep hand-verify-native stark-recursion/Cargo.toml` → exit 1；`ls` 核实 combined-perf 与 engineering-report 两文档存在 |
| **本报告会话实读** | `out/poker-fold-proposal.md` 全文、`out/fold-spec.md` 全文；`fold_batch.cairo` 头部 60 行（17 词布局/Q-1 批终 acc/D2/D2a）及 :104-112/:261；合约 fold 入口 `sed -n '1479,1575p'`（消费路径全序列）；`fold_parity_test.rs:1-120`（语料 P=8/K=8/空日志）；`fold_batch_test.rs:330-410`（T1 语料与断言）与 `:556-599`（T11/T12 构造）；`Scarb.toml:36-40`（fork 配置 publicnode URL）；`stark_final.rs:530-540`（synth_fold_final_output 及「E2E 对拍待生产 fold 程序落库」注释）；各 fixture 调用点（foldagg.rs:795-806、fold_formal_props.rs:318-326,353-360、fold_parity_test.rs:278-288、fold_batch_test.rs:70-82） |
| **实施会话实跑（【实施材料】转引，本报告会话未复跑）** | heavy 切片门禁 10/10（T1 三档、T7 四档 steps、T9/T10 出证后门拒、T11/T12 panic 正控）；t9/t10/t11/t12/t1 单跑与 t11 prove-hand 手动 ASSERT_EQ 复核；snforge 126/0；scarb build（2.19.4）；stark-recursion integration 2 条；lean 三组实跑（HEAD 可编译、强制重 elaboration、旧版 575d0d66 复现三处错误）；combined_single_proof_roundtrip A/B 对照；t13 heavy 全断言 |
| **更早会话数据（【提案】转引，本批未复测）** | 攻击复审 A1/A2 出证（verified=true/388、true/587——388/587 为 steps）、审方 F-1 曲线实测、切片轮 K=64 直跑 32,353 steps/3.35 GiB、combined 基线 12,160 steps/9p 与 2.0–2.4 GiB（仓库文档 `poker_contracts/hand-verify-native/docs/combined-perf-2026-09-29.md` 佐证，本会话核实存在）、K4 wrap 18.3M 约束等 |

**未验证/未覆盖（诚实清单）**：整仓 `lake build` 全根；heavy 套件本报告会话未复跑（实施会话两次记录 10/0，本会话仅复证 debug 门禁与链层构建）；lean 三组实验本会话未复跑；t13 与 T1 的 24 步差未归因复跑（§2.3）；部署动作（owner 切 setter、合约上链）未发生；PoP 验证面（非阻塞，Q-3 裁定退守 BDN ROM plain-PK 强度）。

---

## 5. 剩余条件与建议后续

1. ~~提交纪律~~ → **已完成（a87f5bb1，2026-09-30 复核确认）**：`fold_batch/settlement_stmt.cairo` symlink 以 120000 模式入库（与 combined 侧同 blob）、`fold_parity_test.rs` 同批入库。随附 CI 环境纪律仍有效：scarb 2.11.4 被 snforge 0.63 拒绝（须 ≥2.13.1，机器用 2.19.4 PATH 前置）；`tests/unshield_fork.cairo`（Scarb.toml:37-40）依赖外网 RPC，建议 fork 测试单独分档。
2. **D3b 钉扎落库——✅ 已完成（2026-09-30，发布自动化）**：`FOLD_BATCH_PROGRAM_HASH_HEX = 0x02a42b516184d923ebddb0c3cf1221d62faa380e86a9592709657fbc85e6ba54`。发布流程：`bash scripts/pin_fold_program_hash.sh`——K=1 真出证（FOLD_PERF_ONLY=1 跑 t7，含验收线断言）→ 从 `public_outputs.json` 提取 `program_hash` → 归一化 64 位补零（felt_to_hex 口径）→ 幂等改钉 `stark_final.rs` → 复跑 `cargo test -p stark-recursion --lib`（钉扎两态测试验证）。哈希只钉程序不钉参数；改 `fold_batch.cairo` 后下次发布自动改钉，**不手填**。合约侧部署时 owner 调 `set_fold_program_hash(0x02a42b…)`；链下 fact-verify 用 `--expect-program-hash 0x02a42b…`。Q-2 KAT 已随生产版落库（实施轮），本条闭合。
3. **C3 笼内复测（工作项 6）——✅ 已完成（2026-09-30 补测，三门禁全绿，K=64 保持、退档条款未触发）**：
   - **笼与环境**：stark 产证机（阿里云 Linux x86_64，4 vCPU / 7.3G，内核 6.6 cgroup v2）；slice `zchain-recursion.slice`（memory.max 实读 5,452,595,200B = 5200M、memory.swap.max=0）；单元按 monad-fold@.service 模板探针纪律以 `systemd-run` 瞬态服务 `fold-c3-k64.service` 执行：MemoryMax=4600M / MemorySwapMax=0 / CPUQuota=300% / CPUWeight=60 / IOWeight=60 / Nice=5（**4600M 单元帽比 slice 5200M 更严，取严判定**）；起跑前核查 slice 内无其他证明任务。
   - **被测物**：本仓库同源码交叉编译 musl 静态二进制（`fold_batch_test` + `prove-hand`，SHA256 推送前后双侧核对一致），`FOLD_PERF_ONLY=64` 单档 T7，canonical_small 参数（镜像推送原文件），RAYON 默认 4 线程。
   - **三门禁结果**：① **steps = 397,415**（wire 6,482 词、2^19 桶、EC_OP 256、poseidon 4,096、per-hand 6,209）——**与本机 T7 逐字一致**（steps 确定性 ⇒ 交叉编译不改变电路语义的直接证据）；② **峰值 RSS = 3,222 MiB**（cgroup `memory.current` 100ms 轮询取峰；= 4600M 单元帽 **70%**、slice 5200M 的 62%；`memory.events` oom_kill=0）；③ **texas.service 全程 active，MemoryCurrent = 1,078,407,168 B 首尾中峰同值（漂移 0.00% < 10% 门）**。
   - **时间轴与产物（如实记录，非门禁）**：prove 44,960ms / 总 49,279ms（4 vCPU Xeon；为本机 M 系 prove ~7.4s 的约 6 倍，CPU 口径不同属预期）；测试全程 49.74s；单元累计 CPU 2min9s；proof 15,719,876 B/批（≈245KB/手摊销）。
   - **局限（诚实标注）**：①内存峰值按 100ms 采样粒度，真实峰值可能略高于读数（对 4600M 帽余量 1,378 MiB，量级覆盖该误差）；②本复测为「电路级 T7 K=64 单批」口径，**不含**链级全链口径（stark-recursion 全链 51min/22–26GiB 仍属 T2 待办）；③texas 探针沿用 `systemctl show -p MemoryCurrent` 机制，计数器全程同值与工程报告 §4.4 观察一致（无法区分「真零扰动」与「计数器冻结」，如实标注；服务 active 与系统其它内存计数活动正常为旁证）；④交叉编译经 musl 工具链，未另做双构建对拍（steps 逐字一致为语义等同证据）。
   - **复现物料**：`out/c3-cage-retest/`（runner.sh 编排脚本、cage-run.sh 笼内脚本、result-k64.log 全量输出、push_start.log 含 SHA256）；服务器侧留档 `/root/.zmonad-tmp/fold-c3/`（verdict-k64/t7-k64.log/samples-k64.log）。
4. **C5 声明域文档（随部署交付）**：fold 模式仅在与「真验 STARK 站点 + 前提 K（roster 对照）」同时成立的面上宣称聚合签名效力；fact-registry/wrap 面按降级声明交付；Q-3 的玩家自核纪律（pks 随 `RosterRegistered` 事件可取——合约 ：1388 已实现取数入口）写入产品文档。
5. **C6 外部评审**：聚合协议外部评审（nonce 并发会话/Drijvers 面）+ poseidon-as-RO 实例化论证一次；未做前不宣称生产协议强度。Q-4（ald 是否升 M_h 第 4 槽）一并交安全评审裁定。
6. **工作项 5（EVM/Monad）**：FRI 路径公开输入扩展 + Monad 侧 roster_registry；wrap 腿取舍与降级文档（T2 路线定案下 wrap 腿非必需；StarkVerifier.sol 现为骨架）。
7. **多桌参数化（【提案】后续待办）**：折叠电路从单 roster 泛化为 T 个 roster 段（公开输入 +T 个 roster_digest 与每桌手数，padding 至最大桌 size=8），桌内聚合 + 跨桌 SettleBatch 语句级批（已桌无关）；SettleBatch 零改动；与全量协议迁移同批评审，电路规范改动先行。
8. **小项清理——部分完成（2026-09-30）**：`stark_final.rs:534` 测试辅助 `synth_fold_final_output` 已接回 `parse_fold_final_output_shape_and_rejects` 测试使用（死代码 warning 消除，连带清理 :483 遗留 unused_mut——crate 真实 warning 清零）；范围外公式分歧（§3.13）仍移交 combined 面负责人。
9. **部署序列提醒（【提案】§4.2）**：部署 fold_batch → 双跑对拍 → owner 切 setter → combined 入口保留为 fallback（双模式并存、禁混批三层闸：host 独立类型已落地、合约消费面互斥已落地，fact 公式锚待 D3b 钉扎后完整生效）。**对拍现状的准确口径**：t13 把【提案】§4.2 的双跑对拍在「同一 8 手语料、双证明路径、结算语义零漂移」维度机器化（3a/3b/3c 三断言）；**它不替代部署时对拍**——部署对象是真实部署程序与钉扎参数，部署时仍须以生产程序哈希 + 真实 roster 各跑一次对拍。

---

## 附录 A：本报告会话（撰写轮 + 修订轮）命令清单（复核用，路径相对仓库根）

```bash
# —— 状态与提交/零改动对照（git 证据）——
git status --porcelain && git branch --show-current && git log --oneline -3
git log --oneline -- poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo \
  poker_contracts/hand-verify-native/src/foldagg.rs \
  poker_contracts/hand-verify-native/tests/fold_batch_test.rs \
  poker_contracts/hand-verify-native/tests/fold_formal_props.rs      # → 仅 a7ef893d
git ls-files poker_contracts/hand-verify-native/cairo/src/fold_batch/   # 空输出 → symlink 未入库
git ls-files poker_contracts/hand-verify-native/cairo/src/combined/     # 对照 → 含 settlement_stmt.cairo
git status --porcelain -- poker_contracts/src/poker_table_registry.cairo   # 空 → 无改动
git diff --numstat -- poker_contracts/src/poker_dual_settlement.cairo   # → 541  0（纯新增 0 删除）
git diff -U0 -- stark-recursion/src/stark_final.rs | grep -E '^[-+].*(SEGMENT_LEN|BATCH_PROGRAM_HASH_HEX|expected_batch_fact)'
      # → 仅 + 行（新增 FOLD 常量与调用），无 - 行 ⇒ 共享常量与函数定义零改动
git diff -- stark-recursion/src/chain.rs | grep '^-.*COMBINED'          # 无输出 ⇒ 无 COMBINED 删除行
git diff -- poker_contracts/hand-verify-native/tests/fold_batch_test.rs | grep -E '^[+-].*KAT_(MU0|ROSTER_DIGEST)'
      # → 仅 + 注释行，常量行零改动 ⇒ 沿用 HEAD 切片版逐位一致

# —— 符号与布局（grep 实证存在性；「零改动」结论一律以上方 git 证据承载）——
grep -n 'FOLD_OUTPUT_LEN\|FOLD_MAGIC_INDEX\|FOLD_BINDING_INDEX\|FOLD_ROSTER_INDEX\|struct FoldBatchPlan' stark-recursion/src/chain.rs
grep -n 'FOLD_SEGMENT_LEN\|FOLD_BATCH_PROGRAM_HASH_HEX\|SEGMENT_LEN\|BATCH_PROGRAM_HASH_HEX' stark-recursion/src/stark_final.rs
grep -n 'FOLD_SEGMENT_LEN\|verify_and_settle_dapv_fold_private\|register_roster\|roster_registry\|set_fold_program_hash\|RosterRegistered\|DualProofSettledFold' poker_contracts/src/poker_dual_settlement.cairo
grep -n "poker/fold-batch/roster.v1" poker_contracts/src/poker_dual_settlement.cairo poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo
      # → 合约 :310/:2160 与电路 :105，字符串逐字相同
grep -n '_LABEL' poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo          # → :104-108 五件套
grep -c '#\[ignore' poker_contracts/hand-verify-native/tests/fold_batch_test.rs \
  poker_contracts/hand-verify-native/tests/fold_parity_test.rs                          # → 10 / 1 条属性行
grep -rn build_settle_statement poker_contracts/hand-verify-native/                     # → 语料调用点清点（§3.13）
grep -n 'hand-verify-native' stark-recursion/Cargo.toml                                 # → exit 1（无跨 crate 依赖）
ls poker_contracts/hand-verify-native/docs/combined-perf-2026-09-29.md out/stark-recursion-engineering-report.md

# —— 源码实读（sed 区段）——
sed -n '1,60p' poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo   # 头注释：17 词布局/Q-1/D2/D2a
sed -n '1479,1575p' poker_contracts/src/poker_dual_settlement.cairo            # fold 入口消费路径全序列
sed -n '1,120p' poker_contracts/hand-verify-native/tests/fold_parity_test.rs   # 语料 P=8/K=8/空日志
sed -n '330,410p;556,599p' poker_contracts/hand-verify-native/tests/fold_batch_test.rs   # T1 语料与 T11/T12 构造
sed -n '795,806p' poker_contracts/hand-verify-native/src/foldagg.rs            # mint_fold_hands 空日志
sed -n '318,326p;353,360p' poker_contracts/hand-verify-native/tests/fold_formal_props.rs \
  ; sed -n '278,288p' poker_contracts/hand-verify-native/tests/fold_parity_test.rs       # 非空日志调用点
sed -n '36,40p' poker_contracts/Scarb.toml                                     # fork 配置 publicnode URL
sed -n '530,540p' stark-recursion/src/stark_final.rs                           # synth_fold_final_output

# —— 构建与测试 ——
cargo test -p hand-verify-native            # 两轮各跑：13 个 target 全绿 0 failed（修订轮枚举 Running 行）
cargo build -p stark-recursion              # → Finished，0 errors
cargo test -p stark-recursion --lib         # → 38 passed + synth_fold_final_output warning 复现

# —— 以下为【实施材料】转引，本报告会话未跑（如实区分）——
cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture   # heavy 10/0
snforge test（scarb 2.19.4 PATH 前置）        # → 126/0
scarb build；lean 三组实验；t13 heavy；combined_single_proof_roundtrip 对照
```

## 附录 B：判定所依据的关键文件

- 生产电路：`poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo`（头注释 1–60：17 词布局/Q-1/D2/D2a；:83 mod 复用、:105 标签、:111-112 wire 常量、:261 K×17 输出）
- host 镜像：`poker_contracts/hand-verify-native/src/foldagg.rs`（:463 build_batch_wire、:622 prove_fold_batch、:701-705 出证后 parity 门序）
- 测试：`tests/fold_batch_test.rs`（:302/:324 契约与槽位、:221-225 KAT、:600 T7 文档注释即验收门定义、T1–T12 attack 标签）、`tests/fold_parity_test.rs`（:60-110 对拍语料、:152 host 形、:334 t13）
- 合约：`poker_contracts/src/poker_dual_settlement.cairo`（:302/:304/:308 三段长、:593/:596 存储、:1364/:1384/:1388 register_roster、:1397-1404 program hash、:1479/:1491/:1511/:1515/:1541 fold 入口）
- 链/终证：`stark-recursion/src/chain.rs`（:336-346/:355/:379）、`stark-recursion/src/stark_final.rs`（:67/:79/:83/:215-218/:534）
- 规格/提案：`out/fold-spec.md`（D1–D5、K-1～K-4、Q-1～Q-4）、`out/poker-fold-proposal.md`（§0 硬条件、§4.3 工作项）
