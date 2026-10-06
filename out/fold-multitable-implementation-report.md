# fold 多桌参数化实施报告

- 日期：2026-09-30
- 分支/工作区：`feat/prove_perf` @ `a87f5bb1`（feat: fold-proposal）。**本次全部实施改动均在工作树、未 commit**（本会话 `git status --porcelain` 实跑）：8 个修改文件（`fold_batch.cairo`、`foldagg.rs`、`fold_batch_test.rs`、`fold_parity_test.rs`、`poker_dual_settlement.cairo`、`chain.rs`、`stark_final.rs`、`out/poker-fold-implementation-report.md`）+ 5 个未跟踪路径（`out/c3-cage-retest/`、`out/fold-multitable-spec.md`、`out/fold-multitable-workflow.ts`、`poker_contracts/hand-verify-native/tests/golden/`、`scripts/pin_fold_program_hash.sh`）。其中 `stark_final.rs` 的工作树改动含**会话前遗留**（前批钉扎 0x02a42b… + 测试清理，【实施材料·chain】deviations 声明）与本批重钉行（见 §4）。
- 输入材料：`out/fold-multitable-spec.md`（冻结规格 M1–M9 + 开放点 Q-M1～Q-M4，下称【规格】）、`out/poker-fold-proposal.md:250-257`（多桌段提案原文，经【规格】§0 转引）、**【实施材料】= 工作流编排方随任务下发的四路实施 JSON**（电路/合约/链/测试）、**【评审材料】**（1 轮修复 4 发现）、**【门禁材料】**（5 门全绿记录）与**【钉扎材料】**（before/after 哈希）——以上材料未落盘本仓库、无路径可给（归档建议见 §6.4），其断言按 §5 分级，本报告会话对关键断言做了实读与实跑复核。前批报告 `out/poker-fold-implementation-report.md` 为体例与单桌基线基准（下称【前批报告】）。
- 体例：对齐【前批报告】——结论先行、逐项对照、证据分级。

## 术语表（外部读者用；正文首次出现处不再展开）

| 术语 | 含义 |
|---|---|
| T / 桌段 | 一个 fold 批内的 roster（桌）数；每桌在 wire 上自成一个自定界段 `[P_t, pks×P_t, K_t, blocks×K_t]` |
| ΣK / K_t | ΣK = 批内总手数（沿用 ≤64 且 2 的幂政策）；K_t = 第 t 桌手数（无独立上限、≥1） |
| T_MAX=8 | 桌数评审面政策上限（host 形状检查 `FOLD_T_MAX` + 链层 run 计数 `MAX_TABLES_PER_FOLD_BATCH` 双侧同值 8）。「非 steps 硬门」= 它不是被 steps 预算逼出的约束（ΣK≤64 下 steps 最坏仅占 2^20 地板 47.7%、永不成绑定约束——规格 M1-c），而是限定「新桌段解析循环 + host 循环」审查范围的政策值 |
| 自定界串接 / 无 T 词 | wire 不携带全局桌数前缀，桌数由 wire 长度自证：cursor==words.len() 即终止（【规格】M2） |
| run（slot16） | 段序上 slot16 的极大同值连续段。注意 run 数是 T 的**下界**而非恒等等于 T：相邻两桌 roster_digest 相同（同 roster 开两桌进同批）时 run 合并、run 数 < T；「run 数 = T」仅在相邻桌 digest 互异时成立（链层拒绝面按此语义，边界讨论见 §1 M4 注） |
| 金样（golden） | 重构前生产路径落库的 checked-in 期望输出（`tests/golden/fold_t1_p2k2.json`），钉 T=1 退化逐词一致 |
| 余量（margin） | 门分母 = 2^20 政策地板（`TRACE_FLOOR_LOG2=20`，canonical_small 变体 trace 行数地板，chain.rs:65 本会话实读），非实际落桶——M9-1c 实际落 2^19 桶，紧桶口径余量仅 ≈1.28×（§1 M1-d）；M1-d 验收门 = 地板口径余量 ≥1.5× |
| steps | Cairo VM 执行步数（证明运行的程序步数轴，T7 表主列；确定性量、与运行硬件无关） |
| 桶（2^n 桶） | STARK 以 2 的幂行数的 trace 档出证：实测 steps 自动 pad 到 next_power_of_two 行（M9-1c 409,563 → 2^19 行）；2^20 = 1,048,576 为 canonical_small 的政策地板（见「余量」行） |
| EC_OP / poseidon（表列） | 出证 summary 的面板计数：trace 中椭圆曲线运算（EC_OP）与 poseidon 哈希面板的行数，随 ΣK 线性增长（M9-1c ΣK=64 → 256/4096） |
| 电路臂 / parity 门臂 | 负例两拒绝路径：前者 = 电路内 VM assert panic 无证明；后者 = 诚实出证后 host anchor 对照 Err |
| heavy / `#[ignore]` / host 形 | 真出证测试（实际跑 prove-hand 出证，秒—分钟级），默认门禁跳过、`cargo test --release … -- --ignored --nocapture` 运行；「host 形」= 非 heavy 的 Rust 侧单元测试（只跑 host 公式/构造器，不出证） |
| `--check-only` | prove-hand 的独立复验模式：对已产出证明仅做验证、不出证 |
| 笼 / 笼内复测 | 内存受限产证机上的复测环境（前批 C3 口径：cgroup memory.max=5200M 的产证机 slice，门 = steps / 峰值 RSS / MemoryCurrent 三项）；与本机（Darwin arm64）为不同环境，时长与内存不可直比 |
| PANIC 探针 | 在测试/脚本中捕获 prove-hand stderr 并断言其内容形态的检查手法（如「无 felt panic 标签」「只有 ASSERT_EQ 失败」） |
| host 铸侧 / 铸造臂 | 语料铸造层（`mint_*` 系函数生成确定性测试语料，含 roster 规模 2..=8 检查）；「铸造臂」= 负例测试在铸造层构造攻击语料的分支 |
| FOLD_PERF_ONLY | t7 的环境开关：只筛选扫描跑哪些 K 档（读 env 过滤 sizes 数组，t7 测试体 :4-9 实读），**不改变被编译的程序**——program_hash 只覆盖程序、不含 inputs，故 K=1 档实测哈希即全档程序的哈希（钉扎脚本据此取 K=1 出证提取，§3.2） |

---

## 0. 结论先行

**判定：规格 M1–M9 九项定案全部落地，五门禁全绿，评审 1 轮 4 发现全部修复并经工作流复核不再报出（本报告会话对 4 项修复逐一独立复核确认）；单桌退化以重构前金样钉死逐词一致；多桌预算端点 T=8 ΣK=64 实测 409,563 steps（2^20 的 39.06%、余量 2.56×，过 M1-d 门 1.5×）；程序哈希已由 0x02a42b… 重钉为 0x074f0a…（本会话实读 `stark_final.rs:67` 确认在位）。带收尾条件（见 §6）。**

一句话理由：立项三大改面——电路（桌段自定界串接 + 每桌 keyagg/roster_digest + slot16 桌内常量）、host 镜像（FoldTable/多桌 wire/出证后逐桌锚门）、链层（M4-c 三检放宽 + T_MAX run 计数）——均已实现并测试（本会话复跑：hand-verify-native debug 12 个 target 合计 **64 passed / 0 failed / 22 ignored**；stark-recursion lib **40 passed / 0 failed**；scarb build Finished 零 error）；heavy 切片门禁 **20 passed / 0 failed in 44.60s**（【门禁材料】实跑，含 M8 金样 heavy 回放、M9-1a/b/c 三正例、M9-2 四负例/正控、T7 全档扫描）；合约层 snforge **130 passed / 0 failed**（【实施材料】，本会话未复跑 snforge——含 Sepolia fork 测试依赖外网）。跨桌攻击闭合点（M5）两层验证且分级不同：**电路层为本会话/门禁实跑实证**（m9_2a/b panic 无 proof.json——heavy 门禁 20/0 内；host 镜像 m5 本会话复跑 ok），**消费面层为 snforge 材料转引**（合约跨桌 swap 负例测试在库本会话 grep 实证，15/0 运行结果转引未复跑）。**但以下事项未闭合**（详见 §6）：多桌形状笼内复测已于 2026-09-30 四场景补测闭合（§6.1，三门禁全绿）；与全量协议迁移同批评审未做（提案原文要求）；C5/C6 沿袭未开始；工作树未提交（提交由用户执行）；另有一个本报告会话新核出的缺口——**fold_parity 侧 heavy 对拍 t13/t14 不在任何门禁命令面内、本批未跑**（host 形已绿，见 §3.3）。

规格定案落地状态总览（逐项详对照见 §1）：

| # | 定案 | 状态 |
|---|---|---|
| M1 | T 窗口与批预算（ΣK≤64 零政策改动 / K_t≥1 host 拒 / T_MAX=8 双侧落地） | ✅ 完成（host/链层测试本会话复跑绿） |
| M2 | wire 桌段自定界串接、无全局 T 词 | ✅ 完成（电路/host 实读 + m2 测试绿） |
| M3 | 不 pad（否决提案 padding，冲突 MT-1） | ✅ 完成（变宽解析实读；无死词） |
| M4 | D1a 修订：slot16 桌内常量 + chain.rs 三检放宽 + stark_final 零改动 | ✅ 完成（chain.rs 实读；重钉完成） |
| M5 | keyagg/M_h 每桌一次、跨桌闭合点 | ✅ 完成（m9_2 负例 + m5 host 镜像绿） |
| M6 | acc 单次折叠桌序串接、slot0 批终 acc 不变 | ✅ 完成（m4_m6 测试绿） |
| M7 | 合约多桌零改动（实读证实） | ✅ 完成（git 实证 278 增/5 删均注释行号；+4 测试） |
| M8 | T=1 退化金样钉死 | ✅ 完成（金样在库；host+heavy 双臂绿） |
| M9 | 测试矩阵五组 | ✅ 基本完成（t14 heavy 形未跑，见 §3.3） |

---

## 1. 规格定案对照表（M1–M9 逐项：做了什么 / 证据 / 状态）

### M1 T 窗口与批预算

| 子项 | 做了什么 | 证据 | 状态 |
|---|---|---|---|
| M1-a ΣK≤64 且 2 的幂 | **零政策改动**：`check_hand_count`（`chain.rs:163-178`）与 `MAX_HANDS_PER_LEAF=64` 未触碰，多桌批共用同一 ΣK 纪律 | 【实施材料·chain】git diff 仅 chain.rs；既有政策测试 `max_hands_policy_within_trace_floor` 在本会话复跑的 `cargo test -p stark-recursion --lib`（40/0）中 ok | ✅ |
| M1-b K_t≥1（无独立上限） | `FoldTable` 构造器强制 K_t≥1（空桌 Err）；电路侧不检（Q-M2 维持缺省） | `foldagg.rs:397`（`struct FoldTable` 本会话实读符号）+ 测试 `m1b_empty_table_rejected_by_host_constructor`（fold_batch_test.rs:914）在本会话复跑的 debug 门禁中 ok | ✅ |
| M1-c T_MAX=8 | host 层 `FOLD_T_MAX=8`（`foldagg.rs:112` 本会话实读）形状检查先于出证；链层 `MAX_TABLES_PER_FOLD_BATCH=8`（`chain.rs:354` 本会话实读）以 slot16 run 计数批尾断言（:485-487 实读，Err 文案带 T/T_MAX；run 数与 T 的关系见 M4 边界注） | host：`m1c_t_window_rejects_empty_and_over_max_attack_MT5`（:948）本会话实读测试体（T=0 拒含 "T = 0"、T=9 拒含 "T_MAX"、T=8 放行形状检查）+ 复跑 ok；链层：`fold_batch_plan_rejects_table_run_overflow` 本会话实读测试体（9 桌 9 run / 逐手异值 16 run / 两值交错漂移 16 run 三形态均拒）+ 复跑 40/0 中 ok | ✅ |
| M1-d 余量口径 | 多桌验收门 = 实测 steps ≤ 2^20 且余量 ≥1.5×。**门分母 = 2^20 政策地板**（`TRACE_FLOOR_LOG2=20`，`chain.rs:65` 本会话实读；规格 M1-d 钉死该口径，因 ΣK≤64 政策的预算推导以地板为基准）——按 M9-1c 实际落桶 2^19 计，紧桶余量 = 524,288/409,563 ≈ **1.28×**（本会话复算，门不设在紧桶）；「系数 3」= `TRACE_HEADROOM_FACTOR`（`chain.rs:69` 实读，trace 预算安全系数）只服务既有自检（`:67` `MEASURED_STEPS_PER_HAND=5374` 的 settlement 批程序口径），多桌预算不用它；预算模型 steps ≈ Σ_t(404+153·n_t)+6,183·ΣK | 端点实测：**M9-1c T=8 全 8 人 ΣK=64 = 409,563 steps = 2^20 的 39.06%、余量 2.56×**（【门禁材料】heavy 门禁实跑输出 `| M9-1c T=8 ΣK=64 | steps 409563 | margin 2.56x | trace 2^19 | EC_OP 256 | poseidon 4096 |`）；规格模型 408,736 偏差 0.20%（本会话复算）；模型上界（不受 T_MAX 约束的 ΣK=64 全 1 手形状）499,904 = 47.7%、余量 2.10×（【规格】§1 推算值，未实测——该形状超 T_MAX 不可出证） | ✅（端点实测过门） |
| **host 层检查清单（实读，回应 Q-M1 的 host 侧防线内容）** | `check_multitable_shape`（`foldagg.rs:443-468` 本会话实读）只检四项：T≥1、T≤FOLD_T_MAX（:451）、每桌 K_t≥1、锚数==桌数——**不检 ΣK≤64、不检 P_t∈2..=8**。ΣK 政策唯一执行点 = 链层 `check_hand_count`（出证后进链前拒：ΣK>64 的批可先出证、被 `FoldBatchPlan` 拒在链外——分层如实注明）；P_t 2..=8 检查在 **mint 语料铸造层**（`mint_settle_wire`，`foldagg.rs:1041` 实读）与合约注册面（`:1372`）——Q-M1 所指「host 铸侧」即 mint 层 | 出证入口 `prove_fold_batch_multitable`（:821 实读）= 形状检查 → 逐桌铸侧验签 `host_verify_batch`（:837）→ 出证 → 出证后三重门；`m1c` 测试实读并复跑（含 T=8 放行臂） | ✅（防线内容实证在案） |

### M2 wire 布局（桌段自定界串接、无全局 T 词）

| 做了什么 | 证据 | 状态 |
|---|---|---|
| 电路 `fold_batch.cairo` 泛化为外层 cursor 桌循环：`words_len = words.len()`（:146）、`while cursor < words_len`（:163）内逐桌读 `P_t = words.at(cursor)`（:166 运行时变宽解析）、pks 段、`K_t`（:201）、blocks 起点（:202，`block` = 本桌手块游标：自本桌 pks/K 头之后的首手块首址起，每读一手 101 词 `block += HAND_WORDS`，K_t 手读毕后 `cursor = block`（:283）即下一桌段起点）——回到 `while` 条件，`cursor == words.len()` 即终止，截断/越界 ⇒ `at()` 越界 panic 无证明（fail-closed） | 本会话实读 `fold_batch.cairo:83,146,160-163,166,201-202,283`（grep + sed 区段）；头注释 :83 记「cursor 越过本桌 blocks 后 == words.len() 即终止（桌数由 wire 长度自证）」 | ✅ |
| host `foldagg.rs` 逐位镜像：`build_batch_wire_tables`（:557）、`write_inputs_tables`（:632）、`expected_public_output_tables`（:425）、`prove_fold_batch_multitable`（:821，内置逐桌 anchors + T≤FOLD_T_MAX 形状检查 :451-455）；**单桌 `build_batch_wire`/`write_inputs`/`prove_fold_batch` 全部委托多桌核心**（T=1 结构同一，非兼容模式） | 本会话实读符号位置（grep）；T=1 逐词一致由 M8 金样钉死（见下） | ✅ |
| 桌序=wire 序=段序=claims 序；T=1 时逐词等于现行 build_batch_wire | host 单元测试 `m2_multitable_wire_layout_self_delimiting_tables`（fold_batch_test.rs:802）本会话复跑 ok；`wire_layout_matches_circuit_contract` 与 `acc_chain_formula_parity` 两条既有契约测试同批复跑 ok（单桌布局无回归） | ✅ |

### M3 padding 定案：不 pad（冲突 MT-1 裁定）

| 做了什么 | 证据 | 状态 |
|---|---|---|
| **否决提案「padding 至最大桌 size=8」**：pad 词进 roster_digest ⇒ digest≠注册值 ⇒ 合约对照（`poker_dual_settlement.cairo:1508-1513` vs `:1371-1381`）永拒；不进 digest ⇒ 无约束死词 + 每桌多付 (8−n_t)×153 steps。定案不 pad，电路保持既有变宽解析（P 本就是运行时读） | 本会话实读 `fold_batch.cairo:166`（`n_players = (*words.at(cursor)).try_into().unwrap()`——运行时读人数，无等宽假设）；wire 全程无 pad 词（m2 布局测试钉词数 = 2+2P_t+101K_t 逐桌串接） | ✅ |
| 形状负例兜底：截断/K_t=0/span_len 不符（M9-3） | `m9_3a_truncated_tail_wire_rejected`（:1273）、`m9_3c_span_len_mismatch_rejected`（:1292）；K_t=0 由 m1b 承载（M1-b 定案即 host 层）。m9_3a/c 为 `#[ignore]` unchecked 出证臂，在【门禁材料】heavy 门禁 20/0 中通过；【实施材料·circuit】另记 m9_3c 手动复跑 prove-hand 探针确认 span ±1 双向均为 VM 内 `at()` 越界 ASSERT_EQ 失败 | ✅ |

### M4 D1a 修订：slot16 批常量 → 桌内常量

| 子项 | 做了什么 | 证据 | 状态 |
|---|---|---|---|
| 电路侧 | 17 词段布局不动（index 16 = 本桌 roster_digest）；roster_digest 每桌算一次、桌内段复制（【实施材料·circuit】：「桌循环内每桌一次 roster_digest/keyagg」） | 电路桌循环实读（§M2 证据行）；段布局钉在 m2/m4_m6 测试 | ✅ |
| chain.rs 三检放宽 | ① slot0 acc 批常量**不动**（`chain.rs:442-450` 实读；Q-1 = 前批规格定案「批终 acc 复制到全部段 slot0，使每手段独立成 fact 都钉住整批链状态」，此检查即其批常量断言）；② slot16 逐手非零**不动**（:452-459 实读）；③ slot16 批同值 → **run 分组**：段序极大同值 run 计数 `table_runs`，批尾断言 ≤ `MAX_TABLES_PER_FOLD_BATCH`（:460-490 实读，注释明记「旧跨批同值 match 分支按规格删除：手间不一致不再批拒（那是合法的换桌边界）」） | 本会话实读 `chain.rs:440-490` 全段 + `cargo test -p stark-recursion --lib` 复跑 40/0（含新旧两测试）。**边界（如实注明）**：相邻两桌 roster_digest 相同（同 roster 开两桌进同批）时极大同值 run 合并、run 数 < T——「run 数 = 桌数」仅相邻桌 digest 互异时为恒等式，链层 run 计数在该边界下是 T 的**下界**（可少计）；T≤8 的硬拒点在 host 形状检查（知真实桌数 `tables.len()`，`check_multitable_shape:451` 实读），链层计数属评审面政策的尽力面、非 soundness 面（同 digest 两桌的手段仍逐手验签、各自对照合约注册面）；新负例的 9 桌语料为互异 digest（`fold_multitable_hands` 每桌加盐派生，chain.rs 实读），该同 digest 相邻边界无专项测试 | ✅ |
| stark_final.rs 零改动 | `parse_fold_final_output` 只检形状、本就无 roster 一致性检查；唯一触碰 = 重钉哈希（§4） | 【实施材料·chain】git diff 实证本会话未编辑该文件函数体；本会话实读 `FoldFinalOutput` 文档（stark_final.rs:236-239）已改为「word 16 = roster_digest **桌内常量**——规格 D1a 多桌修订…跨桌可异」（评审发现 3 的修复在位） | ✅ |

### M5 keyagg 与 M_h：跨桌攻击闭合点

| 做了什么 | 证据 | 状态 |
|---|---|---|
| keyagg 每桌一次：μ = poseidon([KEYAGG_LABEL, **n_t**, pkx, pky])（n 槽取本桌 P_t）——同 pks 集不同人数 ⇒ μ 不同，跨桌签名复用再堵一层 | 本会话实读 `fold_batch.cairo:186`：`array![KEYAGG_LABEL, *words.at(cursor), pkx, pky].span()`——n 词即 cursor 处本桌 P_t；host 镜像 `key_coeff_raw(n_players,…)`（`foldagg.rs:122-124`，【规格】§5 引） | ✅ |
| M_h 公式不动、含本桌 roster_digest（槽序与标签零改动，T8 KAT 钉值不触碰）；c 同时含 M_h 与本桌 P̄_t ⇒ 桌 A 手配桌 B roster ⇒ M_h/c 变 ⇒ 方程 z̄·G−c·P̄_B−R̄_A≠O ⇒ `RESIDUAL_NOT_IDENTITY` panic | 闭合链推导见【规格】§5（引 `fold_batch.cairo:208-214,228-237`）；**运行实证** = m9_2a/b 电路臂（§3）+ m5 host 镜像（精确断言 `RESIDUAL_NOT_IDENTITY`，fold_batch_test.rs:882，本会话复跑 ok）；T8 KAT 测试 `t8_kat_labels_mu_mh_c_pinned_attack_T8` 复跑 ok（公式未漂移） | ✅ |
| 消费面第二重：合约逐手段独立对照 segment[16] vs roster_registry | snforge 负例 `fold_multitable_cross_table_roster_swap_reverts`（`poker_dual_settlement.cairo:2665` 本会话 grep 实证在库）——【实施材料·contract】15/0 实跑 | ✅（snforge 结果材料转引） |

### M6 acc 链：单次折叠桌序串接

| 做了什么 | 证据 | 状态 |
|---|---|---|
| 跨桌 claims 按桌序串接后仍**单次折叠** acc=poseidon([prev_acc]++claims)；批终 acc 复制全段 slot0（Q-1 语义不变）；不引入逐桌分段折叠；claim 含 M_h 天然带桌色 | host 单元 `m4_m6_multitable_anchors_shared_acc_table_digests`（fold_batch_test.rs:833）本会话复跑 ok（全部段 slot0 同值 == fold_acc(桌序串接 claims)、seg[16]==本桌 digest 两桌各异）；`acc_chain_formula_parity` 既有公式测试复跑 ok；chain.rs slot0 批常量检查不动（§M4 证据） | ✅ |

### M7 合约判定：多桌零合约改动

| 做了什么 | 证据 | 状态 |
|---|---|---|
| **零合约逻辑改动**，据【实施材料·contract】逐行实读判定（消费路径 `:1479-1513`、注册面 `:1364-1389`、fact 吸收 `:335-344` 均该会话实读转引）：fold 入口一次调用只吃一段 17 词且 `segment.at(16)` 逐手对照 registry；`register_roster` 每次一桌、registry 支持任意多 digest；`fact_for_segment` 逐词吸收长度无关；`fold_program_hash` 全局单值；`BatchStatement` 三字段无桌字段（`groth16-wrap/src/batch.rs:29-33`）——不存在必需最小改动面。本报告会话独立复核：git diff（下行）+ sed 复读入口 `:1479-1495`（一次调用一段 17 词、binding 幂等门、段长检、MAGIC 检在位） | 本会话实跑 `git diff --numstat -- poker_contracts/src/poker_dual_settlement.cairo` → **278 增 / 5 删**；5 条删除行逐条核验**均为注释内过期行号更新**（`git diff` 删除侧 grep：全部是 `fold_batch.cairo:67`/`:66-67` 行号引用的注释改写，无逻辑行）——合约逻辑零改动、编辑纯插入 | ✅（git 实证 + 入口复读；:335-344/:1364-1389 为材料实读转引） |
| 在 `settlement_fold_private_tests` 模块新增 4 测试 + 3 helper：两桌（n=2/n=3）各自注册后同批三手段交错结算正例（slot0 同批终 acc、事件各携本桌 digest）、未注册第三桌 fact 齐备仍拒、桌 A 段尾词换桌 B digest 跨桌 swap 被 fact 门拒、combined+fold 同合约共存回归 | 本会话 grep 实证 4 测试在库（`poker_dual_settlement.cairo:2553/2648/2665/2687`）；snforge `settlement_fold_private_tests` → **15 passed / 0 failed**（11 既有 + 4 新增）、snforge 全量 → **130 passed / 0 failed**（129 src + 1 tests/，combined 模块 5 测全过）——【实施材料·contract】实跑，本会话未复跑 snforge（fork 测试依赖外网 RPC） | ✅（测试在库实证；snforge 结果材料转引） |

### M8 单桌退化回归（T=1 金样）

| 做了什么 | 证据 | 状态 |
|---|---|---|
| 重构前以临时捕获测试经**现行生产路径**出证落库金样 `tests/golden/fold_t1_p2k2.json`（wire 208 词 + 2×17 段 + acc/digest；捕获时 PANIC 探针同时实测 stderr 无 felt panic 标签）；捕获后临时测试已删 | 本会话 `ls` 实证文件在库（18,532 B，2026-09-30 16:43）；`head` 实读内容：`cairo_acc = 0x0512d75d27e15662…`、provenance 字段原文「pre-multitable production path prove_fold_batch, P=2 K=2 seed=0xFA17+0x5EED, prev_acc=0」 | ✅ |
| 重构后双层断言：host 单元 `m8_t1_wire_matches_pre_multitable_golden`（:779，wire 逐 hex）+ heavy `m8_t1_golden_roundtrip_heavy`（:978，段/acc/digest 逐 felt + verified） | host 臂本会话复跑 ok（debug 17/0 内）；heavy 臂在【门禁材料】heavy 门禁 20/0 中 ok，输出 `| M8 T=1 golden | steps 12347 | acc 0x0512d75d27e15662 | digest 0x0517777ae1826362 |`（输出行只印 16 位截断）。金样完整值（本会话 python 实读）：`cairo_acc = 0x0512d75d27e15662b9a23efcac93d3d73f05ef9be44a1d54833edbec3b48795a`；结构 = wire 208 词 + 2 段×17 词——输出截断值与全值前缀一致，**完整逐 felt 相等由 m8_t1_golden_roundtrip_heavy 测试断言并在 heavy 门禁通过**（此前报告层只比前缀的原因即门禁输出截断，特此补全值） | ✅ |
| steps 与 program_hash 不进金样（steps 走 T7 门、哈希走钉扎脚本） | 金样字段实读（cairo_acc/provenance/public_output——无 steps/hash 字段）；T7 与重钉结果见 §4 | ✅ |

### M9 测试矩阵五组

| 组 | 落地 | 证据 | 状态 |
|---|---|---|---|
| M9-1 T≥2 正例 | (a) T=2 不同人数（8×8+2×8）、(b) T=2 同人数不同 roster（8×4+8×4）、(c) T=8 ΣK=64 预算拼批。**记法 P×K（人数×手数）**：8×8+2×8 = 桌1 8 人 8 手 + 桌2 2 人 8 手（m9_1a 语料 `honest_table(8,8)+honest_table(2,8)`，测试断言 `table_players=[8,2]`/`table_hands=[8,8]`/ΣK=16——本会话实读测试体）；8×4+8×4 = 两桌各 8 人 4 手 | heavy 门禁 20/0 全过（【门禁材料】输出：M9-1a **98,685** steps / trace 2^17 / EC_OP 64 / poseidon 512；M9-1b **52,885**；M9-1c **409,563 / margin 2.56×**）；预算模型复核：m9_1b 模型 52,720 vs 实测 52,885（偏差 0.31%，本会话复算）、m9_1a 模型 101,266 vs 实测 98,685（偏差 ≈2.6%，本会话复算——【实施材料】「~2% 内」口径对 (a) 略乐观，如实注明）、m9_1c 偏差 0.20% | ✅ |
| M9-2 跨桌攻击负例 | m9_2a（换桌 roster）/m9_2b（跨桌重放）电路 panic 臂 + m9_2c（换桌锚）parity 门臂 + m9_2d 正控 | 详 §2.2/§2.3；heavy 门禁 20/0；m9_2c 本会话实读测试体（:1205-1223）三断言 | ✅（拒因钉法偏离规格原文，见 §2.3 与 §4 偏离 3） |
| M9-3 padding/形状负例 | 截断（m9_3a）/K_t=0（m1b host 层）/span_len 不符（m9_3c ±1 双向） | heavy 门禁 20/0；【实施材料·circuit】手动 prove-hand 探针双向确认 | ✅ |
| M9-4 T 窗口负例 | host 层 T=0/T>8（m1c）；链层 run 溢出三形态；ΣK>64/非 2 幂/空批 = 既有三检零改动 | m1c + `fold_batch_plan_rejects_table_run_overflow` 本会话实读测试体并复跑绿；`fold_batch_plan_rejects_bad_shapes` 复跑绿（实读含空批拒、16 词拒、K=3 非 2 幂拒等既有臂；**ΣK>64 未新增专测**——拒绝面 = `check_hand_count` 零改动，由既有政策测试承载，如实注明） | ✅ |
| M9-5 对拍扩展 | (a) fold_parity 多桌 host 臂（桌锚）；(b) 合约层两桌正例 + 跨桌/未注册负例；(c) T=1 金样回归 | (a) host 形 `fold_multitable_parity_two_tables_host`（fold_parity_test.rs:396）本会话复跑 ok；**heavy 形 t14 未跑**（§3.3）；(b) 见 M7 行；(c) 见 M8 行 | ⚠️ (a) heavy 形缺位 |

---

## 2. 跨桌攻击面与负例结果

### 2.1 闭合结构（两层，规格 M5/M7）

- **第一重（电路内，出证时）**：c = poseidon([SIG_LABEL, hand_binding, M_h, P̄_x, P̄_y, R̄]) 同时含 M_h（内含本桌 roster_digest_t）与本桌聚合公钥 P̄_t。桌 A 的手配桌 B 的 roster 头 ⇒ digest 变 ⇒ M_h 变 ⇒ c 变 ⇒ 残差方程 z̄·G−c·P̄_B−R̄_A ≠ O ⇒ 电路 panic、无证明。μ 的 n 槽取本桌人数（`fold_batch.cairo:186` 实读）使「同 pks 不同 n_t」的签名复用也在此层被堵。
- **第二重（消费面，结算时）**：合约 fold 入口逐手段独立对照 `segment.at(16)` vs `roster_registry`（`poker_dual_settlement.cairo:1508-1513`）——即使某幻影证明通过，未注册 digest 即 revert；跨桌重放同 binding 由 `settled_bindings` 幂等门拒绝。

### 2.2 负例矩阵（全部活跃，`_attack_MT*` 标签防语义漂移）

| 负例 | 拒绝面 | 拒因实证 | 复核级别 |
|---|---|---|---|
| m9_2a（_attack_MT1 换桌 roster：桌 A 手 + 桌 B pks 头，桌 A 段诚实） | 电路 panic，无 proof 产出 | 本会话实读测试体（fn :1149、三断言 :1163-1166）：`err.contains("circuit rejected")` + `assert_circuit_assert_rejected(&err)`（钉「An ASSERT_EQ instruction failed」VM assert 形态）+ `!dir.join("proof.json").exists()`；经裸出证入口 `prove_fold_batch_unchecked_tables`（foldagg.rs:773-784 实读：落 inputs 直跑 prove-hand，**绕过**形状检查、逐桌铸侧验签 host_verify_batch 与出证后三重门——故拒绝只能来自电路本身）；heavy 门禁 ok | 测试体实读 + 门禁材料 |
| m9_2b（_attack_MT2 跨桌重放：桌 B 手携桌 A (R̄,z̄)） | 电路 panic（c 变） | fn :1173（本会话 grep 实证，紧接 m9_2a 之后独立测试），同款三断言、同走 `prove_fold_batch_unchecked_tables`；heavy 门禁 ok | 同上 |
| m9_2c（_attack_MT3 换桌锚正控：诚实两桌出证后 anchors.reverse()） | **出证后** parity 门 Err | 本会话实读测试体（:1205-1223）：三断言 = `err.contains("roster digest parity failure")` + `err.contains("table 0")`（失败带桌序号）+ `dir.join("proof.json").exists()`（**钉成磁盘实证**：拒绝发生在出证后、proof.json 已落盘） | 测试体实读 + 门禁材料 |
| m9_2d（正控：诚实两桌 wire 过 m9_2a/b 同一裸出证入口 `prove_fold_batch_unchecked_tables`） | ——必须**成功出证**；同语料 z̄+1 必须 panic | 双向活跃性：排除「两桌 wire 一律失败」的假阳性（即证该入口无隐性过滤、m9_2a/b 的拒绝确属电路；T11/T12 的多桌对应物）；【实施材料·tests】磁盘核查：m9-2d-honest 目录 proof.json 存在、m9-2d-zbar 无 proof.json；heavy 门禁 ok | 门禁材料 + 实施材料 |
| m5_cross_table_mix_host_equation_rejects_attack_MT1（host 镜像） | host 公式层，**对 soundness 零证明力**（文件内已标注） | 两臂均精确断言 `RESIDUAL_NOT_IDENTITY`（【实施材料·circuit】引 :842-869）——补足电路臂无法上浮的**标签级**拒因验证；本会话复跑 ok | 本会话复跑 |
| 合约：桌 A 段尾词换桌 B digest | fact 门拒（digest 变 ⇒ fact 变 ⇒ 未登记） | snforge `fold_multitable_cross_table_roster_swap_reverts`（:2665 在库实证）——【实施材料·contract】15/0 | 在库实证；snforge 材料转引 |
| 合约：未注册第三桌（fact 齐备） | roster 对照拒 | snforge `fold_multitable_unregistered_third_table_reverts`（:2648） | 同上 |

### 2.3 「panic 标签进不了失败文案」的实证与钉法（重要边界）

prove-hand 出证栈对电路 panic 的 stderr **只含** `An ASSERT_EQ instruction failed: 0 != 1`（felt 标签不解码；重构前 z̄+1 探针与金样捕获时 PANIC 探针两次实证——【实施材料·circuit/tests】）。因此规格 M9-2「断言失败文案含电路 panic 标签（如 RESIDUAL_NOT_IDENTITY）」**在本出证栈不可实现**，负例拒因改为三层钉法：`circuit rejected` 前缀 + `assert_circuit_assert_rejected`（VM assert 形态，辅助函数 :148-154 本会话实读，doc 注明「panic label itself cannot surface on this proving stack」）+ 无 proof.json 落盘；**标签级验证由 host 镜像 m5 承载**（公式镜像同 panic 路径，精确断言 RESIDUAL_NOT_IDENTITY）。

---

## 3. 门禁与哈希重钉结果

### 3.1 五门禁

| 门禁 | 命令 | 结果 | 复核级别 |
|---|---|---|---|
| debug 全量 | `cargo test -p hand-verify-native` | **12 个测试 target 全部 0 failed，合计 64 passed / 22 ignored**（枚举：lib 30 / main 2 / empty_batch 1 / **fold_batch_test 17 passed + 20 ignored** / fold_formal_props 12 / **fold_parity_test 2 passed + 2 ignored** / combined_perf、combined_test、compose_test、perf、recurse_test、Doc-tests 各 **0 个测试被执行**——0 passed / 0 failed / 0 ignored，target 在库但无默认门禁测试，非「有测试 0 失败」） | ✅ **本报告会话复跑**（与【门禁材料】记录一致；【实施材料·circuit】中期记录 63 passed/19 ignored 为 m9_2d 与 parity host 臂加入前的态，以终态为准） |
| heavy 切片 | `cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture` | **20 passed / 0 failed in 44.60s**（17 filtered out）：T1 三档、T2/T3/T5/T6/T9/T10/T11/T12 既有臂、T7 全档（K=1/8/32/64 = **7,897 / 51,254 / 199,922 / 398,146**）、M8 金样 heavy、m9_1a/b/c、m9_2a/b/c/d、m9_3*。**T 系 12 条中 T4/T8 不在 heavy 集**：T4 = host 公式对拍 `t4_host_…`、T8 = KAT 标签钉值 `t8_kat_…`，均 debug 级测试，在本会话复跑的 fold_batch_test 17 passed 内 ok——heavy 名单因此无 T4/T8，非缺漏 | 【门禁材料】实跑，本会话未复跑 release 出证 |
| 链层 | `cargo test -p stark-recursion --lib` | **40 passed / 0 failed**（含新增 `fold_batch_plan_multitable_two_tables_builds`、`fold_batch_plan_rejects_table_run_overflow`，及未改的 `fold_batch_plan_k2_builds_and_roots` 单桌回归 / `fold_final_output_statements_and_pinning` 钉扎测试） | ✅ **本报告会话复跑** |
| 合约编译 | `env PATH=/Users/mac/.local/opt/toolchains/scarb-2.19.4/bin:… scarb --manifest-path …/Scarb.toml build`（scarb 2.19.4 / cairo 2.19.4） | **Finished dev profile，零 error**；warning 本会话复跑实点 = **10×E2066**（corelib deprecated import，文件位于本批未触碰的 hand_batch.cairo / keccak.cairo / secp256k1_verifier.cairo——git status 实证 `poker_contracts/src/` 下仅 poker_dual_settlement.cairo 被修改）+ **24×E2100**（unused import）。「均非本次引入」的判定基线（如实写明）= ① 本批合约 diff 纯插入中 **0 条 `use` 行**（git diff grep 实证）⇒ 新增代码无引入 unused import 的路径；② E2066 所在文件零触碰（上行）；③ 与【前批报告】§2.1 记录的同款 warning 清单及【门禁材料】输出一致 | ✅ **本报告会话复跑**（命令同门禁原文；warning 计数为复跑实测） |
| 程序哈希重钉 | `bash scripts/pin_fold_program_hash.sh` | K=1 真出证（FOLD_PERF_ONLY=1 跑 t7，7,897 steps 过验收线）→ 实测 program_hash = `0x074f0a7f4f082590a4ffb9f929c9fd47dbc131cdb18dc9f5d659105c4b280299` == 钉值，**幂等无操作**（脚本判定「程序源码与上次发布一致」） | 【门禁材料】实跑；本会话实读 `stark_final.rs:67` 确认钉值在位 |

未入五门禁但在材料内实跑的：snforge 全量 **130 passed / 0 failed**（总数口径：129 src + 1 tests/ = 130；combined 模块 5 测 ⊂ 129 src 之内）与 `poker_contracts_integrationtest` Sepolia fork 测试（Latest block 15861106，首跑即过）——【实施材料·contract】，本会话未复跑。**snforge 与重钉的时序**：【实施材料】未记录 snforge 运行时间戳，其与重钉写入（0x074f0a… 落 stark_final.rs:67）的先后不可定；但该结果对钉扎值**零依赖**——合约测试自注测试哈希（`dual.set_fold_program_hash(FOLD_HASH)` / `0x99`，`poker_dual_settlement.cairo:2252/:2392/:2493` 本会话 grep 实证），Rust 侧钉扎常量对 Cairo 测试不可见，时序不影响其证明力。`cargo clippy -p stark-recursion --lib` 12 warnings 全在会话前既有位置（【实施材料·chain】）；`cargo build -p hand-verify-native` 0 error / 0 unused-dead 警告（【实施材料·circuit】）。

**运行环境（如实记录）**：门禁、实施会话与本报告会话共用同一工作副本所在本机——本报告会话 `uname -sm` = **Darwin arm64**（darwin 24.3.0）；【门禁材料】未单独记录机器规格，heavy 44.60s 即此环境口径。「本机实测」（M9-1c steps 等）同此。与笼内环境（【前批报告】§5.3：阿里云 Linux x86_64、4 vCPU / 7.3G、cgroup 5200M）**不可直比时长与内存**；steps 为确定性量可跨环境直比（前批笼内与本机 K=64 steps 逐字一致即为先例），Q-M3 待补的 RSS/MemoryCurrent 复测必须回到笼内基准。

### 3.2 哈希重钉时间线（评审发现 1 的闭合）

1. 前批钉值 `0x02a42b516184d923ebddb0c3cf1221d62faa380e86a9592709657fbc85e6ba54`（单桌生产程序，a87f5bb1 时代落库）。
2. 本批多桌改造触碰 `fold_batch.cairo` ⇒ 程序哈希必换（钉扎纪律：改电路后必须重钉）。
3. 【评审材料】发现 1（**medium**）：钉扎过期——钉的是旧程序，多桌版实际编译哈希为 `0x74f0a7f4…`（评审实跑 m8 heavy 的 summary 取证：program_hash=0x74f0a7…、steps=12347、verified=true；时间线 stat 佐证钉扎写入早于电路最后一次改动）。影响面：`fold_batch_program_hash()` 将返回幻影程序哈希，部署即成事实（owner 会把过期哈希上链）。
4. **修复**：重跑 `scripts/pin_fold_program_hash.sh` → 钉为 `0x074f0a7f4f082590a4ffb9f929c9fd47dbc131cdb18dc9f5d659105c4b280299`（【钉扎材料】before/after；评审发现写法 63 位 `0x74f0a7…` 与钉值 64 位 `0x074f0a…` 为 zfill 归一化的同一值）。
5. **复核**：门禁复跑脚本幂等无操作（实测==钉值）；本报告会话实读 `stark_final.rs:67` 确认 `FOLD_BATCH_PROGRAM_HASH_HEX = "0x074f0a…280299"` 在位，且 fail-closed 断言（:217-218）与钉扎两态测试（:644）随 40/0 复跑绿。

### 3.3 steps 漂移与 t13/t14 缺口（如实记录）

- **steps 簿记漂移**：桌循环簿记使单桌 steps 小幅变化——K=1：7,859→**7,897**、K=64：397,415→**398,146**（【门禁材料】T7 表 vs【前批报告】T7 记录）。
- **T7 验收门口径（可自行验算，测试体本会话实读 fold_batch_test.rs:700-714）**：① K=1 门 = `s1 ≤ COMBINED_PER_HAND_STEPS + KEYAGG_STEPS_ANCHOR` = **12,160 + 1,628 = 13,788**（12,160 = combined 9 人每手整证基线，`foldagg.rs:692` 常量；1,628 = keyagg+roster 批固定层 404+8×153，`:696` 常量、注释明记「批固定层只付一次」）；② 边际门 = `(档 steps − K=1 steps) / (K−1) ≤ 12,160`（整数除法，`:706`）——「边际」= 相对 K=1 的每增量手 steps；③ 全档 steps ≤ 2^20。实测：K=1 = 7,897 ≤ 13,788 ✓；K=64 边际 = (398,146−7,897)/63 = **6,194** ≤ 12,160 ✓（本会话由门禁 T7 表数字复算；【实施材料·circuit】所记「边际 6,198」**无法由终态门禁数字复算**——各档差商均为 ≈6,193–6,195，疑为中间构建态记录，如实注明）；全档 ≤ 2^20 ✓（最大 398,146）。门全过由 heavy 门禁 20/0 承载。steps/program_hash 按规格 M8.3 不进金样。
- **t13/t14 heavy 对拍未跑（本报告会话核出的缺口）**：heavy 门禁命令只覆盖 `--test fold_batch_test`；`fold_parity_test` 的 2 条 `#[ignore]`（t13 单桌 combined 对拍 heavy、**t14 多桌对拍 heavy**）不在任何门禁命令面内，【实施材料·tests】明示开发会话未跑（开发纪律只跑单用例迭代）。缓解：t14 的断言面（段 word1..=15 对 host expected_segment、seg[16]==本桌锚、slot0==共享批终 acc）已由 fold_batch_test 的 `assert_multitable_outcome` 在 m9_1a/b/c 三正例覆盖（heavy 门禁 20/0 内）；缺的是「同语料 combined 腿 + fold 腿多桌一批」的双链对拍形态，且 combined 腿行为本批零功能改动。host 形 `fold_multitable_parity_two_tables_host` 本会话复跑 ok。

### 3.4 评审轮总结

1 轮修复、4 发现（1 medium + 3 low）、`stillOpen` 为空：【评审材料】。本报告会话对 4 项修复逐一独立复核——发现 1（重钉）见 §3.2 实读；发现 2（fold_parity 多桌泛化缺位）→ `fold_multitable_parity_two_tables_host` 在库（fold_parity_test.rs:396）且本会话复跑 ok；发现 3（stark_final.rs:236 注释陈旧）→ 实读已改「桌内常量——规格 D1a 多桌修订」；发现 4（m9_2a/b 拒因未钉）→ 实读测试体已为三层钉法（§2.3）。

---

## 4. 与提案/规格的偏离

**裁定性偏离（规格 §0 冲突裁定，按「以代码为准」执行）**：

1. **MT-1 否决提案 padding**：「公开输入 +T 个 roster_digest…padding 至最大桌 size=8」（proposal:254）按代码现实否决——pad 词进 digest 则合约对照永拒、不进则是无约束死词 + 每桌多付 (8−n_t)×153 steps；连带否决 T 前缀两段式头（破坏 T=1 wire 逐词一致）。
2. **MT-2/MT-3 证实提案**：「每桌一次聚合验证（常数）」属实（404+153·n_t 每桌一次）；「SettleBatch 零改动」证实（`BatchStatement` 无桌字段）。

**实现期对规格原文的偏离（均有实测依据）**：

3. **M9-2「失败文案含电路 panic 标签」不可实现**：panic 载荷不进 VM 错误文案（两次探针实证），负例拒因改为三层钉法 + host 镜像标签级验证（详 §2.3）——与既有 T2/T3/T6/T11/T12 同标准。
4. **Q-M1/Q-M2/Q-M4 实现期定案**：Q-M1 维持现状（电路不加 2≤P_t≤8 断言，闭合仍在合约注册面与 host 铸侧）；Q-M2 维持缺省（电路不拒 K_t=0，仅 host 构造器拒，无 soundness 影响）；Q-M4 只做 host 单元臂（key_coeff_raw/agg_pubkey 的 n_t 判别），heavy 铸造臂未做。
5. **金样 fixture 超出三个指名文件**：新增 `tests/golden/fold_t1_p2k2.json` 属 M8 测试适配的必要落库件（规格明示 checked-in golden），在此披露。
6. **单桌退化行为差异**：单桌空手批（K=0）现于 FoldTable 构造器返回 Err（原实现在出证后 segments[0] 索引 panic）——fail-closed 语义不变；正常路径 T=1 输出经金样钉死逐词一致。
7. **M9-3(b)/M9-4(d) 覆盖层次**：K_t=0 与 T>8 在电路侧测试文件覆盖为 host 构造器/prove 入口/形状检查层（M1-b/c 定案即 host 层）；heavy 端点未裁剪（参照系：实施范围允许仿 `FOLD_PERF_ONLY` 把 heavy 用例裁到单档以省出证时间——实际未裁，M9-1c 保留 T=8 ΣK=64 全档出证并实跑通过）。
8. **链层「桌内 roster 漂移拒」的实现形态**：`FoldBatchPlan` 收到的是无桌边界的平铺段列表，规格 M4-c 明示「真正的桌内常量已上移为电路结构事实，host 层不再重复断言」——本层唯一可拒形态是 run 数 > T_MAX（16 run 交错/逐手异值/9 桌三形态测试），非语义加强。
9. **旧负例 `fold_batch_plan_rejects_bad_shapes` 的 roster_drift 分支删除**：按规格 M4-c「删 :443-451 跨批同值断言」执行（:443-451 为**规格行文时删除前的旧坐标**——删除动作发生后该区即现行 chain.rs:440-490 实读段，两坐标系差异注明，对照代码时勿混用）——[A,B] 两手不一致从「拒」转为「合法两桌批」正例语义，拒绝面收窄由新 run 溢出负例补上（测试体实读注释在案），非为过测试而删测试。
10. **T_MAX 常量命名**：链层命名 `MAX_TABLES_PER_FOLD_BATCH`（规格只钉值 8 未钉名；沿用 `MAX_HANDS_PER_LEAF`/`MAX_LEAVES_PER_TREE` 惯例）。
11. **rustfmt/fmt 现状**：两测试文件与全仓均不满足默认 rustfmt（无 fmt 门、历史提交即此风格），本次未做全文件重排以免污染 diff；新增代码按各文件既有风格书写。cairo 侧 `cargo fmt --check` 同理为全仓既有风格不齐（【实施材料·circuit】）。

**过程与范围如实记录**：

12. **stark_final.rs 的会话前遗留**：工作树中该文件的钉扎常量（0x02a42b…）与测试清理为上一会话遗留、非本批所改；本批唯一触碰该文件的动作 = 经钉扎脚本重钉哈希一行（§3.2）。`poker_dual_settlement.cairo` 的 5 条删除行为会话开始前工作树已有的注释行号更新（【实施材料·contract】核对），本批编辑纯插入。
13. **开发中顺带实证（非规格项）**：M9-1a/b 的 98,685 / 52,885 steps 与预算模型吻合（(b) 0.31%、(a) ≈2.6%——本会话复算，「~2% 内」的材料口径对 (a) 略乐观，如实注明）。
14. **并行分工边界**：ΣK/2 幂/空批政策在 chain.rs（由链层实现员承载、零改动）；电路/host/测试/合约四路由不同实现会话并行完成，最终工作树为合并态——与【前批报告】§3.12 同型的并行合并记录。

---

## 5. 证据分级

| 级别 | 内容 |
|---|---|
| **本报告会话实跑**（命令见附录 A） | 门禁组：`cargo test -p hand-verify-native`（12 target 合计 **64 passed / 0 failed / 22 ignored**）、`cargo test -p stark-recursion --lib`（**40 passed / 0 failed**）、`scarb build`（PATH 前置 scarb 2.19.4，**Finished dev profile 零 error**）。git 对照组：`git status --porcelain`（8 修改 + 5 未跟踪）、`git branch --show-current`/`git log`（feat/prove_perf @ a87f5bb1）、`git diff --numstat`（合约 **278 增/5 删**；fold_batch.cairo 184/145、foldagg.rs 353/101、fold_batch_test.rs 657/11、fold_parity_test.rs 403/3、chain.rs 183/34、stark_final.rs 15/13）、合约 5 删除行逐条核验均为注释行号更新。符号/布局组（grep/sed 实读）：`stark_final.rs:67` 钉值 `0x074f0a…` 在位 + :217-218 fail-closed + :236-239 桌内常量注释；`chain.rs:354/:440-490`（三检放宽 + run 计数 + T_MAX 断言）；`foldagg.rs:112/:397/:425/:451-455/:557/:632/:821`（FOLD_T_MAX/FoldTable/多桌四函数）；`fold_batch.cairo:83/:146/:160-163/:166/:186/:201-202/:283`（cursor 桌循环 + 每桌 keyagg n 槽）；测试体实读：m9_2a 三断言、m9_2c 三断言、`assert_circuit_assert_rejected` 辅助 :148-154、m1c（T=0/T=9/T=8）、`fold_batch_plan_rejects_table_run_overflow` 三形态、`fold_batch_plan_rejects_bad_shapes` 既有臂；金样文件 ls + python json 实读（完整 `cairo_acc`、wire 208 词、2 段×17 词结构）；4 条合约多桌测试 grep 在库（:2553/:2648/:2665/:2687）；heavy 门禁输出的 M9-1c/409,563/2.56× 与 M8 acc `0x0512d75d27e15662` 对金样完整 `cairo_acc` 前缀比对；预算模型复算（m9_1a/b/c 偏差 2.6%/0.31%/0.20%）；T7 验收门测试体与常量实读（fold_batch_test.rs:701/:706、foldagg.rs:692/:696）+ 边际复算；host 检查清单实读（`check_multitable_shape` foldagg.rs:443-468、`mint_settle_wire` 2..=8 :1041、`prove_fold_batch_unchecked_tables` :773-784、入口逐桌 `host_verify_batch` :837）；chain.rs 常量实读（`TRACE_FLOOR_LOG2=20` :65、`MEASURED_STEPS_PER_HAND=5374` :67、`TRACE_HEADROOM_FACTOR=3` :69）；合约入口 sed 复读（poker_dual_settlement.cairo:1479-1495）+ 测试自注哈希 grep（:2252/:2392/:2493）；钉扎脚本逻辑实读（scripts/pin_fold_program_hash.sh:33-55——zfill 64 归一 + 钉值字符串等值比较，「程序源码与上次发布一致」为哈希相等的解读文案）；scarb build warning 实点（10×E2066 + 24×E2100）+ 合约 diff 新增 `use` 行 = 0；`uname -sm` = Darwin arm64；Lean 依赖 grep（见未验证清单）；m9_2a/m9_2b 精确行号（fn :1149/:1173、三断言 :1163-1166） |
| **工作流门禁实跑（【门禁材料】转引，本会话部分复跑）** | heavy 切片 **20 passed / 0 failed in 44.60s**（T7 全档 7,897/51,254/199,922/398,146、M8 heavy、m9_1a/b/c、m9_2a/b/c/d、m9_3*）；`bash scripts/pin_fold_program_hash.sh`（实测==钉值幂等无操作）；debug 全量与链层两门本会话已复跑（上行）；合约编译门本会话已复跑（上行） |
| **实施会话实跑（【实施材料】转引，本会话未复跑）** | snforge `settlement_fold_private_tests` 15/0 与全量 130/0 + Sepolia fork（block 15861106）；`cargo clippy -p stark-recursion --lib`（12 warnings 全在会话前位置）；`cargo build -p hand-verify-native`（0 error）；m9_3c 手动 prove-hand 探针（span ±1 双向 VM 越界）；m9_2 系磁盘证据核查（m9-2a/b 目录无 proof.json、m9-2c proof.json 15MB + summary verified:True）；**金样捕获时 PANIC 探针**——捕获测试同时在 stderr 断言无 felt panic 标签（证明捕获语料的出证路径干净、金样非 panic 产物）；**output 目录 tag 全量审计**——grep 清点两测试文件全部 `out_dir("…")` 输出目录标签共 33 处，确认单桌既有测试与多桌新测试不共用输出目录（防产物互相覆盖导致的假阳性/误读旧产物）；`grep -rn 'slot 16 非批常量…'` 无残留引用 |
| **评审会话实跑（【评审材料】转引；修复结论本会话独立复核）** | 4 发现的证据命令（m8 heavy summary 取证 0x74f0a7…/12347、mtime 时间线 stat、grep fold_parity_test 无多桌命中、断言面实读）；修复后复核未再报出 + stillOpen 空——4 项修复本会话均已实读/复跑独立确认（§3.4） |

**未验证/未覆盖（诚实清单）**：t13/t14 heavy 对拍（不在门禁命令面，§3.3）；snforge 全量与 Sepolia fork 测试（本会话未跑）；heavy 切片门禁本会话未复跑（以【门禁材料】20/0 为准）；ΣK>64 专项新负例（拒绝面零改动、由既有政策测试承载）；t13 与 T1 的 steps 微差归因（【前批报告】§2.3 已注，本批未涉及）；部署动作未发生（owner 上链 `set_fold_program_hash(0x074f0a…)` 待部署时执行）；Lean 复核未做——悬置已消除为事实：Lean 的 Fold 层**在库且引用 fold_batch**（`src/airs_lean/AirsLean/Fold.lean`，模块自述「牌桌折叠协议（fold_batch）安全属性层」；另有 `Fold/Chain.lean`——本会话 `grep -rln fold_batch src/airs_lean/` 实证命中），但其属性是否隐含单桌形状前提（如 slot16 批常量）本会话未复核，归 §6.2 同批评审一并核对。~~多桌形状笼内复测~~ → **已于 2026-09-30 补测闭合（§6.1）**。

---

## 6. 剩余条件

1. ~~**笼内复测多桌形状（Q-M3 前提）**~~ → **✅ 已完成（2026-09-30 补测，四场景三门禁全绿）**：
   - **环境与方法**：stark 产证机笼内（阿里云 Linux x86_64、4 vCPU/7.3G、cgroup v2），每场景独立 `systemd-run` 瞬态单元 `fold-mt-<name>.service`，属性对齐 monad-fold@.service 探针纪律（Slice=zchain-recursion.slice、MemoryMax=4600M、MemorySwapMax=0、CPUQuota=300%、Nice=5，取严判定）；被测物 = 本仓库同源码交叉编译 musl 静态二进制（`fold_batch_test` 新哈希 8568f23f…、`prove-hand` 与前批同哈希 e963fd7d… 证 proving-tool 零改动），SHA256 双侧核对；采样 = 无 memory.peak 内核下 100ms 轮询本单元 memory.current 取峰 + texas.service MemoryCurrent 全程探针。
   - **四场景结果**（steps 与本机逐字一致——交叉编译/环境不改电路语义的直接证据）：

     | 场景 | steps（笼内 = 本机） | 峰值 RSS（4600M 单元帽） | oom_kill | texas 漂移 | 笼内耗时 |
     |---|---|---|---|---|---|
     | k64 单桌回归（FOLD_PERF_ONLY=64 t7） | 398,146（2^19） | 3,224 MiB（**70%**） | 0 | 0.00% | 38.8s（prove 34.2s） |
     | mt8 最坏形状（T=8×8 人 ΣK=64，m9_1c） | 409,563（2^19） | 3,221 MiB（**70%**） | 0 | 0.00% | 51.6s |
     | mt2a 两桌异人数（8p×8h+2p×8h，m9_1a） | 98,685（2^17） | 1,839 MiB（39%） | 0 | 0.00% | 28.1s |
     | mt2b 两桌同规模（8p×4h+8p×4h，m9_1b） | 52,885 | 1,731 MiB（37%） | 0 | 0.00% | 18.3s |

   - **判定**：最坏多桌形状峰值与单桌 K=64 基本重合（3,221 vs 3,224 MiB——同落 2^19 桶，8 份 keyagg 只加 steps 不动内存）；对 4600M 单元帽余量 30%，texas 全程 active 且零漂移，四场景 exit=0、零 OOM。**Q-M3（T_MAX=8 终值复核）的待跑前提已满足**——数据支持维持 T_MAX=8（若评审想放宽，约束在政策不在资源：桶占用 39%、单元帽 70%，二者都有空间，但放宽属 §6.2 同批评审裁定面）。
   - **本机对照口径（同日 Darwin arm64 实测）**：T7 全档 K=1/8/32/64 = 7,897/51,254/199,922/398,146 steps（多桌化簿记漂移 +38/+115/+379/+731，K=64 per-hand 6,221）；m9_1c 5.5s / m9_1a 2.6s / m9_1b 3.0s；本机全树峰值 RSS 4.47-4.57 GiB（线程数多于笼内 4 线程，口径不可直比，如实标注）。
   - **局限（诚实标注）**：内存峰值 100ms 采样粒度（余量 30% 量级覆盖该误差）；prove-hand 每场景首跑含 cairo 编译（笼内耗时含编译，时长非纯 prove 口径）；texas 计数器全程同值与前批 C3 观察一致（无法区分真零扰动与计数器冻结，服务 active 为旁证）。
   - **复现物料**：`out/mt-cage-retest/`（cage-run-mt.sh、run-mt-all.sh、result-all.txt 全量证据）；服务器侧留档 `/root/.zmonad-tmp/fold-mt/`（verdict/log/samples ×4；二进制已清理，再生成命令见目录 README）。
2. **与全量协议迁移同批评审**：提案原文（proposal:255-257）要求多桌参数化与全量协议迁移同批评审、电路规范改动先行——本批为电路+host+链+合约+测试的全栈落地，评审未做；Q-M1（电路是否加 2≤P_t≤8 断言）、Q-M2（K_t=0 电路侧一行 panic）、Q-M4（heavy 铸造臂）三个实现期定案应随该评审一并裁定；**Lean Fold 层的属性前提核对**（§5 未验证清单：Fold.lean/Fold/Chain.lean 在库引用 fold_batch，多桌化后其是否隐含单桌形状——如 slot16 批常量——须逐条核对）同批进行。C6 的 poseidon-as-RO 实例化论证对多桌 μ(n_t) 构造同样适用，一并交外部评审。
3. **C5/C6 沿袭**：前批未开始项原样沿袭——C5 声明域纪律文档（fold 模式宣称边界：真验 STARK 站点 + roster 对照前提 + 事实登记面降级声明；多桌下「同 pks 不同 n_t ⇒ μ 不同」的玩家自核说明应补入）；C6 聚合协议外部评审（nonce 并发会话/Drijvers 面 + poseidon-as-RO）。
4. **提交由用户执行**：全部改动在工作树未 commit。应提交清单 = 8 个修改文件中的 7 个代码/测试文件（`out/poker-fold-implementation-report.md` 的修改为前批报告的工作树更新，是否随批提交由用户定）+ 4 个未跟踪新件（`tests/golden/`、`scripts/pin_fold_program_hash.sh`、`out/fold-multitable-spec.md`、`out/fold-multitable-workflow.ts`；`out/c3-cage-retest/` 为前批产物）。注意 `scripts/pin_fold_program_hash.sh` 当前未跟踪——不提交则重钉自动化在他处不可复现。部署序列（owner `set_fold_program_hash(0x074f0a…)`、部署时双跑对拍）沿【前批报告】§5.9 提醒。**材料归档（可审计性）**：四份工作流材料 JSON（【实施材料】/【评审材料】/【门禁材料】/【钉扎材料】）未落盘本仓库——heavy 20/0、snforge 130/0、评审 4 发现、钉扎 before/after 均挂其上；本报告会话无权写报告以外文件、未代归档，建议用户随提交将材料 JSON（或其 SHA256 清单）归档至 out/ 供独立复核；过渡措施 = 本报告已将其关键数字与文案逐条内嵌（§3.1/§3.2/§5）。
5. **t13/t14 heavy 补跑（本报告会话核出，建议并入下一门禁轮）**：`cargo test --release -p hand-verify-native --test fold_parity_test -- --ignored --nocapture`——多桌对拍 heavy（t14）与单桌 combined 对拍 heavy（t13 回归）均未在五门禁内执行；断言面已由 m9_1a/b/c 与 host 臂覆盖，风险有限但应跑齐（§3.3）。

---

## 附录 A：本报告会话命令清单（复核用，路径相对仓库根）

```bash
# —— 状态与 git 对照 ——
git status --porcelain && git branch --show-current && git log --oneline -2
git diff --numstat -- poker_contracts/src/poker_dual_settlement.cairo \
  stark-recursion/src/chain.rs stark-recursion/src/stark_final.rs \
  poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo \
  poker_contracts/hand-verify-native/src/foldagg.rs \
  poker_contracts/hand-verify-native/tests/fold_batch_test.rs \
  poker_contracts/hand-verify-native/tests/fold_parity_test.rs
      # → 合约 278/5；其余见 §5 第一行
git diff -- poker_contracts/src/poker_dual_settlement.cairo | grep '^-' | grep -v '^---'
      # → 5 行删除全为注释内 fold_batch.cairo 行号更新，无逻辑行

# —— 符号与实现实读（grep / sed 区段）——
grep -n 'FOLD_BATCH_PROGRAM_HASH_HEX' stark-recursion/src/stark_final.rs          # :67 = 0x074f0a…
grep -n 'MAX_TABLES_PER_FOLD_BATCH' stark-recursion/src/chain.rs                  # :354 常量 / :485-487 断言
sed -n '440,495p' stark-recursion/src/chain.rs                                    # M4-c 三检放宽 + run 计数全段
grep -n 'FOLD_T_MAX\|struct FoldTable\|fn build_batch_wire_tables\|fn write_inputs_tables\|fn expected_public_output_tables\|fn prove_fold_batch_multitable' \
  poker_contracts/hand-verify-native/src/foldagg.rs                               # :112/:397/:557/:632/:425/:821
grep -n 'words.len()\|cursor' poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo   # 桌循环 :146-283
sed -n '100,135p' poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo   # 域标签五件套/SETTLE_WORDS
sed -n '230,244p' stark-recursion/src/stark_final.rs                              # 桌内常量注释（评审发现 3 修复）
grep -n 'fn assert_circuit_assert_rejected' -A 14 poker_contracts/hand-verify-native/tests/fold_batch_test.rs
sed -n '1100,1170p' poker_contracts/hand-verify-native/tests/fold_batch_test.rs   # m9_1c / m9_2a 测试体
sed -n '/fn m9_2c/,/^}/p' poker_contracts/hand-verify-native/tests/fold_batch_test.rs   # 三断言含 proof.json 落盘
sed -n '/fn m1c_t_window_rejects_empty_and_over_max/,/^}/p' poker_contracts/hand-verify-native/tests/fold_batch_test.rs
sed -n '/fn fold_batch_plan_rejects_bad_shapes/,/^    }$/p' stark-recursion/src/chain.rs
sed -n '/fn fold_batch_plan_rejects_table_run_overflow/,/^    }$/p' stark-recursion/src/chain.rs
grep -n 'fn fold_multitable_parity_two_tables_host\|fn t14_multitable' poker_contracts/hand-verify-native/tests/fold_parity_test.rs
grep -n 'fn fold_multitable' poker_contracts/src/poker_dual_settlement.cairo      # 4 合约测试 :2553/:2648/:2665/:2687
ls -la poker_contracts/hand-verify-native/tests/golden/
python3 -c "import json; d=json.load(open('poker_contracts/hand-verify-native/tests/golden/fold_t1_p2k2.json')); print(d['cairo_acc'], len(d['wire']), [len(s) for s in d['public_output']['segments']])"
      # → 0x0512d75d27e15662b9a23efcac93d3d73f05ef9be44a1d54833edbec3b48795a / 208 / [17, 17]

# —— 修订轮补充实读（对应读者意见核证）——
grep -n 'let marginal\|s1 <= COMBINED\|fn t7_perf' poker_contracts/hand-verify-native/tests/fold_batch_test.rs
      # → :655 fn / :701 K=1 门 / :706 边际公式
grep -n 'COMBINED_PER_HAND_STEPS\|KEYAGG_STEPS_ANCHOR' poker_contracts/hand-verify-native/src/foldagg.rs   # → :692 =12,160 / :696 =1,628
sed -n '425,475p' poker_contracts/hand-verify-native/src/foldagg.rs      # check_multitable_shape：T≥1/T≤8/K_t≥1/锚数，无 ΣK、无 P_t 检查
sed -n '1035,1048p' poker_contracts/hand-verify-native/src/foldagg.rs   # mint_settle_wire 的 2..=8 检查（:1041）
sed -n '/fn prove_fold_batch_unchecked_tables/,/^}/p' poker_contracts/hand-verify-native/src/foldagg.rs   # :773 裸出证入口（落 inputs 直跑 prove-hand）
sed -n '60,70p' stark-recursion/src/chain.rs    # TRACE_FLOOR_LOG2=20 / MEASURED_STEPS_PER_HAND=5374 / TRACE_HEADROOM_FACTOR=3
sed -n '1479,1495p' poker_contracts/src/poker_dual_settlement.cairo     # fold 入口复读（一次一段 17 词/幂等门/段长/MAGIC）
grep -n 'set_fold_program_hash' poker_contracts/src/poker_dual_settlement.cairo | head   # 测试自注哈希 :2252/:2392/:2493
sed -n '30,95p' scripts/pin_fold_program_hash.sh    # zfill(64) 归一 + 钉值字符串等值比较（幂等）
grep -rln fold_batch src/airs_lean/                  # → AirsLean/Fold.lean、Fold/Chain.lean（Lean 依赖在库）
git diff -- poker_contracts/src/poker_dual_settlement.cairo | grep '^+' | grep 'use '   # → 0 条（新增代码无 import）
env PATH=…/scarb-2.19.4/bin:… scarb … build 2>&1 | grep -o 'warn\[E[0-9]*\]' | sort | uniq -c   # → 10 E2066 + 24 E2100
uname -sm                                            # → Darwin arm64

# —— 门禁复跑（本会话）——
cargo test -p hand-verify-native            # 12 target：64 passed / 0 failed / 22 ignored
cargo test -p stark-recursion --lib         # 40 passed / 0 failed
env PATH=/Users/mac/.local/opt/toolchains/scarb-2.19.4/bin:/Users/mac/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  scarb --manifest-path /Users/mac/projects/poker_texas_air/poker_contracts/Scarb.toml build   # Finished dev profile

# —— 以下为【门禁材料】/【实施材料】转引，本会话未跑（如实区分）——
cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture  # heavy 20/0
bash scripts/pin_fold_program_hash.sh                                                          # 幂等无操作
snforge test（scarb 2.19.4 PATH 前置）                                                          # 130/0
cargo clippy -p stark-recursion --lib                                                          # 12 既有 warnings
```

## 附录 B：判定所依据的关键文件

- 生产电路：`poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo`（:83 头注释桌循环、:146-283 cursor 桌循环、:186 每桌 keyagg n 槽、域标签五件套与五步断言链未动）
- host 镜像：`poker_contracts/hand-verify-native/src/foldagg.rs`（:112 FOLD_T_MAX、:397 FoldTable、:425/:557/:632/:821 多桌四函数与出证入口）
- 金样：`poker_contracts/hand-verify-native/tests/golden/fold_t1_p2k2.json`（重构前生产路径捕获）
- 测试：`tests/fold_batch_test.rs`（m 系 16 条：m1b/m1c/m2/m4_m6/m5/m8×2/m9_1a/b/c/m9_2a/b/c/d/m9_3a/c）、`tests/fold_parity_test.rs`（:396 host 多桌对拍、:695 t14 heavy 未跑）
- 合约：`poker_contracts/src/poker_dual_settlement.cairo`（消费面 :1479-1513 本批零逻辑改动；新增 4 测试 :2553-:2687）
- 链/终证：`stark-recursion/src/chain.rs`（:354 T_MAX、:440-490 M4-c 放宽）、`stark-recursion/src/stark_final.rs`（:67 重钉值、:236-239 桌内常量注释）
- 规格/提案：`out/fold-multitable-spec.md`（M1-M9、Q-M1~Q-M4）、`out/poker-fold-proposal.md:250-257`（多桌段）
- 钉扎脚本：`scripts/pin_fold_program_hash.sh`（未跟踪，提交清单见 §6.4）
