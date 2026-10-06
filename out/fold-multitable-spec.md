# fold 多桌参数化接线规格（fold-multitable-spec）

- 日期：2026-09-30
- 输入：`out/poker-fold-proposal.md:250-257`（「后续待办：多桌参数化」段，本会话实读）+ `out/fold-spec.md`（冻结稿，重点 D1/D1a/D5，本会话全文实读）+ 本会话逐文件实读的 5 份实现文件（清单见 §10）。
- 原则：提案与代码冲突时**以代码为准**，冲突在 §0 逐条注明；本规格只写规格，不改任何实现代码。
- 引用约定：`path:line` 均为本会话实读时的行号；实测数字均注明取数出处。

---

## 0. 提案 vs 代码：冲突与修正（先读）

| # | 提案说法（多桌段原文位置） | 代码现实（本会话实读） | 规格裁定 |
|---|---|---|---|
| MT-1 | 「公开输入 +T 个 roster_digest 与每桌手数，padding 至最大桌 size=8」（proposal:254） | (a) roster_digest = poseidon([ROSTER_LABEL, n] ++ pks) 以**实际 (n, pks)** 入哈希，电路 `fold_batch.cairo:131-153` 与合约注册面 `poker_dual_settlement.cairo:1371-1381` 两侧同式——把 roster 补齐到 8 人再哈希即改变 digest，合约 #10 对照（`:1508-1513`）永拒；(b) 电路**今天就是变宽解析**：P 是运行时读的 `words.at(0)`（`fold_batch.cairo:128,134`），不存在「必须等宽才好解析」的约束；(c) wire 头加 T 前缀会使 T=1 wire 与现行生产 wire 不再逐词一致 | **否决 padding 与 T 前缀**：wire 采用桌段自定界串接、无全局 T 词（§2）；padding 的两难（进 digest 破合约对照 / 不进 digest 是死词）见 §3 定案 |
| MT-2 | 「每桌一次聚合验证（常数）」（proposal:254） | 属实且已是代码现状的单桌推广：keyagg/roster_digest 每批一次（`fold_batch.cairo:131-159`），K 手共享 P̄；实测批固定层 = 404 + 153·n（P=8 → 1,628，`foldagg.rs:553-555` KEYAGG_STEPS_ANCHOR） | 按「每桌付一次固定层」定预算（§1），O(1)/手 账不破坏 |
| MT-3 | 「SettleBatch 零改动」（proposal:255） | 证实：语句三元组 `BatchStatement { program_hash, hand_binding, fact }`（`groth16-wrap/src/batch.rs:29-33`）无桌/roster 字段，形状只依赖全局 fold program hash；SettleBatch 批根吃 statements（`chain.rs:483-485` keccak_batch_root 复用） | 维持零改动；桌结构对语句层不可见（每手段自带 slot16） |

---

## 1. T 窗口与批预算（钉死 M1）

**实测口径（本会话取数）**：
- 2^20 = 1,048,576 steps 桶 = canonical_small trace 地板（`chain.rs:64-65`，引 circuit_params lib.rs:227）；trace 自动 pad 到 2 的幂行（K=64 实测 397,415 → 2^19 行，`out/c3-cage-retest/result-k64.log:16`）。
- 生产单桌 P=8：K=1 = 7,859 steps、K=64 = **397,415** steps（`out/poker-fold-implementation-report.md:101` T7 heavy 记录 7,859/51,139/199,543/397,415；K=64 与笼内复测 `out/c3-cage-retest/result-k64.log:16` 逐字一致）。**平均 6,209/手**（397,415/64 = 6,209.6），**边际 6,183/手**（(397,415−7,859)/63 = 6,183.4，本会话算得）。
- 每桌批固定层（keyagg + roster_digest 重算）= 404 + 153·n_t steps（提案 §3.1 锚，P=8 → 1,628 = `foldagg.rs:553-555`）。

**钉死**：
- **M1-a（ΣK ≤ 64 且 2 的幂）**：沿用 `check_hand_count`（`chain.rs:163-178`：空批拒 `:166-168`、>64 拒 `:169-173`、非 2 幂拒 `:174-176`）与 `MAX_HANDS_PER_LEAF=64`（`chain.rs:63`），**零政策代码改动**。理由：ΣK 是 steps 的主导项（6,183·ΣK），现有政策已把它钉在桶内。
- **M1-b（K_t 无独立上限、K_t ≥ 1）**：K_t ≤ ΣK ≤ 64 自动成立，不新增 K_t 上限常量；**K_t = 0 的空桌段由 host 构造器拒绝**（只花 keyagg steps 零产出，属构造错误；电路侧不检——无 soundness 影响，见 §2 附注）。
- **M1-c（T ≤ T_MAX = 8，host 层新增检查）**：steps 最坏情形推算——合法批内最大化固定层 = 全部桌 P=8、T=ΣK=64（每桌 1 手）：64×1,628 + 64×6,183 ≈ **499,904 = 2^20 的 47.7%（余量 2.10×）**；T=8 全 8 人 ΣK=64：8×1,628 + 64×6,183 ≈ 408,736 = 39.0%（余量 2.57×）。模型对单桌 K=64 校验：1,628 + 64×6,183 = 397,340 vs 实测 397,415（偏差 0.02%）。**steps 在 ΣK ≤ 64 下永不成为绑定约束**——T_MAX=8 是**评审面政策**（限定新桌段解析循环 + host 循环的审查面），不是 steps 硬门；首版 T=8 拼批笼内实测落库后可复核放宽（开放点 Q-M3）。
- **M1-d（余量系数注明）**：多桌验收门 = 实测 steps ≤ 2^20 桶且**实测余量 ≥ 1.5×**（对照单桌 K=64 实测真实余量 1.74×，`out/stark-recursion-engineering-report.md:161`）；`chain.rs:69` 的政策系数 `TRACE_HEADROOM_FACTOR=3` 只服务于既有自检 `:1260-1268`（其 5374 是 settlement 批程序口径，`chain.rs:67`），多桌预算**不用**该系数、直接用 fold 自身实测（6,183 边际 + 每桌 404+153·n_t）推算。

**理由（M1）**：全部数字可从两个实测锚（397,415@K=64 与 7,859@K=1）加每桌固定层公式复算，不留「3× 余量」式的无出口系数；ΣK 政策零改动使 combined/fold 两条链共享的 K 纪律不被多桌扰动。

---

## 2. wire 头布局：单 roster 段的自定界串接（钉死 M2）

**现状（代码）**：单桌 wire = `[P, (pkx,pky)×P, K, (settle 98 词, R̄x, R̄y, z̄)×K]`（`fold_batch.cairo:65-76` 头注释；host `foldagg.rs:461-483` build_batch_wire 同布局，词数 = 2+2P+101K）；main 完整 inputs = `[prev_acc, span_len] ++ wire`（`fold_batch.cairo:75-76`、`foldagg.rs:505-520`）。

**钉死（M2）**：多桌 wire = **桌段自定界串接，无全局 T 词**：

```text
wire = [P_1, (pkx,pky)×P_1, K_1, blocks×K_1] ++ [P_2, pks_2, K_2, blocks×K_2] ++ … ++ [P_T, pks_T, K_T, blocks×K_T]
blocks = (settle 98 词, R̄x, R̄y, z̄)          # 与现状每手 101 词块逐词同形
main inputs = [prev_acc, span_len] ++ wire     # span_len = Σ(2+2P_t+101K_t)，序列化约定不变
```

- 电路按 cursor 消费：第 t 桌从 `cursor_t` 起，`P_t = words.at(cursor_t)`、pks 段 `cursor_t+1 .. cursor_t+2P_t`、`K_t = words.at(cursor_t+1+2P_t)`、blocks 起 `cursor_t+2+2P_t`，`cursor` 越过本桌 blocks 后若 `cursor == words.len()` 则终止，否则下一桌。`Span::len()` 可用（`fold_batch.cairo:179` 已用 `seg.len()` 同 API）；截断/越界声明 ⇒ `at()/slice()` 越界 panic ⇒ 无证明（fail-closed，同 `:78-81` 纪律）。
- **桌序 = wire 序 = 段序 = claims 序**：输出仍为 `[len] ++ (ΣK)×17 词`平铺（`fold_batch.cairo:261-277` 输出循环的推广），桌 t 的手占据连续段区间；acc 的 claims 按同一顺序入链（§6）。
- **T=1 逐词退化**：`[P, pks, K, blocks]` 与现行 build_batch_wire 输出**逐词一致**——这是 §8 回归钉死的结构基础（有 T 前缀或等宽 padding 都会破坏它，见 MT-1）。
- host 侧（规格面，不写实现）：`build_batch_wire` 泛化为吃 `&[(pks_t, hands_t)]`（T=1 时输出与现函数逐词相等）；`prove_fold_batch` 的 anchor 从单个 `RosterAnchor`（`foldagg.rs:300-305`）泛化为**逐桌 anchors**，parity 门逐手对**本桌** anchor（§4/§9）。

**理由（M2）**：每桌头就是现行单桌头的原样复用（P 运行时变长解析今天已存在，`fold_batch.cairo:128-152`），泛化 = 把「读一次头 + 一层 K 循环」套进桌循环；无 T 词 ⇒ 无 T 与实际桌数不一致的检查面（桌数由 wire 长度自证）。

**附注（K_t=0 空桌）**：host 构造器拒绝（M1-b）；电路不检的后果 = 恶意 prover 自写 inputs 塞空桌段，只多付 404+153·n_t steps、不产生任何输出段、不触任何 soundness 面——可接受，若评审要求电路也拒则加一行 `K_t == 0 → panic`（开放点 Q-M2）。

---

## 3. padding 语义定案：**不 pad**（钉死 M3）

提案「padding 至最大桌 size=8」（proposal:254）指**roster 人数补齐**层面（把每桌 pks 列表补到 16 词等宽）。两种实现路径都不可取：

- **pad 词进 roster_digest**：digest = poseidon([LABEL, n] ++ pks) 以实际 (n, pks) 定义，合约 `register_roster` 链上重算同式（`poker_dual_settlement.cairo:1371-1381`）且 n∈2..=8（`:1372`）——pad 后 digest ≠ 注册值，fold 入口 #10 对照（`:1508-1513`）**必然永拒**，直接不可行。
- **pad 词不进 digest（死词）**：每桌 +2×(8−n_t) 个无约束死词进 soundness 承重 witness，且需要一条「pad 规范值」的 host/电路约定（0？生成元？）徒增对拍面；若电路对 pad 位也跑 keyagg 则每桌多付 (8−n_t)×153 steps 与 EC_OP。收益仅是「等宽表头」——而变宽解析是电路既有能力（MT-1b），收益为零。
- **附带否决**：为等宽而加的 `[T, (P_t, pks_t, K_t)×T, hands…]` 两段式头同样否决——T 前缀破坏 T=1 wire 逐词一致（§8），且把 hands 与其 roster 头分离扩大评审面。

**理由（M3）**：不 pad 的代价 = 电路/host 的 cursor 按桌推进（既有模式的循环化）；pad 的代价 = 破合约对照或引入死词面。代价严重性不对称，定案不 pad，提案措辞按代码现实修正（冲突 MT-1）。

---

## 4. D1a 修订：roster_digest 从批常量改为**桌内常量**（钉死 M4）

**现状（代码）**：单桌批内 slot16 全段同值（电路每批算一次 digest、逐段复制，`fold_batch.cairo:153,274`；D1a 原文 `out/fold-spec.md:41`）；`chain.rs` 的 `FoldBatchPlan::new` 批常量三检（`:426-451`）：acc 同值（`:426-436`）、roster 非零（`:437-442`）、roster 同值（`:443-451`）。

**钉死（M4）**：
- **17 词段布局不动**：index 16 仍是**本桌** roster_digest（word 0–15 combined 信封同位不动，`fold_batch.cairo:261-277` / `out/fold-spec.md` D1 表不变）。多桌下不同桌的段在 slot16 携不同值——段本身零改动。
- **电路侧**：roster_digest 每桌算一次、桌内段复制（`fold_batch.cairo:131-159` 的循环体套进桌循环）——「桌内常量」由电路结构保证，与今天「批内常量」由结构保证同型。
- **chain.rs 三检放宽为**：
  1. **slot 0（acc）批常量：不动**——跨桌 claims 仍折进同一批终 acc（§6），全段同值检查原样保留（`chain.rs:426-436`）；
  2. **slot 16 逐手非零：不动**（`:437-442`）；
  3. **slot 16 批同值 → 桌内常量**：删除跨批同值断言（`:443-451` 的 match 分支），代之以**run 分组语义**——按段序切极大同值 run，run 数 = 桌数 T，新增断言 **T ≤ T_MAX(8)**；同 run 内同值由 run 定义自持（真正的桌内常量已上移为电路结构事实，host 层不再重复断言）；**允许不同 run 同值**（同一批玩家群开两桌是合法场景，两桌 digest 相同不构成攻击：手段 binding 各异、签名各验）。
  4. 其余五连检（len 17/MAGIC/fact 重算/binding 槽位/去重，`chain.rs:414-425,452-467`）零改动——fact 对段逐词吸收，桌结构无关。
- **stark_final.rs：零改动**——`parse_fold_final_output`（`:276-302`）只检 `[len] ++ 17k+4` 形状，**本就无 roster 一致性检查**（本会话实读确认）；`FoldFinalOutput::statements`（`:248-267`）逐段派生 fact/binding，桌无关。唯一触碰 = 改 fold_batch.cairo 后重钉 `FOLD_BATCH_PROGRAM_HASH_HEX`（`:58-67`），走既有自动化 `scripts/pin_fold_program_hash.sh`（本会话实读脚本头，幂等重钉 + 测试验证）。
- **foldagg parity 门泛化**：`prove_fold_batch` 的 roster 门（`foldagg.rs:687-693`）从单一 anchor 改为逐手对本桌 anchor（`seg[16] == anchor[t(hand)].roster_digest`）；acc 门（`:694-699`）与段 word1..=15 门（`:700-707`）不动。

**理由（M4）**：批常量三检里只有「roster 同值」一条是单桌不变量；acc 同值与逐手非零都是多桌下仍成立的不变量。放宽面收在 chain.rs 一个 match 分支 + 新增 T 计数，是最小可评审 diff；`out/fold-spec.md:41` 的 D1a 原文在 T=1 特例下仍真，本节是它的多桌超集（不是推翻）。

---

## 5. keyagg 与 M_h：跨桌攻击闭合点（钉死 M5）

**钉死**：
- **keyagg 每桌一次**：μ_i = poseidon([KEYAGG_LABEL, **n_t**, pkx, pky])、P̄_t = Σ μ_i·pk_i，n_t = **本桌**人数——现代码单桌形态 `fold_batch.cairo:149`（`*words.at(0)` 即本桌 P）与 host `foldagg.rs:122-124`（`key_coeff_raw(n_players,…)`）的 n 槽在多桌下取 P_t。μ 含 n_t 的附带收益：**同 pks 集不同人数的两桌 μ 不同**，跨桌签名复用再被堵一层。
- **M_h 含本桌 roster_digest：公式不动**——M_h = poseidon([M_LABEL, hand_binding, m1, m2, cm_digest, **roster_digest_t**])（电路 `fold_batch.cairo:208-210`；host `foldagg.rs:146-156,344-348`）。多桌下 roster_digest_t 是该手所属桌的 digest，槽序与标签零改动（T8 KAT 钉值不触碰）。
- **跨桌闭合（攻击必拒的推导，逐行依据）**：c = poseidon([SIG_LABEL, hand_binding, M_h, **P̄_x, P̄_y**, R̄_x, R̄_y])（`fold_batch.cairo:212-214`）——同时含 M_h（内含 roster_digest_t）与本桌 P̄_t。把桌 A 的手（其聚合签名由桌 A 全员对 M_h_A、c_A 作出）配桌 B 的 roster 头：roster_digest_B ≠ roster_digest_A ⇒ M_h 变 ⇒ c 变 ⇒ 验证方程 z̄·G − c·P̄_B − R̄_A ≠ O ⇒ `RESIDUAL_NOT_IDENTITY` panic、无证明（方程与 panic 见 `fold_batch.cairo:228-237`）；反之唯一通过路径 = 桌 B 的 roster 真实共签该手（桌 B 批准，非攻击）。**这是电路内的第一重闭合**；消费面第二重 = 合约逐手段独立对照 segment[16] vs roster_registry（`poker_dual_settlement.cairo:1508-1513`，§7）。
- **host 铸侧同构**：`aggregate_sign` 以本桌 pks 集 derive rd/P̄/M_h/c（`foldagg.rs:331-349`）——多桌即按桌各调一次。

**理由（M5）**：闭合不需要任何新构造——它是「M_h 进 c、c 进方程」既有链条（fold-spec D2a 同型论证）在桌维度的自然延展；单桌版攻击测试 T9/T10（`fold_batch_test.rs:504-556`，forge0 攻击 roster / agg1 换 roster 均被拒）已实证该链条，多桌只需把攻击语料换成跨桌混合（§9-M2）。

---

## 6. acc 链：跨桌 claims 折进同一批终 acc（钉死 M6）

**钉死**：
- **单次折叠公式不动**：acc = poseidon([prev_acc] ++ claims)（电路 `fold_batch.cairo:250-259`；host `foldagg.rs:181-187` fold_acc / recurse 同公式）。多桌 = claims 列表按桌序（桌内手序）串接后**仍一次折叠**——不引入逐桌分段折叠、不引入桌间中间 acc。
- **Q-1 语义不变**：批终 acc 复制到本批全部 (ΣK) 段的 slot 0（`fold_batch.cairo:25-30,261-277` 布局注释与输出循环），使每手段独立成 fact 时都钉住整批链状态；chain.rs 的 acc 批常量检查（`:426-436`）不动（§4）。
- claim_i = poseidon([CLAIM_LABEL, hand_binding, M_h])（`fold_batch.cairo:217`）——M_h 含本桌 digest，故 claim 天然带桌色，无需额外桌标签。

**理由（M6）**：acc 链的绑定对象是「本批全部已证语句」而非「某桌」；改成逐桌折叠会改 slot0 语义、连带 fact/合约事件面全动，收益为零。桌序串接使 acc 是确定序的函数（换桌序 ⇒ 换 acc ⇒ 换全部 fact），顺序本身即绑定。

---

## 7. 合约判定：多桌**零合约改动**——实读证实（钉死 M7）

**证实（逐处代码依据）**：
1. **fold 入口逐手独立**：`verify_and_settle_dapv_fold_private(hand_binding, hand_id, segment)` 一次调用只吃**一段** 17 词（`poker_dual_settlement.cairo:1479-1484`），`segment.at(16)` 逐手读、逐手对照 `roster_registry`（`:1508-1513`）——多桌批 = 每手一次调用，各携各桌 digest，入口对「批里还有别的桌」全然无感知。
2. **registry 天然多桌**：`roster_registry: Map<felt252, bool>`（`:593`）；`register_roster` 每次注册一桌（`:1364-1389`），链上重算 digest（`:1374-1381`）、n∈2..=8（`:1371-1372`）、一次性仅对**同 digest** 重复注册拒绝（`:1383-1386`）——T 桌 = T 次调用，无互相干扰。
3. **fact 门长度无关**：`fact_for_segment` = poseidon([ph ‖ 整段逐词])（`:335-344`），对段长通用；fold 入口绑 `fold_program_hash` 分槽（`:1514-1521`），program hash 是**全局单值**（`:1397-1405` set/view）——多桌共用同一 fold 程序哈希，禁混批闸（D3c）不受桌数影响。
4. **事件/派奖逐手**：`DualProofSettledFold` 每手携带本手 roster_digest（`:1540-1549`）；claim_cms/escrow 按 binding 写（`:1524-1539`），binding 全局唯一由 `settled_bindings` 幂等门（`:1486-1489`）保证——跨桌重放同 binding 直接拒。
5. **语句层桌无关**（SettleBatch）：`BatchStatement` 三字段无桌字段（`groth16-wrap/src/batch.rs:29-33`）；keccak 批根对 statements 计算（`chain.rs:483-485`），桌结构对其不可见（MT-3）。

**结论**：提案「SettleBatch 零改动」（proposal:255）与「fold 入口多桌零改动」**均被代码证实**；最小改动面为零。若未来要求合约感知桌结构（如按桌统计），那是产品增量而非多桌必需——不列最小面（不存在必需改动）。

---

## 8. 单桌退化：T=1 回归钉死（钉死 M8）

**钉死**：T=1 时——
- **wire 逐词一致**：多桌构造器（§2 泛化后的 build）在单桌输入下的输出 = 现行 `build_batch_wire`（`foldagg.rs:463-483`）逐 felt 相等；main inputs 序列化 `[prev_acc, span_len] ++ wire`（`foldagg.rs:505-520`）同形。
- **输出逐词一致**：17 词段 word 0–15、slot 16（= 该桌 digest）、批终 acc 与现行生产输出逐 felt 相等（公式零改动 ⇒ 值确定相等）。
- **程序哈希必然更换**：改 fold_batch.cairo ⇒ 重编必换哈希（`stark_final.rs:63-64` 纪律），走 `scripts/pin_fold_program_hash.sh` 重钉——回归钉的是**行为**不是哈希。

**回归测试形态（定案）**：
1. **金样生成（重构前）**：用现行生产单桌路径（T8 KAT seed 确定性语料，`mint_roster_sks`/`mint_fold_hands`，`foldagg.rs:763-825`）出证一次，落库金样 = inputs.json + public_outputs（17 词段 + len 前缀）+ summary 的 acc/roster_digest/verified——作为 checked-in golden（或哈希清单）。
2. **金样断言（重构后，两层）**：host 单元层（非 heavy）——多桌构造器 T=1 的 wire 与金样逐 hex 相等；heavy 层（#[ignore] 形态，`fold_batch_test.rs:355-362` 同款）——出证后段/acc/digest 与金样逐 felt 相等 + verified=true。
3. **不进金样的项**：steps（重构可小幅漂移 loop 簿记，steps 走 T7 门 `fold_batch_test.rs:643-657`：K=1 ≤ 12,160+1,628、边际 ≤ 12,160）与 program_hash（必然换，钉扎脚本管）。
4. **T8 KAT 钉值不动**：五个域标签与 μ/M_h/c 金值（`fold_batch.cairo:103-108` 常量、`fold_batch_test.rs:154-155` T8）零触碰——多桌不改任何公式。

**理由（M8）**：wire 无 T 前缀（§2）使 T=1 退化是**结构同一**而非「兼容模式」；金样把「逐词一致」从口头承诺变成一条每次 CI 可跑的断言，防止泛化过程顺手改掉单桌语义。

---

## 9. 测试矩阵（钉死 M9）

| 组 | 用例 | 形态/断言 | 现有锚 |
|---|---|---|---|
| **M9-1 正例（T≥2）** | (a) T=2 不同人数桌：P=8/K=8 + P=2/K=8（ΣK=16）；(b) T=2 同人数不同 roster（P=8 vs P=8）；(c) 预算上限拼批：T=8 全 8 人 ΣK=64 | heavy #[ignore]：verified=true；逐手段 word1..=15 == host `expected_segment`；seg[16] == **本桌** anchor；全部段 slot0 同值 == `fold_acc(prev, claims 桌序串接)`；(c) 另记 steps 进 T7 表并过 1.5× 余量门（M1-d） | D5-3a/3b/3c（`out/fold-spec.md:196-199`）、T1 形态 `fold_batch_test.rs:361-362`、T7 表 `:600-659` |
| **M9-2 跨桌攻击负例** | (a) 换桌 roster：桌 A 手 + 桌 B pks 头 ⇒ 电路 `RESIDUAL_NOT_IDENTITY` panic、无证明；(b) 换桌重放：桌 A 的 (R̄,z̄) 配桌 B 的手 ⇒ 同 panic（c 变）；(c) parity 门版：诚实出证后把 anchor 换成别桌 ⇒ `prove_fold_batch` Err（roster parity failure 带手序号） | (a)(b) 走 `prove_fold_batch_unchecked`（`foldagg.rs:588-611`）断言失败文案含电路 panic 标签；(c) 走 `prove_fold_batch`（`:687-693`） | T2/T3 形态 `fold_batch_test.rs:410-441`；T9/T10 攻击形态 `:502-556`；闭合推导 §5 |
| **M9-3 padding/形状负例** | (a) 尾桌 blocks 截断 ⇒ 越界 panic/构造 Err；(b) K_t=0 空桌 ⇒ host 构造器 Err（M1-b）；(c) span_len 与实际词数不符 ⇒ runner/电路拒绝 | host 单元（非 heavy）+ `unchecked` 出证臂 | fail-closed 纪律 `fold_batch.cairo:78-81`；P_t 越界不在电路强制的现状见 Q-M1 |
| **M9-4 T 窗口负例** | (a) ΣK>64；(b) ΣK 非 2 幂；(c) 空批；(d) T>T_MAX=8 | (a)(b)(c) `FoldBatchPlan::new` Err（现状已拒）；(d) 新 run 计数检查 Err（M4-c） | `chain.rs:166-176` 既有三检 + `:1014` 空批/`:1021` 16 词拒绝在库负例形态 |
| **M9-5 对拍扩展（D5 增补）** | (a) `fold_parity` 泛化：多桌语料（≥2 桌不同人数）——combined 腿逐手 16 词、fold 腿多桌一批 17 词段，逐手 3a-3c 带**桌锚**；仍不断言 combined acc == fold acc（两链公式异源，D5-4 不变）；(b) 合约层（snforge）：两桌各自 `register_roster` 后各自段过 fold 入口正例 + D5-6 四条负例（未注册/16 词/combined 哈希 fact/重放）不变；(c) T=1 金样回归（M8） | 同 D5 运行形态（`#[ignore]` + `--release -- --ignored --nocapture`）；合约臂镜像 `settlement_combined_private_tests` setup 形态 | D5 全节 `out/fold-spec.md:191-204`；合约负例臂 `:202`；T1 运行形态 `fold_batch_test.rs:24-29` |

**理由（M9）**：矩阵沿既有测试的形态扩展（heavy 出证臂 + host 单元臂 + snforge 臂三层），不引入新验证原语；跨桌攻击两臂（电路 panic 臂 + parity 门臂）与单桌 T2/T9/T10 一一对应，评审可逐条映射。

---

## 10. 本会话检查清单（诚实条款）

**实读（全文或目标区段）**：`out/poker-fold-proposal.md`（多桌段 :250-257 + 附录 A/B :230-248）；`out/fold-spec.md`（全文 1-227）；`poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo`（全文 1-278）；`poker_contracts/hand-verify-native/src/foldagg.rs`（全文 1-826）；`stark-recursion/src/chain.rs`（:36-180 常量与 K 政策、:300-520 FoldBatchPlan 全段、:1260 附近自检）；`stark-recursion/src/stark_final.rs`（:30-340 钉扎/parse_fold/statements/verify）；`poker_contracts/src/poker_dual_settlement.cairo`（:234-260 trait、:296-310 常量、:335-344 fact_for_segment、:1362-1550 fold 注册面+双入口、:1550-1620 测试区头）；`poker_contracts/hand-verify-native/tests/fold_batch_test.rs`（测试清单 grep + T7 :591-659 实读）；`groth16-wrap/src/batch.rs:29-40`；`scripts/pin_fold_program_hash.sh`（头 30 行）。

**实跑命令与结果**：
- `grep -n "多桌" out/poker-fold-proposal.md` → 定位 :250；
- `python3 -c` 读 `/tmp/fold-direct-k1/summary.json`、`/tmp/fold-direct-k64/summary.json` → **切片版**（2 词输出时代）：K=1 = 2,149 steps、K=64 = 32,353 steps、verified=true——与提案附录 A「T7 steps 逐位 2,149/…/32,353」对应；**生产版 17 词口径的 397,415/6,209 取自** `out/c3-cage-retest/result-k64.log:16`（实读：`| 8 | 64 | 6482 | 397415 | 2^19 | 256 | 4096 | … | 6209 |`）与 `out/poker-fold-implementation-report.md:101,151,185`；边际 6,183 与 §1 各预算数为本会话算得；
- `grep -n "fold\|roster" poker_contracts/src/poker_dual_settlement.cairo` + 逐行实读 :1360-1550 → §7 结论依据；
- `grep -n "struct BatchStatement" -A 12 groth16-wrap/src/batch.rs` → 三字段、无桌字段；
- `grep -rn "6,209\|6209" out/*.md` → 定位口径出处（implementation report :52/:101/:151/:185）。

**本会话未跑**：cargo test / heavy 出证 / snforge / 笼内复测（本规格是静态规格，全部 steps 数字转引上述留档工件并注明；T=8 拼批的实测 steps 是 M9-1(c) 的**待跑项**，不是已得数）。

## 11. 开放点（移交实现阶段）

- **Q-M1**：电路内是否加 `2 ≤ P_t ≤ 8` 断言——现状电路无此检查（`fold_batch.cairo:128` 起 try_into 后直接循环），闭合在合约注册面（`:1372`）与 host 铸侧（`foldagg.rs:789-791`）；多桌不改此边界（维持现状）还是加防浪费断言，实现时定。
- **Q-M2**：K_t=0 空桌的电路侧一行 panic（M1-b 现只 host 拒）——评审要求则加。
- **Q-M3**：T_MAX=8 的终值——首版 T=8 ΣK=64 拼批笼内实测（steps/RSS，M9-1(c)）落库后复核；steps 侧最坏 47.7% 表明放宽空间在政策不在桶。
- **Q-M4**：M9-2 的「同 pks 不同 n_t」附加负例需铸侧支持（同 pks 集以两个 n 调 `key_coeff_raw` 即可在 host 单元断言 μ 不同，`foldagg.rs:122-124`）；heavy 铸造臂是否值得做，实现时定。
