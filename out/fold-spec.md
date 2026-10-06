# fold 接线规格（fold-spec，冻结稿）

- 日期：2026-09-30
- 输入：`out/poker-fold-proposal.md`（重点 §1.2/§2.2/§4.1/§4.2/§4.3/附录 B）+ 本会话逐文件实读的 7 份实现文件（清单见 §6）。
- 原则：提案与代码冲突时**以代码为准**，冲突在 §0 逐条注明；本规格只写规格，不改任何实现代码。
- 引用约定：`path:line` 均为本会话实读时的行号。

---

## 0. 提案 vs 代码：冲突与修正（先读）

| # | 提案说法 | 代码现实（本会话实读） | 规格裁定 |
|---|---|---|---|
| K-1 | §4.1 要求改共享常量：`chain.rs:181 COMBINED_OUTPUT_LEN 16→17`、`stark_final.rs:68 SEGMENT_LEN 16→17`、`poker_dual_settlement.cairo:277 COMBINED_SEGMENT_LEN 16→17` | 三者都是**在役路径的承重常量**：`CombinedBatchPlan::new` 用 16 逐手校验并**拒绝 17 词输出**（`stark-recursion/src/chain.rs:252`、负例测试 `chain.rs:658-662`）；`parse_final_output` 用 16 解析已钉扎程序 `settlement_batch_private` 的在证输出（`stark-recursion/src/stark_final.rs:55-56,177-181`）；合约 combined 入口断言 16 且测试 `combined_wrong_length_reverts` 钉死 15 词拒绝/16 词接受（`poker_contracts/src/poker_dual_settlement.cairo:1310-1313`、`:1714-1727`） | **否决改共享常量**：fold 链一律**新增**常量/新类型（见 §3、§4.6）。否则 §4.2 自己要求的「combined 入口保留为 fallback」当场失效 |
| K-2 | §1.2/§4.1 把 M_h 生产槽写成「wire[1]/wire[2]/wire[36] + cm_digest」，读起来像 4 个自由槽（ald 独立入 M_h） | 已实现的 M_h 公式只有 **3 个自由槽** m1/m2/cm_digest：电路 `fold_batch.cairo:143-145`、host 镜像 `foldagg.rs:117-126`；`fold_batch.cairo:27-30` 自己的注释也只列 3 槽（"wire[1] / wire[2] / wire[36] ald + cm_digest" 是歧义措辞） | **按代码钉 3 槽**：m1=wire[1]、m2=wire[2]、cm_digest=H(wire[28..=35])；ald（wire[36]）经语句内 digest 断言**传递绑定**进 M_h（见 §2.2）。若要 ald 直接入 M_h 属公式变更（M_h 加第 4 槽 → T8 KAT/host 镜像全重钉），留开放点 Q-4 |
| K-3 | 提案行 4：「fold 切片文件均未 commit（untracked）」 | 已过时：`git log --oneline` 显示 `fold_batch.cairo`/`foldagg.rs`/`fold_batch_test.rs`/`fold_formal_props.rs` 均已在 **a7ef893d（batch verify）** 提交；`git status --porcelain` 仅 `?? out/poker-fold-workflow.ts`，工作树对 HEAD 无 diff | 记录为提案状态陈旧，不影响技术内容 |
| K-4 | §2.2 A5 写「cm_digest = poseidon(wire[28..35])」 | Rust 半开区间读法只覆盖 28–34 共 7 词；实际 cm 槽是 **8 词 wire[28..=35]**（`settlement_stmt.cairo:194` 以 `settle.at(28 + i)`、i∈0..8 吸收） | 按 `settlement_stmt.cairo` 实际布局钉为 wire[28..=35]（8 词），见 §2.1 |

---

## 1. 生产版 fold_batch.cairo 的 17 词输出布局

**钉死（D1）**：生产版 fold 程序的**每手公开段 = 17 词**，布局为 combined 16 词信封原样 + 尾插 1 词：

| index | 词 | 来源 |
|---|---|---|
| 0 | chain_acc（fold 链累计承诺） | 沿用 combined 首词语义（`cairo/src/combined.cairo:101-110`、`chain.rs:190-194` 文档） |
| 1 | MAGIC 'SP2M_OK'（0x5350324d5f4f4b） | `settlement_stmt.cairo:32`、`chain.rs:185`（COMBINED_MAGIC_INDEX=1） |
| 2 | hand_id | `settlement_stmt.cairo:181` |
| 3 | registered_digest | `settlement_stmt.cairo:182` |
| 4 | n_expected | `settlement_stmt.cairo:183` |
| 5 | hand_binding | `settlement_stmt.cairo:184`、`chain.rs:186`（COMBINED_BINDING_INDEX=5） |
| 6..=13 | cm_0..cm_7（赢家认领承诺，非赢家为 0） | `settlement_stmt.cairo:185-205` |
| 14 | total_winnings | `settlement_stmt.cairo:207` |
| 15 | action_log_digest | `settlement_stmt.cairo:208` |
| **16** | **roster_digest**（本批常量，K 段同值） | 新增；值 = poseidon([ROSTER_LABEL, n] ++ (pkx,pky)×n)，电路内每批重算一次（`fold_batch.cairo:66-67,80-102`；host `foldagg.rs:87-96`） |

**理由（D1）**：word 0–15 与 combined 信封逐词同位，合约与链侧的全部既有槽位锚（MAGIC@1、binding@5、digest@3、total@14、ald@15、cm@6..13）零位移复用，唯一新增语义收口在 index 16 这一个固定锚上——这正是「消费面对照」需要的最小改动面（提案 §4.1 同布局，`chain.rs:185-186`、`wrap_circuit.rs:44-50` 兼容性由此成立）。

**附带钉死**：
- D1a：roster_digest 对一批 K 手是**同一值**（roster 每批进电路一次），K 个段各自在 slot 16 重复携带它，使「每手段独立成 fact/binding 语句」的链侧公式（fact = poseidon([ph‖seg])、binding = seg[5]，`chain.rs:206-211`）无需感知批结构。
- D1b：切片版现输出 2 词 `[acc, roster_digest]`（`fold_batch.cairo:191-194`），生产化 = 并入 98 词 settle wire 后把输出改为本布局；对拍锚 = word 1–15 必须逐词等于 `settlement_statement(settle)` 的 15 词返回（`settlement_stmt.cairo:60,179-209`）。
- D1c：roster 域标签五件套与 T8 KAT 钉值不变（`fold_batch.cairo:66-70`、`fold_batch_test.rs:181-184`），17 词输出不触碰 M_h/c/claim 公式。

---

## 2. M_h 真槽映射（以 settlement_stmt.cairo 实际布局为准）

### 2.1 98 词 settle wire 索引表（实测钉死）

`SETTLE_WORDS = 98`（`settlement_stmt.cairo:57`），布局（`:14-19` 注释 + 逐行实读）：

| index | 语义 | 实读出处 |
|---|---|---|
| 0 | hand_id | `:62` |
| 1 | **registered_digest** | `:63`；约束 1 终点 `:89`（DIGEST_MISMATCH） |
| 2 | **n_expected** | `:64`；约束 3 终点 `:176`（COUNT_MISMATCH） |
| 3 | hand_binding | `:65` |
| 4..=11 | p0..p7（玩家地址，非零前缀 + 规范零尾） | `:75`、`:79`（NON_TRAILING_EMPTY_SLOT） |
| 12..=19 | s0..s7（sign ∈ {0,1}） | `:82`、`:153` |
| 20..=27 | m0..m7（\|delta\| ≤ u64） | `:83`、`:154` |
| **28..=35** | **c0..c7（cm 槽，8 词）** | `:194`（`settle.at(28 + i)`，i∈0..8） |
| **36** | **action_log_digest** | `:87`（吸收进 digest）、`:146`（ACTION_CHAIN_MISMATCH）、`:208`（公开段尾词） |
| 37 | action_count（≤30） | `:92-94` |
| 38..=97 | w0..w59（30×2 日志打包/合法性词） | `:100-101` |

### 2.2 M_h 槽映射钉死（D2）

电路/host 公式：`M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])`（`fold_batch.cairo:143-145`、`foldagg.rs:117-126`）。生产版真槽映射：

| M_h 槽 | settle wire 槽 | 说明 |
|---|---|---|
| hand_binding | **wire[3]** | 与链上注册 binding 同值（combined.cairo:43 同取法） |
| m1 | **wire[1]**（registered_digest） | 切片占位 `foldagg.rs:646` 的槽语义升格 |
| m2 | **wire[2]**（n_expected） | **不得**沿用切片占位 `Felt::from(roster_pks.len())`（`foldagg.rs:647`）——roster 人数（聚合签名者集）与该手非零结算人数（`settlement_stmt.cairo:170-176` 计数）是两个独立量，生产版必须逐字复制 wire[2] |
| cm_digest | **poseidon(wire[28..=35])**（8 词 c0..c7 压缩） | 切片占位为 2 词 poseidon([cm0,cm1])（`foldagg.rs:648-650`）；生产 8 词压缩的确切 sponge 用 `poseidon_hash_many`（与 corelib HashState 同构造，`stark_final.rs:79-82`），落库时在 T8 KAT 钉值（开放点 Q-2） |
| roster_digest | 电路内自算（§1 表 index 16 同值） | `fold_batch.cairo:102` |

**ald（wire[36]）的绑定路径（D2a）**：wire[36] **不是** M_h 的独立槽；它经语句内两条断言传递钉死——(a) 约束 1 把 ald 吸收进 digest 并断言 `digest == registered_digest`（`settlement_stmt.cairo:87-89`），而 registered_digest = wire[1] = m1 ∈ M_h，故改 ald 必改 digest 必破 m1；(b) `ACTION_CHAIN_MISMATCH` 断言链根 == wire[36]（`:146`）。
**理由**：M_h 任何槽改动都会改变聚合签名消息——攻击者换 ald 只能连同 wire[1] 一起改，而 wire[1] 在 M_h 里，改了就破签；这条传递链与提案 F-3 的论证一致且已被电路/hook 双侧实现。

---

## 3. stark-recursion 的 16→17：**新增常量/新类型，不改共享常量**

**钉死（D3）**：
- D3a：`chain.rs` **不动** `COMBINED_OUTPUT_LEN=16`（:181）、`COMBINED_MAGIC_INDEX=1`/`COMBINED_BINDING_INDEX=5`（:185-186）；新增 `FOLD_OUTPUT_LEN = 17`、`FOLD_MAGIC_INDEX = 1`、`FOLD_BINDING_INDEX = 5`、`FOLD_ROSTER_INDEX = 16`，并新增 `FoldBatchPlan`/`FoldHandEntry` 类型（校验逻辑镜像 `CombinedBatchPlan::new` 的 len/MAGIC/fact/binding/去重五连检，`chain.rs:247-281`），K 政策/keccak 根/叶 H1 经既有共享函数复用（`check_hand_count`/`keccak_batch_root`/`leaf_output_words`）。
- D3b：`stark_final.rs` **不动** `SEGMENT_LEN=16`（:68）与钉扎哈希 `BATCH_PROGRAM_HASH_HEX`（:55-56，钉的是 settlement_batch_private 16 词段程序）；fold 链的终证解析走**新常量**（`FOLD_SEGMENT_LEN = 17`）+ 新钉扎哈希常量（生产 fold 程序新哈希，`stark_final.rs:50-54` 注释明示「重编程序必然换哈希 → 同步更新钉扎」）。`expected_batch_fact`（:84-98）**原样复用**——它对 segments 切片长度不敏感，且电路内 batch_fact 公式 `poseidon([acc_prev, root_hi, root_lo, k] ++ segments)` 逐字沿用（`proving-tool/src/settlement_batch_private.cairo:231-248` 实读确认）；仅 `parse_final_output`/`FinalOutput::statements`（:143-189，硬编码 16）需要 fold 侧平行版本。
- D3c：**禁混批的三层闸**（必须同时成立）：
  1. **host 编译期**：独立类型使 fold/combined 条目互插是类型错误——沿用 `chain.rs:213-219` 的既有先例原文（「独立类型让旧路径零改动、编译期即禁止混装」）；即便强插，17/16 词长检（D3a）与去重检也会拒绝；
  2. **fact 公式锚**：两链 program_hash 不同（fold 新程序 ⇒ 新哈希，合约侧分属 `fold_program_hash` 与 `combined_program_hash` 两个存储槽），跨链语句的 fact 重算必不等；
  3. **合约消费面**：fold 入口只吃 17 词 + fold 哈希 fact + roster 对照，combined 入口只吃 16 词（:1310-1313）——互相过不了对方的形状/门检。

**理由（D3）**：combined fallback 链的在证材料（已钉扎的 settlement_batch_private 程序哈希、已提交的 16 词段、在库负例测试 `chain.rs:649-662` 与合约测试 `:1714-1727`）全部绑定 16；改共享常量即报废 fallback（违反提案 §4.2），而新增常量/类型是本仓库已验证过的双形态共存模式。

---

## 4. 合约接口（PokerDualSettlement 增量）

### 4.1 存储（加进 `#[storage] struct Storage`，`:515-560`）

```cairo
/// fold 链注册面：roster_digest → 已注册（键 = 电路公开输出词本身）。
roster_registry: Map<felt252, bool>,
/// fold 链程序哈希（fold 入口 fact 绑定根，与 combined_program_hash 平行）。
fold_program_hash: felt252,
```

**理由**：fold 入口与注册面在同一合约内直读自有存储，免跨合约调用与第二个信任根；digest 作键 = 「segment[16] 的值本身即可注册成员证明」，与电路输出词直接对得上。

### 4.2 `register_roster`

```cairo
fn register_roster(ref self: TContractState, table_id: u64, n: felt252, pks: Span<felt252>);
```

实现钉死：
- owner-gated：`self.ownable.assert_only_owner()`（同 `set_combined_program_hash` :1287-1291 的门形）；
- 合法性：`n` 经 try_into 断言 2≤n≤8（与结算侧人数窗一致，`:414`/`:1082`），`pks.len() == 2·n`；
- 计算并写入：`roster_digest = poseidon_hash_span([ROSTER_LABEL, n] ++ pks)`，其中合约内常量 `ROSTER_LABEL = 'poker/fold-batch/roster.v1'` 与 `fold_batch.cairo:67` **逐字节一致**；`roster_registry.write(digest, true)`；
- 一次性：digest 已注册时拒绝（注册值不可改写——前提 K 的合约面落地；PokerTableRegistry 的「不可变行」哲学，但键换成 digest）；
- 不验 on-curve：合约无 EC 能力，垃圾 pks 只会登记一个电路必然 panic 的 digest（`fold_batch.cairo:90-96` fail-closed），不出证即不出金。

**理由（D4a）**：on-chain 重算 digest（而非只存调用方给的 digest）使注册值与电路公式同源，消费面对照才是「H1 单射 ⇒ wire pks == 注册 pks」（提案 §1.2 第 3 步）的成立形态；owner-gated 是提案 C1 指定的 ACL（F-4 的代注册 griefing 残余走产品侧玩家自核纪律，见开放点 Q-3）。

事件：`RosterRegistered { table_id: u64, n: felt252, roster_digest: felt252, pks: Span<felt252> }`——pks 全文随事件可取，供玩家自核注册面（F-4 纪律的取数入口）；view：`roster_registered(digest) -> bool`。

### 4.3 `set_fold_program_hash` / view

```cairo
fn set_fold_program_hash(ref self: TContractState, program_hash: felt252);   // owner + assert != 0
fn fold_program_hash(self: @TContractState) -> felt252;
```

**理由**：逐字复刻 `:1287-1295` 的 owner-gated + 非零断言 + 独立存储槽模式——两链哈希分槽是 D3c 第 2 层禁混批的承重件。

### 4.4 fold 结算入口（逐项对照 combined 入口 `:1299-1362`）

```cairo
fn verify_and_settle_dapv_fold_private(ref self: TContractState, hand_binding: felt252, hand_id: u64, segment: Span<felt252>);
```

calldata 形状与 combined 入口完全一致（三参），检查序列逐项对照（行号为 combined 现行对应点）：

| # | fold 入口断言 | combined 对应 |
|---|---|---|
| 1 | `hand_binding != 0` | :1305 |
| 2 | `!settled_bindings.read(hand_binding)`（幂等） | :1306-1309 |
| 3 | `segment.len() == FOLD_SEGMENT_LEN(17)` | :1310-1313（16） |
| 4 | `segment[1] == MAGIC` | :1314-1317 |
| 5 | `segment[2] == hand_id` | :1318 |
| 6 | `segment[5] == hand_binding` | :1319 |
| 7 | `n = segment[4]` ∈ 2..=8 | :1320-1321 |
| 8 | `segment[3] == registered_digest`（read_registered_digest） | :1322-1323 |
| 9 | `segment[15] == action_logs.read(hand_binding)` | :1324-1327 |
| 10 | **新增：`segment[16] != 0 && roster_registry.read(segment[16])`（"Roster not registered"）** | 无——这是 C1 的闭合点 |
| 11 | fact 门：`fact_for_segment(self.fold_program_hash, segment)` 已登记（复用 `settlement_facts`，:1329-1335 形） | :1329-1335（combined 哈希） |
| 12 | 派奖：total = segment[14]（:1338 形）、`claim_cms.write((binding, i), segment.at(6+i))` i∈0..8（:1346-1350 形）、`amounts_hidden`/`settled_bindings` 写位（:1351-1352 形） | 同 |
| 13 | 事件 `DualProofSettledFold { hand_binding, settlement_digest, participant_count, chain_acc(=segment[0]), roster_digest(=segment[16]), total_winnings }`（DualProofSettledCombined :622-630 加一字段） | :1353-1361 |

**理由（D4b）**：与 combined 逐项同构 + 仅两处增量（长度 17、slot16 对照）使双跑对拍与代码评审都在「已知面 + 已知 diff」上进行；fact 公式 `poseidon([ph‖seg])`（`fact_for_segment` :302-311）对 16/17 词长度均通用，无需改。

### 4.5 ACL 汇总

| 面 | ACL | 依据 |
|---|---|---|
| register_roster | owner-only | 提案 C1 指定；set_combined_program_hash 同门形 |
| set_fold_program_hash | owner-only + 非零 | :1287-1291 模式 |
| fold 证明 fact 登记 | **复用 `register_settlement_fact`**（owner 或 prover，:990-999）——不新增 ACL | fact 登记面已存在且门形正确 |
| fold 结算入口 | 无 caller 门（fact 即门），与 combined 入口一致 | :1299 起无 caller 检查 |
| 事件 | 新增 `RosterRegistered`、`DualProofSettledFold`，挂进 Event 枚举（:562-578） | 沿用事件风格 |

### 4.6 段长常量三态共存

```cairo
const SETTLEMENT_SEGMENT_LEN: usize = 15;  // :275，v2/v3/emit 入口，不动
const COMBINED_SEGMENT_LEN: usize = 16;    // :277，combined fallback 入口，不动
const FOLD_SEGMENT_LEN: usize = 17;        // 新增，fold 入口专用
```

**理由**：三个入口各自断言自己的段长（`:406`/`:1074`/`:1234` 用 15、:1310 用 16、fold 用 17），常量并存即形状自文档；改 :277 会同时破坏 v2/v3 在役入口与在库测试——即冲突 K-1 的裁定。

### 4.7 为什么不放 PokerTableRegistry

`poker_table_registry.cairo` 的 `create_table` 是 **permissionless**（:127），且其模块注释自认「注册表是绊线与审计轨迹，不是缰绳」（:11-12）——soundness 承重面不能放在一个任何人可写、且自我声明不作为缰绳的合约里。roster_registry 落在 PokerDualSettlement（fold 入口同合约直读）；PokerTableRegistry 保持零改动（多桌参数化的「可选对账面」角色不变，提案后续待办同此定位）。

---

## 5. host 层 fold/combined 双跑对拍 parity 测试形态

**钉死（D5）**：新建 heavy 测试（建议 `tests/fold_parity_test.rs`，或挂进 `fold_batch_test.rs` 作 T13；`#[ignore]` + `cargo test --release -p hand-verify-native --test fold_parity_test -- --ignored --nocapture`，与 T1 同运行形态 `fold_batch_test.rs:24-29,285-321`）：

1. **同一语料双吃**：一张 8 人 roster（`mint_roster_sks`/`roster_pks_from_sks`，`foldagg.rs:626-634`）× 8 手；每手用 `combined::build_settle_statement` + `SettleStatement::wire_words` 产出 98 词 wire（`combined.rs:400-457,147-165`）——**同一条 wire 喂两条腿**，语料单一来源是对拍有效性的前提。
2. **combined 腿**：逐手 `prove_combined_layer`（`combined.rs:251-395`）→ 16 词输出；其内部双 parity 门（acc 对 `host_fold_tasks` 重算 :346-354、segment 对 `expected_segment` 重算 :355-357）即该腿的既有机器核对。
3. **fold 腿**：`prove_fold_batch`（`foldagg.rs:502-615`）一次吃 8 手 → 生产版 17 词段；断言：
   a. **跨腿主对拍**：fold 段 word 1..=15 == 同手 combined 输出 word 1..=15（两侧都源自同一 `settlement_statement(settle)`，等值才有「同账」意义）；
   b. fold acc 门：cairo acc == host `fold_acc(prev, claims)`（`foldagg.rs:152-157`，T5 门同形）；
   c. fold roster 门：cairo 输出 slot 16 == `anchor.roster_digest` == host `roster_digest(pks)`（`foldagg.rs:87-96,317-325`，T9/T10 同形——roster_registry 的 host 模拟）；
   d. `--check-only` 独立复验（`foldagg.rs:569-584` 同款）。
4. **明确不断言**：combined chain_acc == fold acc。两链 claim 公式不同源（combined claim = poseidon([hand_binding, digest, payload 词…]) 无域标签，`combined.cairo:74-82`；fold claim = poseidon([CLAIM_LABEL, hand_binding, M_h])，`fold_batch.cairo:152`/`foldagg.rs:147-149`）——两条 acc 链是**有意的两个对象**，parity 只做逐链 host 重算一致 + 跨腿结算词一致；提案 §4.2 的「acc 链一致性人工核对」据此机器化为 3a–3c。
5. **门序纪律**：先出证、后对照注册面锚（`foldagg.rs:497-501` 门序注释原文；电路对 wire pks 自由、T9 实证）——对拍测试里一切 soundness 承重断言必须是**出证后**的锚对照，host 预检（`host_verify_batch` :327-347）只承担公式漂移检测（T4 语义，对 soundness 零证明力，`fold_batch_test.rs:92-95` 原文）。
6. **合约层负例臂**（snforge，进 `poker_dual_settlement.cairo` 测试区，镜像 `settlement_combined_private_tests` :1602-1738 的 setup）：fold 入口对 (i) 未注册 roster digest（"Roster not registered"）、(ii) 16 词段（"Segment length mismatch"）、(iii) combined 哈希 fact（"Settlement fact not registered"）、(iv) 重放（"Hand already settled"）各一条 should_panic——消费面禁混批与前提 K 的直接测试化。

**理由（D5）**：双跑对拍的价值在「同一语料、两条证明生产路径、结算语义零漂移」，而两链 acc 不可跨等是公式事实；把提案的人工核对机器化为 3a–3c + 合约负例臂，是 T1/T9/T10 既有门形（`fold_batch_test.rs:285-321,419-483`）的直接扩展，不引入新验证原语。

---

## 6. 本会话检查清单（诚实条款）

**实读（全文或目标区段）**：`out/poker-fold-proposal.md`（全文）；`cairo/src/fold_batch.cairo`（全文 1-195）；`cairo/src/settlement_stmt.cairo`（全文 1-210）；`src/foldagg.rs`（全文 1-658）；`src/poker_dual_settlement.cairo`（全文 1-2255）；`src/poker_table_registry.cairo`（全文 1-317）；`stark-recursion/src/chain.rs`（全文 1-911）；`stark-recursion/src/stark_final.rs`（全文 1-500）；另抽查 `cairo/src/combined.cairo`（全文）、`src/combined.rs`（全文）、`tests/fold_batch_test.rs`（全文）、`groth16-wrap/src/wrap_circuit.rs:1-70`、`proving-tool/src/settlement_batch_private.cairo:215-250`、`tests/fold_formal_props.rs`（测试名 grep）、`src/lib.rs:1-15`。

**实跑命令与结果**：
- `git status --porcelain && git branch --show-current` → 仅 `?? out/poker-fold-workflow.ts`，分支 `feat/prove_perf`；
- `grep -rn 'roster_registry\|register_roster' poker_contracts/src/ texas/src/starknet/` → **无结果（exit 1）**：C1「未实现」现状本会话复核成立；
- `grep -rn 'set_fold_program_hash\|fold_program_hash\|FOLD_SEGMENT' poker_contracts/src/ stark-recursion/src/` → **无结果（exit 1）**：§4 全部为待实现增量；
- `git log --oneline -- <fold 四文件>` → 均在 a7ef893d（batch verify）提交（冲突 K-3 依据）；
- `ls -d third_party/corelib-2.19.4` → 存在于仓库根（与提案 §2.6 对【设计】路径勘误一致）；
- `wc -l` 四个目标文件（行数与引用范围核对）。

**本会话未跑**：`cargo test`/heavy 出证全套、`lake build`（提案自述 ExecEval.lean 阻塞，未复跑；本规格不依赖测试结果，只依赖静态实读 + grep）。

## 7. 开放点（移交实现阶段，非本规格可定案）

- Q-1：生产 fold 批程序顶层输出形状——提案 §4.1 stark_final 行暗示「[len] ++ K×17 词段 ++ 链尾(4)」形态，但每段 slot 0 的 acc 语义（逐手跑动 acc vs 批终 acc 复制）提案未定；影响 `parse`/`statements` 的 fold 平行版与 fact 绑定负例写法，实现时先钉后码。
- Q-2：cm_digest 的 8 词压缩（`poseidon_hash_many(wire[28..=35])`）需随生产版在 T8 KAT 钉十六进制值（切片 2 词占位值不迁移）。
- Q-3：roster 注册 ACL 的 completeness griefing 残余（owner 同桌注册多套 roster、代注册他人 pks）按提案 F-4 走「玩家自核注册面」产品纪律；PoP 纵深为提案非阻塞项，另立。
- Q-4：若安全评审要求 ald 直接进 M_h（第 4 槽），属公式变更——M_h 域输出、T8 KAT、host 镜像全量重钉；本规格按代码现状钉 3 槽 + 传递绑定（D2a）。
