# 席位容量 8→9 全链路迁移报告（fold 链 + combined + L1 批腿 + 合约）

日期：2026-09-30 · 分支：feat/prove_perf（未 commit，按要求）

## 结论

迁移完成，全套门禁到绿。德扑 9 人桌口径下：

- **settle wire 98 → 102 词**（p/s/m/c 四组席位数组各 +1，尾部字段右移 4 词）；
- **语句公开段 15 → 16 词**（cm×9）→ **combined 信封 16 → 17 词** → **fold 段 17 → 18 词**（FOLD_ROSTER_INDEX 16 → 17）；
- **L1 批腿（settlement_batch_private）同步迁移**：每手入参 98 → 102、批段 16 → 17 词（字面前缀 15 → 16）、解析闸 16k+4 → **17k+4**，与 fold 侧 18k+4 的互斥闸长度碰撞面更新为 **lcm(17,18)=306**（首个双形状 elements=310）；
- **两个程序哈希均从真实出证重钉**（fold + batch），金样与 KAT 均真实重采；
- 五步断言链、域标签、验证方程、acc 链、digest 折叠公式**一行未动**——只有布局常量与循环界右移；全部负例按等效新形状更新（无语义削弱）。

## 改动清单（逐文件）

### Cairo 电路
| 文件 | 改动 |
|---|---|
| `poker_contracts/hand-verify-native/cairo/src/settlement_stmt.cairo` | N_PLAYERS 8→9；SETTLE_WORDS 98→102；s 槽 12+i→13+i、m 槽 20+i→22+i、c 槽 28+i→31+i、ald 36→40、count 37→41、词条区 38→42；公开段 15→16 词（cm×9）。约束 assert 全部原样 |
| `poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo` | SETTLE_WORDS 102、CM_START 31、CM_WORDS 9、STMT_WORDS 16、SEGMENT_LEN 18（=STMT_WORDS+2 自动）；头注释/槽注释同步。电路体逻辑零改动 |
| `poker_contracts/hand-verify-native/cairo/src/combined.cairo` | 仅文档（消费 settlement_statement 泛型 Span，输出 17 词自动成立） |
| `proving-tool/src/settlement_batch_private.cairo` | N_PLAYERS 9、HAND_INPUT_LEN 41+1+60=102；槽位偏移同 settlement_stmt；批段字面前缀 15→16、段长 16→17、main 输出循环 16→17。digest 仍为固定 9 槽全吸收（既有语义，仅循环界右移） |

### 宿主镜像（hand-verify-native）
| 文件 | 改动 |
|---|---|
| `src/combined.rs` | SETTLE_WORDS 102；SettleStatement 四数组 [;8]→[;9]；expected_segment 16 词（cms/循环界 9）；wire_words 摊平自动 102；build_settle_statement 上限 8→9、尾零填充 ..9；prove_combined_layer 段锚定切片 +15→+16 |
| `src/foldagg.rs` | SETTLE_WORDS 102、SETTLE_CM_START 31、SETTLE_CM_WORDS 9、FOLD_SEGMENT_LEN 18、FOLD_ROSTER_INDEX 17；parse_settle_wire 槽位/词条偏移；mint_settle_wire 窗口 2..=9、承诺 9 词；COMBINED_PER_HAND_STEPS 重锚 12,160→12,384（9p 重测）；KEYAGG_STEPS_ANCHOR 保持 1,628（见偏离节） |
| `src/main.rs`（CLI `combined`） | combined_felt8/u64_8 → felt9/u64_9；输出锚定 16→17 词；wire 解析测试语料 9 槽 |

### 链层（stark-recursion）
| 文件 | 改动 |
|---|---|
| `src/chain.rs` | COMBINED_OUTPUT_LEN 16→17、FOLD_OUTPUT_LEN 17→18、FOLD_ROSTER_INDEX 16→17；错误文案/注释（cm@6..=14、total@15、ald@16、slot17 run）同步；测试金向量基 15+1 补位词、词数负例 16/18 与 17/19、预映像切片右移 |
| `src/stark_final.rs` | SEGMENT_LEN 16→17、FOLD_SEGMENT_LEN 17→18、HAND_INPUT_LEN 98→102；解析闸 17k+4 / 18k+4 互斥；**lcm(17,18)=306 碰撞注释新增**（FOLD_SEGMENT_LEN doc：首个双可解析 elements=310，ΣK≤64 时 elements≤1156 可越过——真正禁混批闭合仍靠 program_hash 分槽，解析闸是第一层）；BATCH_PROGRAM_HASH_HEX 重钉；互斥负例长度算术更新（38-4=34 非 18 倍数等） |
| `src/bin/batch_inputs.rs` | HAND_INPUT_LEN 102、SEGMENT_LEN 17、DIGEST_MSG_LEN 1+9×3+1；hand_digest 槽位偏移（13/22/40） |
| `tests/final_k2.rs` | 钉扎断言换新哈希；批段生成器换 17 词形（[16]++金向量 v2 15 词++cm9 补位），批根载荷改由批段派生语句计算（wrap baseline 计划保留供压缩层叶预映像） |

### 合约（poker_dual_settlement.cairo）
- 三段长常量：SETTLEMENT_SEGMENT_LEN 15→16、COMBINED_SEGMENT_LEN 16→17、FOLD_SEGMENT_LEN 17→18；
- **六处**参与窗口 `n >= 2 && n <= 8` → `<= 9`（validate_settlement_segment / proved / v2 / register_roster / combined / fold——比任务列的四处多两处，同为窗口闸，漏改即不一致）；
- 索引右移：v2 族 ald at(14)→at(15)、total at(13)→at(14)、claim_cms 循环 8→9；combined ald at(15)→at(16)、total at(14)→at(15)、cm 循环 9；fold ald at(15)→at(16)、roster at(16)→at(17)、total at(14)→at(15)；
- register_roster：`pks.len() == 2·n`（n≤9 ⇒ 2n≤18，断言式不变，窗口负例更新为 n=10/20 词 pks）；
- 测试：cm 座位循环 8→9、零垫 7→8、互斥负例 `combined_rejects_18_word_fold_segment` / `fold_rejects_17_word_combined_segment`（等效新形状）、跨桌换尾词截断 16→17。

### 证明工具 / 验证器钉扎
| 文件 | 改动 |
|---|---|
| `proving-tool/src/main.rs` | SETTLEMENT_BATCH_PROGRAM_HASH 重钉（出处注释更新为 2026-09-30 K=1 真出证） |
| `proving-tool/prove-batch.sh` | EXPECTED_PH 重钉 + 102 词基础手输入说明；K=1 E2E 全流程复验通过（batch_fact/根回显 电路↔宿主 逐字一致） |
| `fact-verify/src/lib.rs` | PINNED_BATCH_PROGRAM_HASH 重钉；BATCH_SEGMENT_LEN 16→17；工件重采（见下） |
| `proving-tool/output/settlement-batch/` | K=1 proof/public_outputs/summary/manifest 替换为 9 人桌两阶段重采；README 记录新旧两轮 provenance；K=8/K=64 manifests 标记为 8 人桌历史 |

### 测试
| 文件 | 改动 |
|---|---|
| `tests/fold_batch_test.rs` | settle_wire 承诺 9 词；SETTLE_CM_SLOT 31；T1 语料 [2,5,9]；m9_1a (9×8 + 2×8)；m9_1c T=8 全 9 人（新最坏情形）；KAT_CM_DIGEST/KAT_MH/KAT_C 重钉；wire 词数注释 105K |
| `tests/fold_parity_test.rs` | N_PLAYERS 9；语料 9 席零和（6u+u−7u）；信封 17/段 18 词切片与断言；t14 语料 (9,2)+(2,2) |
| `tests/fold_formal_props.rs` | P2 seats ..=9、段长 16、total 槽 seg[14]；P2b 9 席数组；P5 roster [2,5,9] |
| `tests/combined_test.rs` | 前缀折叠负例 pad 到 9 槽；文档 17 词 |
| `tests/golden/fold_t1_p2k2.json` | 全量重采（见金样节） |

## 新布局词表（9 人桌口径，逐槽）

**settle wire（102 词）**：
```
[0] hand_id   [1] registered_digest   [2] n_expected   [3] hand_binding
[4..13]  p0..p8   [13..22] s0..s8   [22..31] m0..m8   [31..40] c0..c8
[40] action_log_digest   [41] action_count   [42..102] w0..w59（30 词条 ×2）
```

**语句公开段（16 词）**：`[0]MAGIC [1]hand_id [2]digest [3]n [4]binding [5..14]cm×9 [14]total [15]ald`

**combined 信封（17 词）**：`[0]chain_acc [1]MAGIC [2]hand_id [3]digest [4]n [5]binding [6..15]cm×9 [15]total [16]ald`

**fold 段（18 词）**：combined 17 词原样 + `[17] roster_digest`（桌内常量）

**L1 批段（17 词，settlement_batch_private）**：`[0]字面16 [1]MAGIC [2]hand_id [3]digest [4]n [5]binding [6..15]cm×9 [15]total [16]ald`；批输出 = `[len] ++ K×17 ++ [acc,hi,lo,fact]`（17k+4）

**fold 批 wire**：`Σ_t(2 + 2·P_t + 105·K_t)` 词（每手块 102+3）；桌数 T ≤ 8、ΣK ≤ 64 政策不动。

## 金样与 KAT 重采记录（全部真实运行采集）

- **金样 `fold_t1_p2k2.json`**：临时把 M8 heavy 测试改为捕获模式 → release 真出证落库 → 还原对照模式 → **独立重跑逐 felt 复现一致**。新值：cairo_acc `0x035c3df15c09c56b…`、roster_digest `0x0517777ae1826362f…`（roster 公式未变故 digest 与旧值相同，实测确认）、wire 216 词（2+4+105×2）、段 2×18 词、steps 12,864。provenance 字段更新为重采记录。
- **KAT（T8）**：`KAT_CM_DIGEST/KAT_MH/KAT_C` 由断言失败输出的 left 值（真实运行）逐个重钉：
  - CM_DIGEST `0x69d003b5d7359531…`（9 词 c0..c8 压缩）
  - M_h `0x0b03e88e70c9c5140…`、c `0x7537f4ba3b536c5e…`
  - `KAT_M1/KAT_MU0/KAT_ROSTER_DIGEST` **实测未漂移**（roster/digest 侧公式与前 2 席语料不变），沿用旧钉值。
- **fact-verify 工件**：`proving-tool/output/settlement-batch/proof.json` 替换为 9 人桌 K=1 两阶段真出证（阶段 B 绑定真实 keccak 根 `0xb078968d…`、batch_fact `0x055a0418…`），`prove-batch.sh` E2E 电路↔宿主对拍逐字一致。

## 门禁与哈希结果

| 门禁 | 结果 |
|---|---|
| `cargo test -p hand-verify-native`（debug 全量） | **64 passed / 0 failed**（12 个 target 全 ok） |
| `cargo test --release … --test fold_batch_test -- --ignored --nocapture`（heavy 全套） | **20 passed / 0 failed**（含 T2/T3/T5/T6/T9/T10/T11/T12 攻击负例、M9-2a/b/c/d、M9-3a/c、M8、T7） |
| `cargo test --release … --test fold_parity_test -- --ignored`（t13/t14） | **2 passed / 0 failed** |
| `cargo test --release … --test combined_test -- --ignored` | **3 passed / 0 failed**（2p 7,428 / 9p 12,384 steps） |
| `cargo test -p stark-recursion`（含 --lib） | **42 passed / 0 failed** |
| `cargo test --manifest-path fact-verify/Cargo.toml` | **5 passed / 0 failed** |
| `scarb build`（scarb 2.19.4，PATH 前置） | **Finished**（仅既有 unused-import 警告） |
| `snforge test`（poker_contracts/） | **130 passed / 0 failed**（含 RPC 依赖的 unshield_fork，一次通过；fold/combined 合约负例全绿） |
| `bash scripts/pin_fold_program_hash.sh` | 重钉成功 + 复跑验证（幂等确认「钉值未变」） |
| `bash proving-tool/prove-batch.sh 1 …`（等价 K=1 出证提哈希） | **OK**（新哈希钉扎 + 链尾对拍一致） |

### 程序哈希 before / after

| 常量 | before | after |
|---|---|---|
| `FOLD_BATCH_PROGRAM_HASH_HEX`（stark_final.rs） | `0x074f0a7f4f082590a4ffb9f929c9fd47dbc131cdb18dc9f5d659105c4b280299` | `0x00668efec4dbe90831565fa723a9b47cd32cd35b5c71125e6fc591919aa2b0cf` |
| `BATCH_PROGRAM_HASH_HEX`（stark_final.rs）+ `SETTLEMENT_BATCH_PROGRAM_HASH`（proving-tool main.rs）+ `PINNED_BATCH_PROGRAM_HASH`（fact-verify）+ `EXPECTED_PH`（prove-batch.sh） | `0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803` | `0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d` |

第三个会变的哈希：**combined 程序**（combined.cairo 内联 settlement_stmt，已改）。它**没有代码内钉扎**（合约运行时 `set_combined_program_hash` / texas 环境变量口径）——部署侧需用新程序重新出证取哈希后 owner 重设，本次无可更新的代码常量，如实记录。

### 性能对照（P=9 vs P=8，同新电路、同机、release）

| 语料 | steps | trace 桶 | 备注 |
|---|---|---|---|
| P=8 K=64 | 414,969 | 2^19 | T7 @ P=8 基线（迁移前旧电路口径 398,146——差 +16,823 来自 9 槽循环对 8 人语料也执行的簿记 ≈263/手） |
| **P=9 K=64** | **418,603** | **2^19** | Δ=+3,634 = keyagg 桌固定层 +153 + 每手簿记 ≈54×64——「+153/桌+簿记、桶不动」预期成立 |
| P=9 K=1 | 8,383 | 2^14 | T7 验收线 8,383 ≤ 12,384+1,628=14,012 ✓（P=8 口径 8,151 ≤ 13,788 亦过） |
| T=8 全 9 人 ΣK=64（m9_1c 新最坏情形） | 431,266 | 2^19 | 余量 2.43×（门 ≥1.5×） |
| combined 9p 每手整证 | 12,384 | — | COMBINED_PER_HAND_STEPS 重锚值 |

## 偏离与遗留（如实）

1. **KEYAGG_STEPS_ANCHOR 保持 1,628（P=8 实测锚）**：T7 语料保持 P=8 作为 steps 门基线（门语义不变），P=9 用临时改跑采集（上表），未把锚改为模型值 1,781——避免把「模型推导」当「实测」写进锚注释。若后续把 T7 常驻 P=9，应实测后改锚。
2. **settlement_private.cairo（P2-M2 单手独立电路）未迁移**：其 ABI 是 98 个独立入参，9 人需 102 个，**顶破 Cairo1 standalone 入参上限 100**——必须重构为 Span ABI，超出本次机械迁移范围。该电路仍为 8 人桌；v2/v3 合约入口的 `circuit_program_hash` 为运行时 owner 钉扎（代码无硬常量），生产上 9 人手应走 combined（已支持 9 人）。
3. **texas 侧 combined 消费面未动**（任务范围外）：`texas/src/starknet/settlement_prover.rs` 本地 `[Felt; 16]` 解析与 8 槽 JSON 输入构造需跟进 17 词/9 槽，否则 texas→combined CLI 子进程缝在运行时不匹配（编译无碍，texas 不链接 SettleStatement 类型）。
4. **proving-tool 全量重编译当前失败（先在问题，非本次引入）**：vendored `third_party/proving` 的 `stwo-cairo-common` 在钉扎 nightly（rustc 1.97.0-nightly 2026-04-14）下 `Mask::to_int` API 漂移编译失败。**已用 git stash 验证**：回退我的 main.rs 改动后 HEAD 状态同样失败（2 errors）。本次所有出证均用既有 release 二进制（9 月 29 日构建，全程工作正常）；main.rs 中的新 BATCH 钉值是源码级（二进制内无运行时消费点，grep 确认仅声明）。
5. **历史工件保留旧哈希**：`scripts/check_final_batch_settlement.sh`（2026-09-29 Monad 链上演练的审计脚本，钉旧哈希+16k+4 形状以核对**当时**的链上证据）与 `out/*.json` 演练明细不改——改了反而失去对历史运行的核对能力。下次用新哈希做链上演练时需产出新 detail 并刷新该脚本。
6. **settlement_batch_private 的 digest 语义保持「固定 9 槽全吸收」**（既有语义仅循环界 8→9）：与链上注册公式只在满桌（n=9）语料下一致——batch_inputs 的基础手语料因此用 9 席全非零构造（/tmp/fold9-base-hand.json，含 8M/−1M×8 零和）。
7. **测试语料右移选择**：T1 扫描 [2,5,9]、m9_1a (9,8)+(2,8)、m9_1c 全 9 人、t14 (9,2)+(2,2)、P5 roster 加 9——让常驻门禁覆盖 9 席；T7 保持 P=8（见偏离 1）。负例全部换等效新形状（如 fold 拒 17 词 combined 段、combined 拒 18 词 fold 段、roster 窗口负例 n=10），断言语义未削弱、未删任何测试。
8. `combined_digest_prefix_fold_semantics`（combined_test）负例的「8 槽全吸收」对照改为「9 槽全吸收」——settlement_stmt 的修复语义（前缀折叠）本身不变。

---

## 附录：主会话独立复核（2026-09-30，迁移代理完成后）

- **常量拍点**（逐处 grep 实读）：settlement_stmt `N_PLAYERS=9`/`SETTLE_WORDS=102`；fold_batch `CM_START=31`/`CM_WORDS=9`/`STMT_WORDS=16`/`SEGMENT_LEN=18`；chain.rs `COMBINED_OUTPUT_LEN=17`/`FOLD_OUTPUT_LEN=18`/`FOLD_ROSTER_INDEX=17`；stark_final `SEGMENT_LEN=17`/`FOLD_SEGMENT_LEN=18` + 解析互斥闸；合约六处 `≤9` 窗口。全部与设计一致。
- **门禁复跑（本会话亲跑）**：debug 全量 **64/0**；heavy fold_batch_test **20/0（45.4s）**；stark-recursion 全量 **42/0**；scarb build **Finished**；`pin_fold_program_hash.sh` 幂等复验（fold 哈希 `0x00668efe…a2b0cf` 未变，无操作）。
- **哈希落库核对**：`FOLD_BATCH_PROGRAM_HASH_HEX = 0x00668efec4dbe90831565fa723a9b47cd32cd35b5c71125e6fc591919aa2b0cf`、`BATCH_PROGRAM_HASH_HEX = 0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d`（stark_final.rs:58/:70 实读；64 位补零口径）。
- **偏离 3/4 的风险裁定**：proving-tool main.rs 的 diff 经核对**仅注释与钉扎常量**（无功能 Rust 改动），未重编译二进制的风险收窄为「二进制内旧 BATCH 钉值无运行时消费点（grep 确认仅声明）」；工具链修复后应重编译并复验一次 E2E。texas 消费面缺口确认在 `texas/src/starknet/settlement_prover.rs:497`（`[Felt; 16]` 合并信封定长 + 8 槽 JSON 构造），**运行时缝会断**，为最重要的跟进项。

---

## texas 消费面迁移（补）

日期：2026-09-30（偏离 3 的跟进闭合）。改动文件（全部实改、全部实测）：
`texas/src/starknet/settlement_prover.rs`、`texas/src/starknet/dual_settle.rs`、
`texas/src/starknet/hooks.rs`、`texas/src/starknet/config.rs`、`texas/src/pokergame/actions.rs`（后三者仅注释）。

### 钉值迁移（旧 → 新）

| 位置 | 旧 → 新 |
|---|---|
| settlement_prover.rs `MAX_PARTICIPANTS` | 8 → **9**（players/signs/magnitudes/commitments 四组定长数组、`build_request` 上限报错文案 8→9、`derive_claim_cms`/`public_segment_felts`/`expected_public_segment` 随常量自动变长——实测 `expected_segment_shape` 断 16 词、cm 槽 5..14、total@14、ald@15） |
| `inputs_felts` 词数（注释+测试） | 37 标量/38+60=98 → **41 标量/42+60=102**；槽位断言右移（s0@13、m0@22、c0@31、ald@40、count@41、末垫词@101） |
| `CombinedProofOutput::public_output` | `[Felt; 16]` → **`[Felt; 17]`**；stdout 解析错误文案 `len != 16` → `!= 17`；`settlement_fact` 容量 1+16 → **1+17**、文档「整段 16 词」→17；MAGIC 锚 `public_output[1]`、`cairo_acc == public_output[0]` 两断言**未动** |
| `prove_settlement_private` 段长闸 | `want_len = 5 + MAX_PARTICIPANTS + 2`（8 席 15）→ 随常量自动 16，未重写 |
| dual_settle.rs 入口文档/注释 | v2 `segment(15)` → **16**（settle_entry_calldata doc + submit 流程注释）；combined `segment(16)`/`段16` → **17**（入口 doc、combined 分支注释、hooks/config 同步共 5 处） |
| dual_settle.rs settle_entry 测试 | v2/proved_private/snip36 段 15→16、长度 2+15(+2)→2+16(+2)、commitment 槽 17→18；combined 测试更名 `…16_word…`→`…17_word…`、段 16→17、断言尾词 `calldata[18]==316`（segment[16]=ald，对照合约 at(16) 实读对齐） |
| actions.rs `ACTION_LOG_MAX_ENTRIES` 注释 | 补注：9 席总量 42+60=102 超出 v2 standalone 100 参上限；combined 路径 Span ABI（combined.cairo `fn main(prev_acc, tasks: Span, settle: Span<felt252>)` 实读确认）沿用 30 词条上限，不受该限 |

### v2 单手电路缝的显式化（偏离 2 的运行时侧）

- **`prove_settlement_private` 前置闸**（settlement_prover.rs，remote attestation 调用点）：新增常量 `V2_CIRCUIT_INPUT_WORDS = 98`（钉未迁电路的 ABI 词数）+ 方法首显式长度比对，失配即返回可读错误：
  `v2 single-hand circuit not migrated to 9 seats (ABI 98 words, request has 102) — 9-seat hands must settle via the combined path`——把失败从「远端电路解析深处失配」提前到「近处可读」，不静默（调用方按既有语义 warn + 回退，结算不阻塞）。
- **`export_settlement_private_inputs` 警示**：导出 inputs JSON 时若词数 ≠ 98 打 `tracing::warn`（文件仍导出：combined 语句同源复用，但 v2 prove-settlement 管线不可消费）。
- **dev local（`shadow::ProverMode::Local`）路径核对**：`local_register_settlement_fact` 用本地推导 16 词段直登 fact——与新合约 `SETTLEMENT_SEGMENT_LEN=16` 一致，devnet e2e 闭环**不受** v2 电路未迁影响（fact 不经电路）；remote attestation 才吃前置闸。

### 桌注册面（任务 5，如实）

`poker_contracts/src/poker_table_registry.cairo` 全文实读 + texas 建桌路径 grep：`create_table` 只收 `params_hash`（承诺态，不含明文 max_players），**无任何 ≤8 上限断言**；texas `register_table`/`compute_params_hash` 纯转发 config，亦无钉死。**无需改动**。`MAX_PLAYERS_PER_TABLE` 默认 5 为运营配置，按任务要求未动。

### 门禁（本会话亲跑）

| 门禁 | 结果 |
|---|---|
| `cargo build -p texas` | **Finished，0 error**（17 条既有 warning，均先在） |
| `cargo test -p texas` | **221 + 6 passed / 0 failed**；8 ignored（向量生成器×3、recursion_e2e 需 proving-tool release 二进制、bench、`e2e_starknet_buyin_play_settle_calldata` 需活的 STARKNET_RPC_URL/devnet）+ 1 ignored（devnet_smoke，同因）——全部为外部环境依赖，非本次引入 |
| 定向复跑 | settlement_prover 10/10、settle_entry 5/5 全绿 |

### 遗留（如实）

1. **v2 单手电路本体仍未迁**（偏离 2 原样）：前置闸使其失败可读而非神秘；迁它需 Span ABI 重构（102 词 > 100 参上限）。根 crate `src/settlement_private_circuit.rs` 仍为 8 席（v2 参考实现，随电路一起迁），settlement_prover.rs 的 `MAX_PARTICIPANTS` 注释已改为如实标注这一分叉。
2. **combined 程序哈希仍无代码内钉扎**（沿主报告结论）：texas 侧从 config/链上视图读取（`combined_program_hash_felt()`），部署侧需用 9 席新程序出证后 owner 重设。
3. 需要链上/devnet 才能跑的 e2e（devnet_smoke、buyin_play_settle_calldata）未在本地执行——texas→combined 子进程缝的**端到端**对拍待下次 devnet 演练（单元面：CLI 输入 JSON 9 槽构造与 17 词 stdout 解析形状已由单测钉住）。

---

## 复核与收尾更新（2026-09-30 晚，主会话）

- **偏离 3 已解决**：proving-tool 重编译失败系**用错工具链**所致（会话默认 nightly 下 vendored stwo API 失配）——在 `proving-tool/` 内按 `rust-toolchain.toml` 钉扎的 nightly-2026-01-15（rustc 1.94.0-nightly 2026-01-14）构建**正常**，新二进制已产出并验证：`pin_fold_program_hash.sh` 用新二进制 K=1 真出证，fold 哈希 `0x00668efe…a2b0cf` 与钉值逐字一致（幂等无操作）。batch（settlement_batch_private）E2E 因 /tmp 语料已失未用新二进制复跑——同一编译器栈，程序哈希一致性由 fold 侧旁证；下次跑 `prove-batch.sh` 时顺带核对 `0x03977925…faf74d` 即可。
- **texas 消费面已迁移**（见「## texas 消费面迁移（补）」）：`MAX_PARTICIPANTS=9`、combined 输出 `[Felt;17]`、v2 缝显式闸；`cargo test -p texas` 221+6/0，主会话拍点复核实读（:30/:328/:541/:723）。9 人桌现在从证明层到游戏层全通。
- **仍开放（有意延后）**：v2 单手电路 settlement_private.cairo 的 Span ABI 重构（98 独立入参顶破上限 100，v2 路径已有显式闸与指路文案，生产 9 席手走 combined——如需激活 v2 再立项）。

---

## v2 电路 Span ABI 重构（补）

日期：2026-09-30（「仍开放」项的闭合）。偏离 2 的原样遗留已消除：v2 单手证明路径恢复可用。

### ABI 前后形态

| | before | after |
|---|---|---|
| `fn main` 签名 | 98 个独立命名入参（p0..p7/s0..s7/m0..m7/c0..c7/w0..w59 各自命名） | `fn main(words: Span<felt252>)`（fold_batch 同款写法：`words.at(i)` 索引 + `words.len() == 102` 断言 `"BAD_SETTLE_LEN"`） |
| 席位 | 8（N_PLAYERS=8） | 9（N_PLAYERS=9） |
| wire 布局 | 头 4 + p/s/m/c 各 8（s@12+i/m@20+i/c@28+i）+ ald@36 + count@37 + 词条 38..98 | 头 4 + p/s/m/c 各 9（s@13+i/m@22+i/c@31+i）+ ald@40 + count@41 + 词条 42..102——**与 settlement_stmt.cairo SETTLE_WORDS=102 逐槽一致**（实读对齐） |
| prove-hand flat 输入 | 98 词 = 命名参直排 | 103 词 = `[102] ++ wire`（Span `[len, elements…]` 摊平，与 combined/fold_batch/settlement_batch 同约定——batch 的 `Array<felt252>` 前缀写法实读对照） |
| 公开段 | 15 felt（cm×8） | 16 felt（cm×9）= 合约 v2 入口 `SETTLEMENT_SEGMENT_LEN=16`（poker_dual_settlement.cairo:302 实读确认）；runner 序列化为 `[16] ++ 16 词`，消费侧从 MAGIC 锚定 |

**语义不换**：电路体全部约束逐条保留（digest sponge、动作日志 30 槽整链重放 + 合法默认规则、sign∈{0,1}、|delta|≤u64、零和、人数、认领承诺公式），只把命名参数引用改为槽位索引、循环界 8→9。**digest 保持「固定 9 槽全吸收」**（既有语义仅循环界右移，与 settlement_batch_private 同口径）——与共享模块 settlement_stmt 的「按实际参与者前缀折叠」仍是两处分叉：链上注册 digest 按实际人数折叠，本电路只在满桌（9 席全非零）语料下与注册值一致，n<9 的手走 combined（电路头注释与 dual_settle.rs 入口文档均已如实标注）。

### 改动文件

| 文件 | 改动 |
|---|---|
| `proving-tool/src/settlement_private.cairo` | Span ABI 重构 + 9 席（上表全部）；值域注释 2^67→2^68（9·2^64） |
| `src/settlement_private_circuit.rs`（根 crate 参考实现） | MAX_PARTICIPANTS 8→9（四数组/SCOPE/AIR 列宽随常量自动）；测试语料 8→9 槽（零变动 +1 槽）；夹具 `write_prove_hand_fixtures` 改产 flat `[102]++wire`（103 hex）+ 16 词期望段 |
| `proving-tool/scripts/prove-settlement.sh` | 负例索引右移：篡改 digest `inputs[1]`→`inputs[2]`（+1 前缀）；非法默认 `38+3`→`1+42+3`（+1 前缀 +4 席移）；头注释记新 ABI |
| `proving-tool/scripts/prover_service.py` | 仅协议 docstring（98 词→103 词 flat 形态）；逻辑零改动（inputs 透传 prove-hand） |
| `texas/src/starknet/settlement_prover.rs` | **解闸**：`V2_CIRCUIT_INPUT_WORDS` 98→**102**；gate 错误文案去掉「9 席手必须走 combined」指路（保留近处可读长度闸）；新增 `flat_inputs_hex()`（`[102]++wire`）——`inputs_json()` 与 HTTP body `inputs` 改用 flat 形态（导出 JSON 直接可被 prove-hand 消费）；`inputs_felts()` 本体仍产裸 102 词 wire（槽位断言不变）；模块头/MAX_PARTICIPANTS/「41 个入参」旧注释按现实改正（它描述的是 wire 前 41 个标量词 ald@40，非旧聚合形态入参数）；export 警告去指路；测试 `inputs_json_is_hex_array` 升级为钉 flat 前缀（0x66/flat[1]=hand_id/flat[2]=digest） |
| `texas/src/starknet/dual_settle.rs` | 仅 v2 入口文档：「未迁 9 席」→「已迁（Span ABI），digest 固定 9 槽全吸收 ⇒ 非满桌语料 DIGEST_MISMATCH fail-closed，n<9 走 combined」 |
| `texas/src/pokergame/actions.rs` | 仅 ACTION_LOG_MAX_ENTRIES 注释：standalone 100 参上限不再约束（Span ABI） |

`proving-tool/src/main.rs` **无需改动**（如实）：prove-hand CLI 是通用 `--program/--inputs` 管线，没有 settlement-private 专属模式——「模式」实体在 prove-settlement.sh + 根 crate 夹具测试 + prover_service.py，本次全部更新；main.rs 内 grep 无 ABI 相关内容。`slimming-matrix.sh` 按位消费夹具与程序，零改动兼容。

### 真出证与程序哈希（本会话亲跑）

`bash proving-tool/scripts/prove-settlement.sh`（K=1 单手，全新夹具目录）**ALL PASS**：

- prove 8.87 s / verify OK / **verified=true**（summary.json）/ **5,632 steps** / total 9.75 s；
- 跨语言对齐：**16 felts aligned from MAGIC**（电路公开段 ↔ Rust starknet_crypto 参考值逐 felt 一致）；
- 负例双拒：篡改 registered_digest → 运行中止无证明；非法默认动作（auto FOLD 谎称 Check）→ 中止无证明；
- 工件落 `proving-tool/output/settlement/`（proof/public_outputs/summary 刷新；.tampered/.illegal 目录仅 executable.json，无 proof）。

**新程序哈希（64 位补零口径）**：

```
0x00ee3b4c4e758aa7c2f5ea2630d7f3147590c3bc3e6a160a6a97910f03416d48
```

v2 电路哈希**仓库无代码常量**（实读确认：合约侧 `set_circuit_program_hash` 为 owner 运行时写入的 storage，texas 侧经链上视图读取）——部署侧需用新程序出证取哈希后由 owner 重设，本次只记录不凭空加常量。

### 门禁（本会话亲跑）

| 门禁 | 结果 |
|---|---|
| `cargo test -p poker_texas_air` | **241 passed / 0 failed**（230 lib + 10 shuffle-stage0 + 1；115 ignored 为既有 heavy/环境项） |
| `cargo test -p texas` | **227 passed / 0 failed**（221 + 6；8+1 ignored 为既有外部环境依赖项，与上一节口径一致）；settlement_prover 定向 10/10 |
| `cargo test -p hand-verify-native` | **64 passed / 0 failed**（与迁移后基线 64/0 持平——本次未触碰该 crate，纯回归确认） |
| `prove-settlement.sh` E2E | **ALL PASS**（上节） |

### 偏离与注记（如实）

1. **根 crate 门禁需 `RUST_MIN_STACK=16777216`**：`canonical_shuffle_chain_stage0::stage0_reconstruct_segment_single_batch` 在默认测试线程栈下 debug 构建栈溢出。**git stash 验证为 HEAD 先在问题**（回退本次改动同样溢出；16 MB 栈下通过）——与 settlement_private 无关（texas_canonical_air 模组），非本次引入，如实记录。
2. **digest 固定 9 槽全吸收语义保留**（按「换 ABI 不换语义」纪律）：v2 单手路径对非满桌（n<9）语料会在电路内 DIGEST_MISMATCH fail-closed——此时仍应走 combined（settlement_stmt 前缀折叠）；满桌语料 v2/combined 两路等价可用。若后续要把 v2 也改前缀折叠，属语义变更需另立项。
3. **`inputs_felts()` 保持裸 wire（102 词）**：作为 settle wire 单一真源（combined 序列化、槽位断言、长度闸同用）；Span 摊平前缀只在「物化 flat 输入」的出口（`flat_inputs_hex()`/`inputs_json()`/HTTP body）加一次，避免三处各自维护偏移。
4. **prover_service.py 未做输入形状校验**（既有行为）：畸形 inputs 由 prove-hand/电路解析失败兜底（非 200 + error），未加前置断言——如需收紧另行小改。
5. 8 席旧哈希无仓库记录（运行时钉扎、旧工件已被本次真出证覆盖刷新），故哈希只有新增记录、无 before/after 对照表。
