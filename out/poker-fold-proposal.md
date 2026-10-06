# poker-fold（手级聚合签名折叠终证）立项报告

- 日期：2026-09-30
- 分支/工作区：`feat/prove_perf`（fold 切片文件均未 commit：`fold_batch.cairo` / `foldagg.rs` / `fold_batch_test.rs` / `fold_formal_props.rs` 为 untracked，`src/lib.rs` 仅 +1 行 `pub mod foldagg;`，见 `poker_contracts/hand-verify-native/src/lib.rs:9`）
- 输入材料：FoldDesign v2（按攻击复审修复后重发）、安全复审（verdict=fail-with-fixes，针对 v1）、切片实测记录；三者下文分别称【设计】【审方】【切片】。本报告对可本地核验的引用做了逐条实读复核，并补跑了门禁与 heavy 测试（见 §6 与附录 A）。

---

## 0. 结论先行

**判定：go-with-conditions（有条件立项）。**

一句话理由：折叠思路在密码学上已被攻击复审救活——v1 的两个致命攻击（A1 无钥知识伪造 / A2 整组换 roster）均在真实 prove-hand 下出证成功，v2 的修复（keyagg 锚定 + roster_digest 进公开输出 + 消费面对照）对症且已落成可跑的电路切片；切片实测远超验收线（每手 505–688 steps，验收 ≤2.2k）。但 **soundness 的闭合点（roster_registry 合约消费面）在代码库中尚不存在**（`grep roster_registry|register_roster` 于 `poker_contracts/src/`、`texas/src/starknet/` 均 0 命中，本轮实跑），生产形状（并 98 词 settle wire、公开段 16→17 词）也未实现——立项批的是「方向 + 切片」，上线路径由下列硬条件门控。

**硬条件（不做完不得上线 fold 模式）：**

| # | 条件 | 现状 |
|---|------|------|
| C1 | Starknet 合约新增 `register_roster`（owner-gated + 事件）+ `roster_registry` 存储 + fold/combined 入口 `segment[16]` 对照 | 未实现（本轮 grep 0 命中）；切片阶段仅 host parity 门模拟（T9/T10） |
| C2 | 生产版 fold_batch.cairo：并入 98 词 settle wire、c 的 M_h 槽换真槽（wire[1]/[2]/[36]+cm_digest）、公开段 16→17 词 | 切片版不含 settle wire，M_h 的 m1/m2/cm_digest 为切片占位槽（`fold_batch.cairo:26-30` 自注） |
| C3 | K=64 在 5200M 笼内复测（steps/RSS/MemoryCurrent 门禁，沿用工程报告 §5.7.3） | 3.35 GiB/32,353 steps 均为本机实测，未入笼 |
| C4 | `src/airs_lean/AirsLean/ExecEval.lean` 仓库侧修复后重跑 `lake build` 全根，确认 Fold/Chain/Settlement/KeyAgg 四层共存 | 审方实测 HEAD 575d0d66 即不可编译（:381/:387/:412），阻塞全根；本轮未复跑 lake build |
| C5 | 声明域纪律：fold 模式仅在与「真验 STARK 的站点 + 前提 K（roster 对照）」同时成立的面上宣称聚合签名效力；fact-registry 面 / wrap 腿的声明按降级文档交付 | 文档义务，随部署交付 |
| C6 | 聚合协议外部评审（nonce 并发会话/Drijvers 面）+ poseidon-as-RO 实例化论证一次 | 未开始；未做前生产协议强度不宣称 |

非阻塞但上线声明前需要：PoP 验证面自建（vendored corelib 无验签 syscall，本轮 grep 实证），未建前退守 BDN ROM plain-PK 强度并如实标注。

---

## 1. 方案

### 1.1 核心思想

现行每手一张 Cairo STARK 证（combined，canonical_small 2.0–2.4 GiB / 2–3.5 s/手，`poker_contracts/hand-verify-native/docs/combined-perf-2026-09-29.md:57-58,66`）。fold 方案把「整手签名验证」改为**全员 MuSig2/BDN 式聚合签名 + 单方程检查**，把同一牌桌的 K 手折成**一张批证**：roster/keyagg 每批只算一次，每手只剩 3 次 poseidon + 单方程 EC 检查 + z̄ 范围检查，acc 链公式逐字复用现行 batch_fact 折叠（`settlement_batch_private.cairo:231-241` / `stark-recursion/src/stark_final.rs:84-97`，本轮实读确认）。

### 1.2 电路断言链（切片已实现，`cairo/src/fold_batch.cairo`，本轮全文实读）

1. **满阶编码**：roster 逐 pk on-curve（`EcPointTrait::new` Option 模式）+ 非恒等（`NonZeroEcPoint`）+ 每手 z̄<n（u256 比较，RangeCheck）——依据审方 F-1 实测：Stark 群阶 n 素、cofactor=1、无 2-torsion ⇒ on-curve + 非恒等即满阶（`fold_batch.cairo:88-96,138-140`）；
2. **电路内 keyagg**（修复 1）：μ_i = poseidon([keyagg_label, n, pkx, pky])（BDN 系数，CCS'06 plain-PK 形状），P̄ = Σ μ_i·pk_i；roster_digest = poseidon([roster_label, n] ++ pks) 从同一批 wire pks 电路内重算（`fold_batch.cairo:97-108`）;
3. **roster_digest 作为公开输出词**：输出 = [acc, roster_digest]（`fold_batch.cairo:189-194`）。soundness 不在电路内闭合——wire pks 在电路内仍是自由的（T9 实证电路对整批换钥照样出证），闭合点在消费面对照注册值（H1 单射 ⇒ wire pks == 注册 pks ⇒ P̄ == keyagg(注册 roster)）；
4. **挑战 c 电路内重算**（修复 2/4）：c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])，M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])——m1/m2/cm_digest 取每手固定 witness 槽（生产 = settle wire[1] registered_digest / wire[2] n_expected / wire[36] action_log_digest + cm 槽），hand_binding 进 c ⇒ 跨手重放必改 c（`fold_batch.cairo:142-149`）；
5. **单方程**：z̄·G − c·P̄ − R̄ == O assert，残差非恒等即 panic → 无证明，fail-closed（`fold_batch.cairo:154-172`）。

域标签五件套（keyagg/roster/msg/sig/claim .v1）钉死于 `fold_batch.cairo:66-70`，T8 KAT 逐 felt 对拍。

### 1.3 与现行 combined 的结构差异

- 结算语句/语句三元组/keccak 批根公式**不动**（`settlement_stmt.cairo` 98 词 wire 与 15 词公开段逻辑复用，本轮实读确认其 digest 折叠、NOT_ZERO_SUM、COUNT_MISMATCH、claim 承诺输出全链）；变的只有「哪个程序生产 fact」与输出 +1 词（roster_digest 尾插 index 16，索引 0–5 不动，MAGIC/binding 兼容 `chain.rs:185-186` 与 `wrap_circuit.rs:44-50`）。
- 动作级逐条 σ 移出终证，host fail-closed 直验保留（`handbatch.rs:438-613`，【设计】引用）——因现行电路内逐条 σ 同样是「自由 pk + c 不含 pk」（本轮实读 `combined/dual/hand_verify.cairo:259-305`：c_input = [label, payload 5–8 词, R 坐标]，无 pk），此项实为无损失项（审方 A7 修正，两版对齐）。

---

## 2. 安全论证与攻击复审

### 2.1 敌手模型与假设

operator 完全恶意；roster ≤N−1 腐败。假设：① ODL/DLP（Stark curve；n 素/cofactor=1 由审方 F-1 实测钉死）；② Poseidon sponge RO（与现行挑战公式同假设类）；③ MuSig2/BDN ROM plain-PK 不可伪造（文献 CCS'06）；④ STARK 知识可靠性 96 bit（canonical_small，pow_bits=26——本轮读 `/tmp/fold-direct-k64/summary.json` 确认 `security_bits: 96`、`pow_bits: 26`）。

### 2.2 v1 被证实的攻击与 v2 修复的对应关系

| 攻击（审方真跑出证） | 实测证据 | v2 修复 | 修复是否进切片 |
|---|---|---|---|
| A1 无钥知识伪造（P̄ 为 wire 自由词，攻击者自签） | `/tmp/aggsig/out_forge0_replay/summary.json`：**verified=true, steps=388**（本轮实读复核；审方命令逐位一致）；z̄+1 负对照 `out_forge0_bad/` 仅 executable.json 无 proof | agg0 形状弃用；电路内 keyagg + roster_digest 进公开输出 | ✅ 电路已实现；❌ 消费面（roster_registry）未实现（C1） |
| A2 整组换 roster（agg1 形状 roster_digest 自由） | `/tmp/aggsig/out_agg1_forge/summary.json`：**verified=true, steps=587**（本轮实读复核） | roster_digest 电路内从 wire pks 重算 + 公开输出 + 合约对照注册 | ✅ 电路；❌ 合约面（C1） |
| A3 ⑤ 非注册绑定 | 本轮实读 `combined.cairo:58` = `assert!(hand_binding == settle_binding, "TASK_BINDING_MISMATCH")`——确系 input-vs-input 内部一致，与链上注册面零关系 | 设计不再依赖它；注册绑定由 segment[16] 对照承载 | ✅ 设计文本已更正 |
| A4 EVM 腿推翻主信任声明 | 本轮实读 `groth16-wrap/src/wrap_circuit.rs:23-29` 信任边界注释原文：**「本电路不验证 STARK……被攻破的 operator 可以包装任意格式良好的伪造 output 上链」** | fold 模式 Monad 腿只走 FRI 验证路径（`stark_final.rs:3-10` 裁定「Groth16 全出局」，本轮实读确认）+ roster_digest 进公开输入 + Monad 侧 roster_registry；wrap 腿若保留则声明降级为「operator 背书 + 电路一致」 | ❌ 迁移期工作（C5） |
| A5 认领承诺不在共签消息 | 本轮实读 `compute_settlement_digest`（`poker_dual_settlement.cairo:331-357`）：吸收 [hand_id, (player,sign,\|delta\|)*, ald] 收尾——确不含 cm | cm_digest = poseidon(wire[28..35]) 进 M_h；合约消费点 `segment.at(6+i)`（现行 ：1348，本轮实读；材料引 ：1389-1392 为同消费点旧行号） | ✅ 电路（切片占位槽语义）；生产槽位随 C2 |
| A6 测试计划缺陷（T4 不可实现、无攻击负例） | — | T4 改 host-parity（零 soundness 证明力，注释注明）；新增 T9–T12 四个攻击负例入库并真跑 | ✅ 本轮实跑（见 §3.2） |
| A7 现行基线高估 | `hand_verify.cairo:259-305` 实读确认 | 安全对比表按实修正（§2.5） | ✅ |

### 2.3 修复后定理（【设计】安全性节，本报告采信其结构、注明承载前提）

> A 控 operator + ≤N−1 玩家。若站点 C 的验证接受含手 h 的批，则：(i) STARK 抽取器得见证；(ii) 电路内 c=RO(·) 重算、z̄·G=R̄+c·P̄ 成立、P̄=keyagg(注册 roster) ⇒ (M_h,P̄,R̄,z̄) 是注册 roster 对 M_h 的有效聚合签名 ⇒ 由 MuSig2/BDN EUF-CMA ⇒ M_h 被全体注册玩家共签；(iii) M_h 钉死 wire[1]/[2]/[36]/cm 槽 ⇒ 金额、日志、人数、认领盐全为玩家所签；hand_binding ∈ c ⇒ 跨手重放必破。伪造概率 ≤ ε_MuSig + ε_H1碰撞 + 2^-96。

**关键诚实条款（承自【设计】/【审方】）**：第 (ii) 步显式条件于**前提 K**——消费面 C 满足 `segment[16] == roster_registry 注册值` 且注册值 operator 不可单方改写。**K 不成立时（如现行 fact-registry/wrap 面），定理退化为「电路算术一致 + operator 背书」，与现行 wrap 面同级**——此降级已写入声明域（C5）。

### 2.4 失败攻击（攻不破，附原因）

| 攻击 | 否决依据 |
|---|---|
| F-1 小阶点/parity-retry 伪造 | Stark curve 无 2-torsion（gcd 实测）、n 素（Miller-Rabin 40 轮）、n·G=O、cofactor=1 ⇒ on-curve+非恒等即满阶（审方 F-1 实测；电路 T6 注释已附满阶依据，`fold_batch.cairo:88-89`） |
| F-2 跨手重放 (R̄,z̄) | c 电路内重算且 hand_binding ∈ c ⇒ 换手必换 c（T3 负例活跃） |
| F-3 金额/日志分离 | registered_digest=wire[1] 且语句内 assert digest(settle)==registered_digest（`settlement_stmt.cairo:62-65,87-89` 本轮实读确认）；c 读同一 witness 槽即钉死；合约侧同款锚已存在（`poker_dual_settlement.cairo:1323,1326`：segment[3]==registered_digest、segment[15]==action_logs，本轮实读） |
| F-4 rogue-key | BDN 系数（μ 只经 RO 依赖各自 pk）在 ROM plain-PK 下抗 rogue-key（CCS'06）；Lean KeyAgg 四命题 + 真曲线 proptest p3 三件套支撑（fold_formal_props 12/12，本轮实跑通过）；**注意**：注册 ACL 未定义时 operator 代注册他人 pks 是 completeness griefing 面（须玩家自核，产品侧纪律） |
| F-5 acc 链/混批/双花 | batch_fact 电路内重算、逐词进公开输出；settled_bindings 幂等（`poker_dual_settlement.cairo:436` 本轮实读）；fold/combined 两链 program_hash 不同禁混批；审方 Lean Chain.lean + proptest p1/p1b + 既有 combined_batch 测试复跑通过（审方真跑，本报告转引） |

### 2.5 信任界对比（按 A4/A7 修正后的诚实版）

| 维度 | 现行 combined | folded v2 | 判定 |
|---|---|---|---|
| 电路内动作/身份层 | 直验 σ 但 pk 为 wire 自由词、c 不含 pk（`hand_verify.cairo:259-305` 实读）——只证「(s,R,c,pk) 自洽」，不证 pk∈注册玩家 | P̄ 锚定注册 roster（条件于 K）⇒ 手级签名身份锚定 | folded **更强**（条件于「真验 STARK + K」） |
| 金额层 | operator 声明 + 良构（wrap_circuit.rs:23-29 实读） | 全员共签 M_h（含 cm） | 站点级更强；registry/wrap 面不变 |
| 动作级逐条 σ | 证明内直验（同上自由 pk） | 移出终证，host fail-closed 直验 | 等价（现行电路内亦不锚身份，无损失项） |
| 证明成本 | 1×FRI/手 | 1×FRI/批（K≤64） | 数量级改进（§3） |

### 2.6 形式化验证现状与明确不覆盖

- **本轮实跑**：`fold_formal_props.rs` 12/12 通过（p1 fold binding no-collision、p1b chain history、p2/p2b 零和含 u64::MAX 边界、p3 rogue 三件套、p4 binding/重组、p5 completeness parity）——宿主公式层。
- **审方真跑、本报告转引未复跑**：Lean Fold/Chain/Settlement/KeyAgg 编译通过；heavy proptest（真 starknet poseidon 256 组）；**caveat**：电路内 NOT_ZERO_SUM 未在电路层验证（fold_batch 尚未并 settle 语句）；完备性只验证到宿主公式层；P3 结论 = RO 不动点难度（无 PoP 亦然），PoP 为纵深防御且合约面不存在（`register_hand` `poker_dual_settlement.cairo:679-690` 仅单 felt g_attestation，本轮实读；vendored corelib `syscalls.cairo` grep `verify_signature` 无结果，本轮实跑，路径 `third_party/corelib-2.19.4/`——注意【设计】写的 `poker_contracts/.../third_party/` 路径有误，实际在仓库根 `third_party/`，summary.json 的 corelib 字段同证）。
- **明确不覆盖**：全员 N/N 共谋；全员被 UI 欺骗共签错账（签名只证「签了」，不证「签对了」）；数据可得性；注册 ACL 未定义时的代注册 griefing；STARK 96 bit 本体与 canonical_small 参数绑定本轮未复测；量子/Poseidon 密码分析与现行同级。

---

## 3. 切片实测 vs 基线对照表

### 3.1 主表（同机、canonical_small、pow26/96bit）

| 配置 | steps | 桶 | prove | 峰值 RSS | proof | fact 密度 | 口径/出处 |
|---|---|---|---|---|---|---|---|
| **fold 切片 K=1**（P=8） | **2,149** | 2^12 | 1.89 s | 1.99 GiB | ~14.1 MB | 1 批 | 【切片】/usr/bin/time 直跑；steps/verified 本轮经 `/tmp/fold-direct-k1/summary.json` 实读复核（verified=true, prove 1804ms） |
| **fold 切片 K=8** | **5,501** | 2^13 | 1.62 s | 2.04 GiB | ~13.9 MB | 1/8 批 | 同上 |
| **fold 切片 K=32** | **17,009** | 2^15 | 2.52 s | 2.53 GiB（测试进程树，偏高估） | ~14.1 MB | 1/32 批 | 同上（RSS 口径 caveat 见【切片】notes 6） |
| **fold 切片 K=64** | **32,353** | 2^15 | 3.65 s（wall 3.77 s） | **3.35 GiB** | 14,080,631 B | **1/64 批** | steps/verified 本轮双重复核：`/tmp/fold-direct-k64/summary.json` 实读 + 本轮 heavy 实跑 T7 表逐位一致 |
| 每手边际 | (32,353−2,149)/63 = **480**；K=8 摊销 688 | — | — | — | — | — | 验收线 ≤2,200/手：**过**（实测 505/506/531/688） |
| T1 正例 P=2/5/8×K=8 | 4,499/5,000/5,501 | 2^13 | — | — | — | — | 本轮 heavy 实跑通过；reverify 35/30/29 ms |
| 现行 combined（1 手/证，9p） | 12,160 | — | ~2.1 s/手 | 2.0–2.4 GiB | 15.7 MB | 1/手 | 【切片】同机复测；7,204 steps(2p) 与 `docs/combined-perf-2026-09-29.md:14` 一致（本轮实读）；2.0–2.4 GiB/2–3.5 s 见同文档 ：57-58,66 |
| 纯结算批程序（无签名层） | 边际 **9,405/手**；K=64 = 602,199 = **2^20 的 57.4%** | 2^20 | — | 2.70–3.69 GiB（三轮） | — | 1/64 批 | `out/stark-recursion-engineering-report.md` §3.6（本轮实读确认 9,405.3 与 57.4% 两数） |
| K4 wrap 腿（对照，不同度量） | 18.3M Groth16 约束/电路 | — | 2×K4 串行 573.9 s | ~14 GiB | — | — | ask 给定的会话基线 +【切片】注明「未本轮复测」；Cairo steps ≠ Groth16 约束，仅按「批证替代每手证」意义比较 |

**三轴结论（切片层，同机同参数，成立）**：steps/手 12,160→506（**24×**）、出证 wall ~2.1 s→~0.06 s（**35×**）、fact 密度 1/手→1/64 手（**64×**）。

**诚实边界（必读）**：
1. 切片 wire **不含 98 词 settle wire**（设计明示本切片不含），M_h 的 m1/m2/cm_digest 为切片占位槽——故 506/手 ≠ 生产 fold 的每手成本。生产形状设计估 **≈11.3k steps/手**（keyagg 层实测 1,628 = 404+8×153 + 范围检查估 100–200 + 结算边际实测 9,405），vs combined 12,160/手 steps 轴收益收窄到 ~7%；**结构性收益在单批单证/fact 密度 64×，不在 steps**。11.3k 为估算待复测（【设计】自标）。
2. 生产 K=64 ≈ 723k steps = 2^20 桶 69%（vs 现行纯结算批 57.4%）——仍装得下，实测余量 1.74×→~1.44×；**切片 3.65 s 的 wall 是 2^15 桶的，2^20 桶的生产 wall 须笼内复测**（FRI 出证时间桶内近似常数，见 combined-perf 文档 ：24-25）。
3. 本轮 heavy 复跑的 prove 时间（K=1 6.9 s 冷编译）高于【切片】直跑 1.89 s（编译缓存热）——时间轴以直跑口径为准，steps 轴两轮逐位一致（2,149/5,501/17,009/32,353）。

### 3.2 门禁与攻击负例（本轮实跑）

- `cargo test -p hand-verify-native`（debug）→ **exit 0**；可见段：fold_batch_test 9 passed/0 failed/10 ignored，fold_formal_props **12 passed/0 failed**。
- `cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture` → **10 passed / 0 failed，19.03 s**：T1 三档 roundtrip、T2/T3/T6/T11/T12 电路 panic 负例、T5/T9/T10 出证后 parity 门拒、T7 扫描。测试名带 `_attack_A1/_attack_A2/_attack_T4` 等标签防回归语义漂移（`tests/fold_batch_test.rs:17-20,412-512` 本轮实读）。
- T2 手动复核（【切片】轮）：prove-hand 对 z̄+1 批报 `ASSERT_EQ instruction failed: 0 != 1`、0.03 s、out 目录仅 executable.json 无 proof.json。
- KAT 交叉验证：K=1 与 K=64 直跑的 roster_digest 同值 `0x66297ceb…`（纯 roster 函数）——本轮实读两份 summary.json 的 public.output 逐位确认。
- 攻击复现件在案：`/tmp/aggsig/{forge0,agg1_forge}.cairo` 及 inputs/bad 对照、`out_forge0_replay`（verified=true/388）、`out_forge0_bad`（无 proof）、`out_agg1_forge`（verified=true/587）——本轮逐一实读。

---

## 4. 迁移与工作量估算

### 4.1 形状变更面（16→17 词的诚实清单，推翻 v1「下游全兼容」红线）

| 改动点 | 内容 | 现状 |
|---|---|---|
| `cairo/src/fold_batch.cairo` | 输出 16→17（roster_digest 尾插 index 16，0–5 不动）；并 98 词 settle wire；c 的 M_h 换真槽 wire[1]/[2]/[36]+cm_digest | 切片版已实现 5 步断言链与 [acc, roster_digest] 输出；settle 并线未做 |
| `stark-recursion/src/chain.rs:181` | COMBINED_OUTPUT_LEN 16→17（:185-186 MAGIC=1/BINDING=5 不变，本轮实读） | 未做 |
| `stark-recursion/src/stark_final.rs:68-76` | SEGMENT_LEN 16→17 + 链尾解析 +1（本轮实读 ：68 SEGMENT_LEN=16） | 未做 |
| `poker_contracts/src/poker_dual_settlement.cairo:277,1311` | COMBINED_SEGMENT_LEN 16→17 + 新断言 segment[16]==roster_registry | 未做 |
| 新合约面 | `register_roster(table, n, pks)`（owner-gated + 事件）+ `roster_registry` 存储 + fold 入口对照；`set_fold_program_hash`（同 ：231 set_combined_program_hash 模式） | 未做（grep 0 命中） |
| `groth16-wrap/src/wrap_circuit.rs:44` | 若保留 wrap 腿：OUTPUT_LEN 16→17 + 预映像 +1 词（约束增量估 +1–2%，未实测）；声明降级文档化 | 未做（决策：非必需） |
| fact 公式 | `poseidon([ph‖output17])`：形状不变、值全变（新程序哈希 + 新长度）⇒ keccak 叶/批根/批次值全变——逐批值本来就不同，无历史冲突；BatchStatement 三元组与 SettleBatch.sol 零改动 | — |
| program hash | 新程序⇒新哈希；钉扎面现成（合约 setter + L1 常量，stark_final.rs:55-58 模式） | — |

### 4.2 上线序列（【设计】迁移节）

部署 fold_batch → **双跑对拍**（folded vs combined 同 8 手，acc 链一致性人工核对）→ owner 切 setter → combined 入口保留为 fallback（一名玩家掉线即回退；双模式并存、禁混批——两链 program_hash 不同，chain.rs:214-219 同政策）。硬前提：`register_roster`（+PoP 纵深）先于 fold 入口开放；fact-registry 面的声明降级说明随部署文档交付。

### 4.3 工作量粗估（估算值，非实测承诺）

| # | 工作项 | 规模 |
|---|---|---|
| 1 | 生产版 fold_batch.cairo（并 98 词 settle wire 复用 settlement_stmt + 17 词输出 + 真槽 c）+ foldagg.rs 镜像同步 | 3–5 人日 |
| 2 | 测试扩展：settle-wire 正例、生产槽位下的 T9–T12 复跑、合约层 roster 负例 | 2–3 人日 |
| 3 | Starknet 合约（17 词段 + segment[16] 对照 + register_roster/roster_registry/set_fold_program_hash + snforge） | 3–5 人日 |
| 4 | chain.rs/stark_final.rs 16→17 与链尾解析 + 双跑对拍工具 | 1–2 人日 |
| 5 | EVM/Monad：FRI 路径公开输入扩展 + Monad 侧 roster_registry；wrap 腿取舍与降级文档（StarkVerifier.sol 现为骨架、FRI 未交付即 revert——工程报告 §3.5 第 6 条，本轮实读） | 3–5 人日 |
| 6 | K=64 笼内复测（steps/RSS/MemoryCurrent + canonical_small 绑定） | 1–3 人日（含排队） |
| **核心路径小计（1–6）** | | **~13–23 人日** |
| 7 | ExecEval.lean 修复 + lake build 全根重验（修复难度未知，阻塞项） | 1–3+ 人日 |
| 8 | PoP 验证面自建（无 syscall 可用，电路内或待确认新面） | 大，可延后；未建不宣称 |
| 9 | 聚合协议外部评审 + poseidon-as-RO 实例化论证 | 外部依赖 |

---

## 5. 风险

1. **soundness 闭合点尚不存在（最高优先）**：roster_registry 未实现（本轮 grep 0 命中）。切片 T9 实证「电路对攻击者整批换钥仍出证成功」——wire pks 在电路内自由是事实，安全完全依赖消费面对照。C1 不落地前，fold 模式在任何面都不得宣称聚合签名效力。
2. **性能全是外推（生产形状）**：11.3k steps/手与 K=64 RSS ≤4.0 GiB 均未在 5200M 笼内实测；超限退档 K=32（本机 17,009 steps 实测）。切片 3.65 s wall 属 2^15 桶，不能外推到生产 2^20 桶。
3. **PoP 无现成面**：vendored corelib 无验签 syscall（本轮 grep 实证），register_hand 仅单 felt（:679-690 实读）。基线安全退守 BDN ROM 不动点（P3 Lean+proptest 支撑）；PoP 需自建，未建前不得宣称 PoP 级强度。
4. **无审计的聚合实现 + nonce 并发面零覆盖**：BDN 三轮 + nonce 承诺 + T8 KAT 为最低配置；审方 proptest 是设计公式的测试内镜像，不构成生产协议验证（C6）。
5. **非密码学前提**：roster 注册 ACL（operator 不得代注册他人 pks，玩家自核）与「partial-sig 前核对 log」客户端纪律；poseidon-as-RO 实例化论证（Starknet poseidon ≠ 论文 SHA-256 RO）上线前需显式一次。
6. **ExecEval.lean 预存损坏**：审方实测 HEAD 即不可编译，阻塞全根 lake build——C4 修复前，Lean 层的 P1/P2/P4 结论停留在审方单轮验证，无法随 CI 复验。
7. **声明域纪律**：任何「金额共签生效」的表述仅限「真验 STARK + 前提 K」同时成立的站点；fact-registry/wrap 面同级现行，越级宣称即虚报。

---

## 6. 复现命令

```bash
cd /Users/mac/projects/poker_texas_air

# ── 门禁（本轮实跑：debug exit 0；fold_batch_test 9 passed/10 ignored，fold_formal_props 12/12）
cargo test -p hand-verify-native

# ── heavy 切片全套（本轮实跑：10 passed / 0 failed / 19.03s，含 T7 扫描与 T9-T12 攻击负例）
cargo test --release -p hand-verify-native --test fold_batch_test -- --ignored --nocapture

# ── K=64 直跑（【切片】轮实测 32,353 steps / 3.65s / RSS 3.35GiB；
#    本轮实读工件 /tmp/fold-direct-k64/summary.json 复核 verified=true、steps、program_hash）
/usr/bin/time -l proving-tool/target/release/prove-hand \
  --program poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo \
  --inputs poker_contracts/hand-verify-native/output/fold-batch-test/t7-k64/inputs.json \
  --params proving-tool/params/canonical_small.json --out-dir /tmp/fold-direct-k64
#（K=1 同式，inputs 换 t7-k1/inputs.json → 2,149 steps）

# ── A1 攻击复现（审方交付件，本轮实读 out_forge0_replay/summary.json：verified=true, steps=388）
proving-tool/target/release/prove-hand --program /tmp/aggsig/forge0.cairo \
  --inputs /tmp/aggsig/inputs_forge0.json --params proving-tool/params/canonical_small.json \
  --out-dir /tmp/aggsig/out_forge0_replay
# z̄+1 负对照（panic 无 proof；本轮实读 out_forge0_bad/ 仅 executable.json）
proving-tool/target/release/prove-hand --program /tmp/aggsig/forge0.cairo \
  --inputs /tmp/aggsig/inputs_forge0_bad.json --params proving-tool/params/canonical_small.json \
  --out-dir /tmp/aggsig/out_forge0_bad
# A2 整组换 roster（verified=true, steps=587，本轮实读 summary.json）
proving-tool/target/release/prove-hand --program /tmp/aggsig/agg1_forge.cairo \
  --inputs /tmp/aggsig/inputs_agg1_forge.json --params proving-tool/params/canonical_small.json \
  --out-dir /tmp/aggsig/out_agg1_forge

# ── combined 基线（【切片】轮同机复测口径：12,160 steps/9p、~2.1s、15.7MB）
cargo test --release -p hand-verify-native --test combined_test combined_single_proof_roundtrip -- --ignored --nocapture

# ── 「本栈无 ECDSA 验签 syscall」实证（本轮实跑：无结果，exit 1）
grep -n 'verify_signature\|VerifySignature' third_party/corelib-2.19.4/corelib/src/starknet/syscalls.cairo

# ── roster_registry 未实现实证（本轮实跑：两处均无结果）
grep -rn 'roster_registry\|register_roster' poker_contracts/src/ texas/src/starknet/

# ── 未跑（如实声明）：lake build 全根（ExecEval.lean 损坏，审方实测；修复前跑不通）
```

---

## 附录 A：证据分级

| 级别 | 内容 |
|---|---|
| **本轮实跑** | debug 门禁（exit 0）；heavy 10/10（含 T7 steps 逐位 2,149/5,501/17,009/32,353 与 T9-T12）；fold_formal_props 12/12；syscalls.cairo grep 无结果；roster_registry grep 无结果；combined.cairo:58 / hand_verify.cairo:259-305 / wrap_circuit.rs:23-50 / chain.rs:181-186 / stark_final.rs:3-100 / poker_dual_settlement.cairo（:277/:331-357/:679-690/:990-997/:1311-1348）/ settlement_stmt.cairo（:28-35/:62-89/:146-175）逐条实读 |
| **本轮实读工件** | /tmp/fold-direct-k{1,64}/summary.json（verified/steps/timings/program_hash/roster_digest 同值）；/tmp/aggsig/out_forge0_replay（true/388）、out_agg1_forge（true/587）、out_forge0_bad（无 proof）；fold_batch.cairo 全文；fold_batch_test.rs 测试清单 |
| **材料转引（审方/切片轮真跑，本轮未复跑）** | /usr/bin/time RSS（1.99–3.35 GiB）；agg0 404/agg1 1,169 steps；K=32 RSS 测自测试进程树；Lean 四层编译通过；heavy proptest 256 组；审方 F-1 曲线实测（n 素/cofactor=1/gcd）；T2 手动 ASSERT_EQ 复核 |
| **ask 给定会话基线（未本轮复测）** | K4 电路 18.3M 约束/单电路 ~14 GiB/2×K4 串行 573.9 s；Monad 批结算 0.307 MON/8 手；combined canonical_small 2.0–2.4 GiB/2–3.5 s（此条另见仓库文档 combined-perf-2026-09-29.md:57-58,66 实读佐证） |

## 附录 B：判定所依据的关键文件

- 切片电路：`poker_contracts/hand-verify-native/cairo/src/fold_batch.cairo`（1-195，五步断言链）
- 宿主镜像/铸造：`poker_contracts/hand-verify-native/src/foldagg.rs`；测试：`tests/fold_batch_test.rs`（T1-T12 带 attack 标签）、`tests/fold_formal_props.rs`（P1-P5）
- 合约锚：`poker_contracts/src/poker_dual_settlement.cairo`（:277 段长、:331 digest 无 cm、:679-690 prover-gated 注册、:990-997 owner/prover-gated fact、:1311-1348 combined 入口逐项对照 + cm 消费）
- 语句：`poker_contracts/hand-verify-native/cairo/src/settlement_stmt.cairo`（98 词 wire、digest 折叠、NOT_ZERO_SUM、cm 承诺输出）
- 链/终证：`stark-recursion/src/chain.rs`（:181-186 输出形状、:214-219 混批禁令）、`stark-recursion/src/stark_final.rs`（:3-10 Groth16 全出局裁定、:47-58 参数钉扎、:68-76 段常量、:84-97 batch_fact）
- wrap 信任边界：`groth16-wrap/src/wrap_circuit.rs`（:23-29 不验 STARK 原文、:44-50 OUTPUT_LEN/HAND_BINDING_INDEX）
- 基线文档：`poker_contracts/hand-verify-native/docs/combined-perf-2026-09-29.md`、`out/stark-recursion-engineering-report.md`（§3.6 K 上限与 9,405/57.4%）

## 后续待办（2026-09-30 增补）：多桌参数化

- **现状边界**：MuSig2 聚合签名绑定单桌 roster（keyagg 系数依赖完整公钥集；roster_digest 进公开输出+合约对照为安全必改项 #1），acc 链按桌序起步——当前折叠为单桌边界。
- **跨桌路径（两级架构）**：桌内 = 聚合签名 + acc 链折叠 → 每桌折叠输出（table_acc, roster_digest, 根）；跨桌 = SettleBatch 语句级批（已桌无关：语句形状只依赖全局 combined program hash，binding 全局唯一，keccak 根桌无关）。
- **电路改动**：折叠电路从单 roster 泛化为 T 个 roster 段（公开输入 +T 个 roster_digest 与每桌手数，padding 至最大桌 size=8）；每桌一次聚合验证（常数）+ 总手数线性——桌数不破坏 O(1)/手 账。非密码学新构造，属电路参数化。
- **合约/信任**：SettleBatch 零改动；roster 对账可选走 PokerTableRegistry（Starknet 侧现成），Monad 侧由 fact/program hash 承载桌注册（信任边界选择需在迁移评审定案）。
- **收益**：冷门桌凑不满批时与其他桌拼批，固定费摊销不再受单桌手数约束。
- **排期建议**：与全量协议迁移（program hash 侧设计冻结，必改项 #1/#3）同批评审；电路规范改动先行，先行量小。

## 路线图增补（2026-09-30）：信任/成本三档阶梯（折叠链已实测跑通）

| 档 | 构成 | 信任宣称 | 链费/手（K=64 口径） | 工程位置 |
| --- | --- | --- | ---: | --- |
| T1 现行 | 2×K4 语句电路 + SettleBatch | 声明式结算（计算端到端可验证在链下，链上锚定为声明式） | 0.0387 MON | 已上线实测 |
| T2 纯折叠 | 折叠链单终证 + **FRI 合约**上链验证 | **真·密码学端到端结算**（无 Groth16） | ~0.028–0.066 MON（终证 calldata 地板 1.79–4.24 MON/批 + FRI 验证 gas） | FRI 验证合约（人月级，二期未交付） |
| T3 折叠+包裹 | 折叠链单终证 → Groth16 包裹（电路内验终证）→ 链上验 Groth16 | 真·密码学端到端结算 | **~0.0005 MON**（常数验证 ~230–350k gas/批） | 终证→R1CS 包裹电路（10⁷–10⁸ 约束自研，人月级）+ 出证基建 |

- 三档的证明系统 soundness 等价（折叠链终证就是端到端证明）；差别只在**链上消费面**：T2 链上直接验 FRI（贵但无包裹），T3 链上验小 Groth16（便宜但多一层电路自研），T1 链上不验计算。
- T2 与 T3 的工程量同级（FRI 合约 vs 包裹电路，均人月级），长期链费差 60–100×；T2 的独特价值：证明体系零 Groth16 依赖。
- 已实测支撑：折叠链 K=8 全链 361.7s / K=64 推算 ~51min（22–26GiB，需 ≥32G 产证机）；终证 3.03MB/440KB bz2；calldata 地板二分实测 1.79–4.24 MON/批。
- 触发条件建议：T2/T3 在日结算 >1 万手或对外承诺去信任结算时启动；选 T2 还是 T3 由「证明体系独立性 vs 长期链费」的取舍决定。

## 路线定案（2026-09-30 运营决策）：T2 为目标路线

- 运营判断：T2 的 0.0952 MON/手（≈$0.0024 @MON=$0.025）绝对值足够便宜，相对 Groth16 的 2.46× 溢价可接受——换取**真·密码学端到端结算 + 证明体系零 Groth16 依赖**。
- **T2 落地清单**（按依赖序）：
  1. FRI 验证合约（人月级）：Solidity 验证 cairo-air STWO 终证（keccak 通道），从根证 3.03MB/440KB bz2 的 wire 格式解析起步；SettleBatch 接线 verify→fact→event；
  2. 产证基建：≥32G 内存机器跑折叠链（K=64 全链 ~51min 实测推算，22–26GiB）；
  3. budget.rs 锚点修正（折叠 7.4GB→实测 22.8GiB）+ l1.rs is_gas_shortfall 白名单补 "intrinsic gas greater than limit"；
  4. calldata 体积优化备选：bz2 wire 1.5MB→更小通道（blob/分块+链下验证面）留观察。
- 交付物就位：折叠链代码与 bench（stark-recursion）、终证 wire 格式、链上 calldata 二分实测方法（l1.rs estimate_gas_bisect）、T1→T2 共存的 SettleBatch 双实例（8/64 语句）。
