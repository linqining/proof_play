> ⚠️ **历史存档(2026-09-05 归档)**:RistrettoAirV2 协议层成本模型——全部基于
> 已删除的 Ristretto/ZR3P/admission 工件,数字按 `docs/plan_d_perf.md` 判为失效;
> 递归路线决策输入已迁至 `docs/TODO.md`(递归协议条目)。

# RistrettoAirV2 协议层性能基准与优化点

测量时间：2026-08（`refractor` 分支）。运行命令：

```bash
cargo +nightly run --release -p poker-hand-bench -- full-hand-v2
cargo +nightly test --release -p poker_texas_air --lib ristretto_shuffle_air -- --nocapture --test-threads=1
cargo +nightly test --release -p poker_texas_air --lib ristretto_reconstruction_v2_air -- --nocapture --test-threads=1
```

## 0. 技术定位：两条路径

RistrettoAirV2 有两条性能上完全不同的路径，本文档的所有数字与优化点
都按此定位阅读：

| 路径 | 执行方 | 内容 | 成本量级 |
| --- | --- | --- | --- |
| **部署路径（生产）** | 客户端 **native prove** + 服务端 **AIR verify** | 客户端用 poker_protocol 原生密码学证明（ownership/洗牌/fold/reveal，交互级毫秒延迟）；服务端只执行验证器（`verify_*` / `admit_*`：BG 公式原生复核 + Flock transcript STARK 验证） | **整手 ~2s 墙钟，服务端 447ms**（§4.0 九人基准） |
| **递归工件路径（Path A 预留）** | （未来）聚合器/链上 | `prove_*_admission_components` 等统一 admission STARK——把服务端的验证义务折叠为单份多组件证明，供链上验证或递归聚合消费 | deck-52 prove ~197–272s（会话波动，§4.1） |

关键澄清：`prove_ristretto_bg_admission_components` / `prove_player_
admission_components` / `prove_ristretto_admission_stark_with_texas` 等
STARK prove **不在生产关键路径上**——客户端实际用 native 证明（毫秒级），
服务端用 AIR 验证器。admission STARK 的定位是递归信封工件：当目标是将
每手的验证义务压缩为链上可验的单证明时才需要它的 prove 侧。因此：

- §1–§3 与 §4.0 的数字是**部署路径**的基准与优化点（关键路径）；
- §4 与 §4.1 的 admission STARK 数字是**递归工件**的成本与优化点
  （非关键路径，按需排期）。

## 1. 整手牌基准（`full-hand-v2`，4 名玩家，release）

一次完整的 mental-poker 手牌：密钥注册（ownership 证明 ×4）、聚合密钥下的规范基牌组、
4 次连续 Bayer–Groth V2 洗牌、发 8 张底牌 + 5 张公共牌、一次中途 `fold_with_proof`
（折叠玩家密钥层从加密牌组与聚合密钥中移除）、下注线（3 个活动玩家跟注）、摊牌
（11 张牌 × 3 名活动玩家 = 33 个 reveal token，明文 = c2 − Σtokens）、结算。

| 阶段 | prove（客户端） | verify（服务端） | 备注 |
| --- | --- | --- | --- |
| ownership ×4 | 585 ms（冷启动） | 21 ms | 含首次 Flock STARK setup；真实客户端启动时预热后热路径 ~10 ms/个 |
| flock 预热 | 7 ms | — | `preheat_flock_setup()`，其后所有阶段热路径 |
| 洗牌 ×4 | 133 ms | 75 ms | BG 论证原生毫秒级；Flock 热 |
| fold_with_proof ×1 | 14 ms | 8.8 ms | leave DLEQ（52 卡批量） |
| 下注线 | 292 ns（原生） | — | 金额转移为纯状态；STARK 化见 hand-bench 默认模式 |
| reveal token（批量化，3 证明） | 31.9 ms | 13.2 ms（并行） | P0 落地前为 33 证明 329 ms/187 ms |
| 解密 + 结算 | 855 µs（原生） | — | |
| **合计** | **168.1 ms** | **91.5 ms** | 客户端证明总量 5.49 MB |

结论：P0/P1/P3 落地后，单手协议层 prove 1.09 s → 178.5 ms（5.9×）、
verify 297 → 96.8 ms（2.9×）、证明量 13.5 → 5.49 MB（−59%）；梯子 codec
合并（§4.1-⑤/其余-1）再降到 168.1 ms / 91.5 ms（6.5× / 3.2×）。剩余体积主体
是 4 个洗牌信封（~3.3 MB）与各证明的 Flock 固定成本（~136 KB/链语句）。

## 2. 单组件基准（release，单线程）

| 路由 | prove | verify | 请求+归档 | 构成 |
| --- | --- | --- | --- | --- |
| V2 洗牌（52 卡） | 36–620 ms | 17 ms | 830 KB | BG wire 5.5 KB + 6 条 Flock 链 ~818 KB |
| V2 重构（ZR3N） | 17 s | 7.2 s | 25 KB + 7.3 MB | 状态绑定 lookup STARK ~5.7 MB + 2 个 Flock ~1.6 MB |
| 重构（旧 ZR3A 路径，对照） | ~1365 s（历史记录） | ~118 s | ~1.27 GB | 416 次标量乘 FpProgram 展开 |
| pk_ownership | ~10 ms（热） | ~5 ms | ~270 KB | 2 条 Flock 链 |
| reveal_token | ~10 ms（热） | ~6 ms | ~270 KB | 2 条 Flock 链 |
| remask / leave（52 卡） | ~15 ms | ~9 ms | ~1.9 MB | 2 条 Flock 链 + 52×32 B wire |

## 3. 部署路径性能优化点（按收益排序；§0 关键路径）

### P0 — 每证明 Flock STARK 体积（✅ 批量化部分已落地，参数部分待做）

13.5 MB 中约 10 MB 是 37 个独立 Flock 归档（每 2 条链语句 ~270 KB；每条链语句携带
独立 Ligerito 实例，固定 ~136 KB）。方向：

1. ~~**reveal token 按玩家批量化**~~ **已落地**（`prove_reveal_tokens_batched`）：
   每玩家一个批量 DLEQ（per-card 承诺 + 单挑战 + 单响应），实测 reveal 阶段
   prove 337→31.9 ms、verify 181→13.2 ms（并行）、整手证明量 −8 MB；
2. **跨证明批处理**：同一玩家一次提交（ownership + shuffle）的 transcript 链语句
   合并进一个 Flock 批证明（`prove_statements` 支持多语句且段间并行）——但
   Ligerito 每实例固定成本仍在，收益主要在语句复用；
3. **vendored flock 参数调优**（log_blowup / rate / 压缩），需在 third_party 内做，
   属独立工作项（剩余 ~5.5 MB 的主要份额）。

### P1 — 冷启动 Flock setup（✅ 已落地）

ownership 阶段 585 ms 几乎全部是第一个 Flock STARK 的 setup。已提供
`blake3_flock::preheat_flock_setup()`（构造一次哑链证明，实测预热本身 7 ms）；
客户端进程启动时调用即可把首手延迟拉平到热路径。

### P2 — 重构路径的状态绑定 lookup STARK（7.3 MB 归档 / ~7 s verify 的主体）

`ZR3N` 归档中 Blake2b lookup 绑定 STARK ~5.7 MB。它是 L1 锚定件（保持 STARK 合理），
但可优化：

1. openings 序列化面（52×2 座位密文 ×2 个 opening）全部进入 Blake2b 语句——按位压缩
   或只哈希承诺根（配合 opening 树）可缩语句数；
2. verify 侧 7.2 s 中含 binding lookup verify——检查其语句分段是否已并行（flock 路径
   已并行，lookup 栈未确认）。

### P3 — 服务端验证并行度（✅ 已落地）

reveal 阶段已按证明 rayon 并行（181→13.2 ms）。整手 verify 297→96.8 ms，剩余
长杆是 4 个洗牌的串行验证（75 ms）——V2 洗牌验证内部的 BG 六组点方程互相独立，
可再 3× 并行 MSM（待做，预计整手 verify 降到 ~60 ms）。

### P4 — 洗牌信封 ~2 MB（九人一手 9 个 ≈ 17.9 MiB 的体积主体，§4.0）

同 P0-3：BG 论证仅 5.5 KB，其余是 6 条 Flock 链。语句数已最小化（1 init + 5 挑战），
收益在 flock 参数或跨洗牌复用（同一玩家连续动作可共享 init 链）。

### P5 — 下注/结算的 STARK 成本（tagged AIR 路径）

本基准中下注是原生状态（292 ns）。完整 host-zero 下注走 canonical tagged AIR
（hand-bench 默认模式：整手 lifecycle+hand 批 prove 数秒级）。两层的证明组合与
递归聚合是 Path A 的范围（见 `HOST_ZERO_RISTRETTO_AIR.md` 的 Path A 章节）。

### P6 — 服务端验证吞吐（部署路径容量项）

九人基准下服务端每手 447ms（洗牌准入 21ms/个为最大项，reveal 已并行），
单核组 ≈ 47 洗牌准入/秒——数百桌并发无压力；多桌场景按准入吞吐横向
扩展（每准入独立、无共享状态）。冷启动仅会话首证（ownership 644ms 中
Flock setup 占大头），服务端预热 8ms。

### 已否决/已完成方向（勿重复）

- slot-OR / cross-key / 牌组转移的 FpProgram 展开：已由 V2 原生 sigma + Flock 替代
  （416 次标量乘 → 0）；
- 更小的 FRI fold_step、更小 Ristretto 域：历史上已验证为负收益；
- π 直接入 AIR：透明 STARK 泄漏置换，已否决（BG HVZK 保 π）。

## 4. 递归工件成本（Path A admission STARK；生产见 §0/§4.0）

| 组件 | 电路内义务 | 估算 |
| --- | --- | --- |
| 洗牌 BG 点方程 | ~7 组 52-way MSM 等式 | ✅ 已落地：`ristretto_scalar_mul_air` 专用 fixed-window 梯子 AIR（N=52 批量 prove 19.0s / verify 1.7s，边际 ~0.34s/次；对比 FpProgram 压缩行路线 172.3s / 8.8s，**prove 9.1× / verify 5.2×**） |
| BG 标量侧调度 | 幂表 + 期望乘积（mod l） | ✅ 已落地：`ristretto_scalar_program_air`（单条 prove 2.7s / verify 1.7s / 17.9MB；**跨调度批摊销实测**：52 条同形状调度一批 prove 2.8s / 证明 18.2MB = **0.35MB/条**，已达 <1MB 目标，无需新代码——结算层按窗口合批即可） |
| pk_ownership / reveal_token | 各 2 条点方程 | ✅ 已接入：player admission 分解器（各 2 / 4 次标量乘 + 原生等式，含 Flock 原生门） |
| remask / leave / fold | 53 条点方程 | ✅ 已接入：deck DLEQ 分解（106 次标量乘 + 53 等式；fold 的密钥更新减法仍为调用方原生检查） |
| transcript 链 | BLAKE3 二元域约束 | 即 Flock 已覆盖的语句 |
| 状态绑定 / openings | Blake2b lookup | 已是 M31 栈 STARK |

结论：每手牌的完整递归义务 ≈ 500–700 次电路内标量乘 + 哈希约束 + 标量侧调度
（✅ 已有 STARK：mod l program AIR）。**统一 admission STARK 骨架也已落地**
（✅ `ristretto_admission_air`，递归聚合器原型）：一份多组件证明把
[梯子 AIR + BG 标量调度 + 基点 decode + 终值 encode + 压缩点累加 + admission
绑定行] 六类组件折进共享的三棵树（tree 0 = 各组件 scope、tree 1 = 各原始
trace、tree 2 = 各 LogUp 交互层，由 stwo 固定索引强制）与单次 FRI。完整口径
实测（2 梯子 + 1 累加行 + deck-12 调度，分离侧计入全部 5 份证明）：合并
prove 3.40s / verify 1.69s / 18.12MB，分离 prove 3.58s / verify 1.55s /
17.11MB —— **成本大致中性（prove -5% / verify +9% / 体积 +6%）**；折叠的
价值在统一单工件、单次验证入口与递归骨架，而非压缩。验证端沿用
fail-closed 纪律：原生重建全部语句 + 可信 scope 比较 + 单次 STARK 验证。点侧的专用 fixed-window scalar-mul AIR
也已落地（✅ `ristretto_scalar_mul_air`）：trace 每行是一次射影 Edwards 加法
（26 个 pinned 值 + 8 个商 witness + 8 条加减链 + `2·Z1` 倍乘链 + `2d·T1`
常数乘 + 7 个一般乘法），基点只 decode 一次、终值只 encode 一次（各一条
fixed-shape Fp program 批行）；行内值经预计算 scope 列钉死到验证者重建的确定
性 schedule，pinned 肢无需电路内 range/canonicity（重建即担保），只有商肢
（11-bit 单肢）与乘法 carry（17-bit 对）进共享 LogUp 表。同输入实测
（ristretto_perf）：N=1 prove 1.4s / verify 0.53s；N=8 prove 3.5s；N=52 prove
16.0s / verify 1.5s / 证明 5.60MB（codec 合并后，2026-08；合并前 1.8s/0.58s、
19.0s/1.7s/6.24MB；FpProgram 压缩行路线 172.3s / 8.8s / 6.54MB）。剩余前置项只有递归聚合器的折叠摊销。宽行证明的批摊销已实测：BG 标量调度
52 条一批 0.35MB/条（`prove_ristretto_scalar_program_batch`，prove 几乎零增长——
宽度主导 FRI，行数只贡献 log 因子）；梯子路线 N=52 全批 5.60MB（codec 合并后）。仍按单条入
ZRS2 信封的场景（单调度 17.9MB / 单梯子 6.2MB）才需要进一步的列打包压缩。

### 4.0 九人整手牌部署路径基准（native 客户端 + AIR 服务端）

`hand-bench -- full-hand-v2-nine`（镜像 `texas_poker_move` Move 合约的一手牌
动作流：9×ownership → 9×BG 洗牌 → 发 18 底牌 + 5 公共牌 → preflop
fold_with_proof → preflop/flop/turn/river 四条街批量 reveal token（8 活跃
玩家）→ 摊牌解密结算）。客户端全程 native poker_protocol 证明，服务端只跑
AIR 验证器（verify_*/admit_*）：

| 阶段 | 客户端证明 | 服务端验证 |
| --- | --- | --- |
| ownership ×9 | 644ms（含冷 Flock 设置） | 65ms |
| BG 洗牌 ×9 | 372ms（41ms/个） | 191ms（21ms/准入） |
| fold_with_proof ×1 | 17.9ms | 8.9ms |
| 每条街 reveal（8 个批量证明） | 109–142ms | 39–50ms（并行） |
| 摊牌解密结算（21 张） | — | 4.9ms（native） |
| **整手合计** | **1.52s** | **447ms** |

整手墙钟 **1.99s**，客户端证明字节 **17.9 MiB**（9 个洗牌信封 ~2MB/个为
大头）。单客户端单动作延迟：洗牌 41ms、fold 18ms、每街 reveal ~14–18ms
（串行模拟 8 客户端的合计 ÷8）——全部交互级。注意：冷 Flock 设置只发生
在会话首证（644ms 中占绝大头），服务端预热 8ms 后全程 warm。此为**部署
路径**；Path A 递归信封（271.9s@deck-52）是链上/递归工件成本，不在该
关键路径上。

### 4.0.1 整手牌递归基准（✅ 2026-08-28 实测，`full_hand_recursion_benchmark`）

九人整手、正确的客户端/服务端分层：**全部玩家证明（ownership/reveal/deck-DLEQ）
与洗牌论证都是客户端 native prove，不进电路**；服务端递归工件只折叠洗牌准入义务
（9 个 deck-52 BG admission STARK，每个一份独立工件）。transcript 链
（BLAKE3/Flock）仍是独立外挂工件，未折叠进递归 AIR（parking 原型见路线图 8）。

| 层 | 实测 |
| --- | --- |
| 客户端 native prove（ownership×9 + 洗牌×9 + fold×1 + reveal 96 token） | **2.07s** |
| 服务端玩家证明原生验证 | 557ms |
| **服务端递归工件 prove（9 × BG admission STARK）** | **1,417.8s**（中位 ~142s/洗牌；单次 136.9–259.9s，会话波动） |
| 递归工件 verify | 140.1s（~15.6s/个） |
| **递归工件体积** | **384.6 MB（42.7MB × 9）** |

解读：①每工件 ~42.7MB 中 ~12.5MB 是 FRI+表条纹地板（2 条梯子的最小语句实测
同为此量级），9 份工件各自全额支付——**多洗牌合批进单份 admission STARK**
（statement 已支持多梯子；schedule/recurrence 需 Vec 化）是把地板摊到每手的
自然下一步（**✅ 已落地，见 §4.0.2**）；②prove 时间与 §4.1 归因一致（梯子
log-18 列主导），⑩ Pippenger 落地后预计 ~50–60s/洗牌（~450–540s/手）；
③体积出路仍是 ①+②+②b+⑧（每工件 42.7→~5–8MB）加合批；④部署路径服务端
原生验证 447ms/手——递归工件的溢价（~3,200×）买到的是单工件链上可验证性，
不是成本优势。

### 4.0.2 一手一证（✅ 2026-08-28 实现，`prove/verify_hand_admission_components`）

按上面的解读 ① 落地：**整手牌的结算义务折叠为一份 admission STARK**。

- **⑥' Vec 化（✅）**：`AdmissionStatement.schedule/recurrence` 从 `Option`
  改为 `Vec`（wire 版本 v4→v5）；rebuild 按 deck 形状分组，同形状的调度/
  recurrence 程序批进**单个**标量段（9 份 deck-52 调度共享一个 FRI 段，列数
  不变、行数只贡献 log 因子）；绑定行的 deck_size 列改为 schedule_count。
  ladder 批上限 `MAX_STATEMENTS` 512→8192（整手 3,870 条梯子 ≈ log-21 行，
  远离 u32/M31 多重度上界）。
- **Poseidon2 段修复 + 健全化（✅）**：parked 原型（路线图 8）的三个叠加
  缺陷——①LogUp 分数生成器按自然序打包而 `LogupTraceGenerator` 存位反序
  （分数被置换→"Constraints not satisfied"）；②验证端组件不恢复 LogUp
  claimed_sum（其它段恰好全零未暴露，本段 `Σ(1/d_init − 1/d_digest)` 非零
  →DEEP-ALI 失败）；③验证端 tree-2 列数取未物化的 interaction 向量。修复
  后补齐**消息吸收**（每步 8 个公开 rate 词进 scope 列，域加法度数 1）与
  **边界绑定**（每链 `(−1, scope 初始)/(+1, scope digest)` 边界条目 +
  one-hot 选择子，总分数和恒为 0，多重集论证钉死首尾态——与 ladder range
  表同一模式）；padding 槽作为一条确定性 padding 链折入。`absorbed_words`
  进 statement digest（fail-closed）。
- **Poseidon2-M31 原生 transcript（✅）**：`ristretto_poseidon2_transcript`
  实现第四个 `CryptoTranscript`——framed 吸收（3 字节/limb）+ absorb-and-
  permute 步进 + 双置换 squeeze（496→256 位）拒绝采样。整个 transcript
  运行即一份 `Poseidon2ChainSpec`（初始态 + 公开词表），
  `merge_poseidon2_chain_specs` 按最长链零词填充合批，`poseidon2_root` 从
  链 digest 派生 M31 原生 hand root。**玩家证明的 Poseidon2 路径已闭环**
  （`prove/verify_pk_ownership_poseidon2`、`prove/verify_reveal_token_
  poseidon2`、`prove/verify_deck_dleq_poseidon2`）与**洗牌准入**
  （`prove_bg_admission_poseidon2`：BG 证明对 Poseidon2 transcript 生成，
  验证重放的链规格随整手工件折叠——只含公开数据，无 π，HVZK 保持）：
  挑战真实由 M31 sponge 派生，全部方程与链以 `HandAdmissionComponents
  { shuffles + shuffle_chains, poseidon2_players }` 折进整手工件。
  `hand_admission_poseidon2_end_to_end`（91s）验证全 Poseidon2 手：
  3 洗牌 + 52 卡 fold + 玩家，单一 STARK，零 Flock 工件——Flock 消除
  （路线图 7）在 admission 路径全部闭环。
- **一手一证 API（✅）**：`HandAdmissionComponents { shuffles, players,
  poseidon2_players, hand_root, poseidon2 }` → `decompose/prove/
  verify_hand_admission_components`。9 份洗牌的梯子/累加/调度/recurrence + 玩家 ownership/
  reveal/DLEQ 点方程 + 手牌全部 transcript 链合并进**一次 prove() 调用**
  （一棵 scope 树、一棵 trace 树、一棵交互树、单次 FRI）；tag = Poseidon2
  hand root。验证端 fail-closed：每份洗牌原生重放（decompose 内含挑战重放
  与全部等式检查）、每个玩家证明原生验证、statement 必须等于推导合并、
  单次 STARK 验证。
- **多成分 Texas 折叠（✅）**：`prove/verify_ristretto_admission_stark_
  with_texas_batch`——多个方法 AIR 成分（`Vec<TexasMethodIngredient>`）
  折进同一份 admission STARK，成分顺序进 FS 绑定；换序/缺成分/篡改期望行
  全部拒绝（测试覆盖）。全方法接线剩余：CanonicalAir（29 种转移）接入
  需同时扩展 Texas 折叠槽的两套管道——(a) tree-0：CanonicalAir 读自身的
  `get_preprocessed_column` 作用域列（当前 Texas 槽无 scope 通道，需按
  fold 命名空间把 canonical scope 列提交进共享树 0）；(b) tree-2：其
  `CanonicalRange8` LogUp 携带非零 claimed_sum，验证端需原生重算交互列
  与求和（对齐 poseidon2 段的 full-build 模式）；外加 CanonicalAir 公开化
  + TexasAir 实现（statement/trace_num_columns）。属多日级重构，未动。
- **测试**：`hand_admission_proves_and_verifies`（3 洗牌 + Poseidon2 路径
  玩家证明——挑战来自被折叠的链，41s，四类篡改拒绝）、
  `poseidon2_player_proofs_prove_verify_and_reject`、
  `admission_poseidon2_segment_proves_
  and_verifies`（去 ignore，含词表篡改拒绝）、`texas_layer1_multi_fold_
  proves_and_verifies`（3 成分）。全库 507 测试回归通过。
- **成本实测（✅ 2026-08-28，`hand_admission_deck52_batch_benchmark`）**：
  3 洗牌 + 18 链单 STARK：**prove 274.3s / verify 22.2s / 43.14MB 单工件**
  （对照 3 份分离工件 ~426s / 128MB：**prove -36%、体积 -66%**。prove 的
  节约来自 padding 摊销——单洗牌梯子 144K→262K 行有 82% 填充开销，3 合批
  432K→524K 仅 21%；体积节约来自 FRI/表条纹地板只付一次）。9 洗牌完整
  运行验证通过（证明+验证 exit 0），按同模型外推 **~820s / ~60–70MB vs
  1,417.8s / 384.6MB（prove -42%、体积 -82%）**；注意 9 洗牌梯子段为
  log-21，36GB 机器需 swap（重跑可能 OOM），基准支持
  `TEXAS_HAND_SHUFFLES=k` 变体。后续优化排序不变：⑩ Pippenger（时间）
  → ①+②+②b+⑧（字节），都在合批后的单工件上直接生效。

  **stwo Poseidon252 SIMD 实验（❌ 2026-08-28 否决，NEON 上不实际）**：
  曾把四个 stwo 依赖切到 `linqining/stwo` 的 `feat/posiden-simd` 分支
  （构建通过、admission 套件 10/10 过），但该分支的 SIMD 门控是
  `cfg!(all(target_arch = "x86_64", target_feature = "avx512f"))`，本机
  Apple Silicon 走标量回退（且回退路径多做列转换，实测单线程更慢）；
  批量内核在 NEON 上 ~6.9µs/哈希 vs 标量 4.4–6.9µs、节点层比 rayon+
  标量基线慢 20–30%——结构性原因：NEON 无 64×64→128 widening 乘法，
  8×8 肢 schoolbook 乘法数为标量 mul+umulh 的 2 倍，且 Starknet
  Poseidon 的无乘法 MDS 在 SIMD 下要付进位链（CIOS/SOS/分半 SOS 三种
  乘法核均试过）。已回退 crates.io 2.3。x86-64 AVX-512 机器上该分支
  仍值得启用。

### 4.1.0 洗牌移出电路后的玩家-only 工件基准（✅ 2026-08-28 实测）

部署路径切 Poseidon2 + host 验证洗牌（§4.0）后，一手一证工件只剩玩家义务。
新增基准 `hand_admission_player_only_benchmark`（ignored，跑法
`TEXAS_PROVE_TIMING=1 cargo test -p poker_texas_air --release --lib
hand_admission_player_only_benchmark -- --ignored --nocapture`）：九个
Poseidon2 ownership + 完整 reveal 阶段（8 玩家 × 4 街批量 token，88 方程）+
一个 deck-52 fold DLEQ + 42 条 transcript 链折入 Poseidon2 段。

**基线（2026-08-28，300 梯子 / 150 additions）**：prove **79.4s** / verify
**9.9s** / 证明 **12.5MB**。相位归因：trace 树 34.7s + interaction 树 19.6s
+ scope 树 5.1s（**Merkle 合计 75%**）、prove.stwo 13.0s、segments.build
2.8s、serialize 1.8s、interact 1.4s。

本轮落地的三项：

1. **玩家-only 工件解锁**：`decompose_hand_admission` 原先硬性拒绝零洗牌
   （"carries no shuffle obligations"）——已放宽为"至少一项义务"，host 验证
   洗牌后的结算工件可证。
2. **批量 reveal 折入 admission（✅）**：`PlayerRevealBatchPoseidon2Entry` +
   `reveal_batches` 分解（1 key + N 卡方程/批）。同负载下梯子 460（单卡编码
   2N/卡）→ **300**；证明字节同步下降（codec 列减少）。**注意行数取整到
   2 的幂**：460 与 300 梯子同落 log-17（131K 行），prove 时间不变、只有字节
   收益；跨到 log-16（65.5K 行）需 **≤195 梯子**——单靠方程打包已不够，
   只有 ⑩+ 桶化 MSM（300 方程 ≈ 600 点 → c=6 时 ~28K 行 ≈ log-15）能跨
   台阶，届时 prove 预计 ~20s。修掉了 `combine_poseidon2_players` 丢
   `reveal_batches` 的健全性缺口（原生门仍 fail-closed，但 STARK 未覆盖
   reveal 方程）。
3. **⑦ 见证定宽算术（✅）**：`ristretto_scalar_mul_air` 的 BigUint 商/比较
   换 4×u64 定宽（利用 p = 2^255−19 的倒数结构估商 + ±1 精确校正，256 组
   随机对照 BigUint 全对）。segments.build ~1.9→~1.0s；本工件收益 ~1s
   （⑦ 的收益随洗牌段消失同步缩水——build/interact 只剩 ~4s）。

**修正后的优化排序（玩家-only 工件）**：⑩+ 跨方程桶化 MSM 是唯一大时间
杠杆（75% Merkle ∝ 行数，跨 log-16 需 ≤195 梯子、跨 log-15 需 ~桶化）；
④ 混合加法（列减）次之（~2400 log-17 列是 Merkle 主体）；⑦ 已兑现；①②
②b⑧ 在此工件只剩字节收益（宽标量段不存在）。

### 4.1 后续工作（增量优化 + 递归路线图）

**递归工件（admission STARK）成本归因（✅ 2026-08-27 实测修正）**——非生产关键路径
（§0），仅当需要链上单证明/递归聚合时排期。归因方法：`bg_admission_deck52_
attribution` 基准（同进程四变体 A/B：完整 / 去 recurrence / 去调度 / 仅梯子），
`TEXAS_PROVE_TIMING=1` 输出按段按相位记录，`TEXAS_STWO_TRACING=1` 激活 stwo
内部 span（Extension/Merkle/Composition/FRI）。同会话基准：**prove 197.5s /
verify 24.9s / 42.7MB**（会话间波动大：历史 271.9s/35.3s 与本次同工况差 ~28%，
跨会话数字不可作归因依据——历史"recurrence 段 +131.5s"的结论**不可复现**，
系跨会话对比伪影）。

**修正后的成本模型**（同会话 A/B + 相位分解）：

- **prove 时间 ∝ 单元数**（每列按 `2^(自身log+blowup)` 扩展 + Poseidon Merkle）：
  梯子段 3,850 个 log-18 列（trace 2,398 + interaction 1,140 + scope 312）贡献
  ~148s（Merkle 占绝对主导：trace 树 91s + interaction 树 46s + scope 树 12.5s，
  每列 ~40ms）；Composition 约束逐点求值 ~19s；见证生成（build 5.6s +
  interact 3.8s）~10s；serialize 1.5s。**宽标量段（调度 117.6K 列 + recurrence
  87.8K 列，全在 log 7–8）合计只花 ~5s 时间**——去掉 recurrence prove 仅
  197.5→196.7s，去掉调度 193.0s，仅梯子（保留 codec+累加）198.6s。
- **证明字节 ∝ 总列数**（每列 ~150B，与列所在 log 无关；FRI 查询覆盖全部三树）：
  调度段 17.9MB + recurrence 段 13.3MB + 累加段 ~6.5MB + codec 段 ~4MB +
  梯子核 ~1MB；四变体字节完美可加（11.52 + 13.34 + 17.88 = 42.74MB）。
- **verify ≈ scope 树重承诺（12.9s，梯子 312 个 log-18 列的扩展+Merkle，刚性）
  + segments.build（6.4s，验证端在物化完整见证 trace，可改 shape-only）
  + stwo verify（1.4–4.8s，随字节线性）**。

**哈希通道实验（✅ 2026-08-27 实测，代码已还原）**——prove 的 ~75%（~148s）
是 Merkle 承诺，其哈希器是 Starknet Poseidon252（`starknet-crypto` 标量实现，
252-bit 素域、非 M31 原生）。微基准（`merkle_hasher_microbench` ignored 测试）：
叶块（16 M31 值）Poseidon252 **5,359 ns** vs Blake2s **103 ns**、节点哈希
**4,290 ns** vs **83 ns**（**52×**）。临时把 4 个文件的通道类型替换为 stwo
自带的 `Blake2sMerkleChannel` 后 deck-52 全矩阵实测：**prove 197.5→28.5s
（6.9×）、verify 24.9→5.77s（4.3×）、证明字节 42.74→42.52MB（-0.5%）**，
全部验证通过；树承诺 ~158s→~5s，verify 的 scope 重承诺 12.9s→0.23s（换哈希
后"刚性"消失）。新瓶颈变为 prove.stwo 组合求值 14.9s、segments.build 4.4s。
**第三选项（SIMD 化 Poseidon252）**：52× 差距主要来自标量实现——stwo 的
`simd/poseidon252.rs` 自带 `TODO: replace with SIMD implementation`，叶哈希
（叶子间独立、可跨叶向量化）SIMD 化预计拿回 4–8× 且**保持 Cairo 对齐**，
是"链上便宜 + CPU 快"的标准解法，也是业界无人做通道包装的原因。
**Blake3 不适用**：stwo 2.3 的 lifted（异构列）通道只有 Poseidon252/Blake2s
两种实现；64 字节块粒度下 Blake3≈Blake2s（各一次压缩函数），Blake3 的大输入/
内置多线程优势在这个叶子形状用不上，自实现 lifted 通道收益≈0。**切换条件**：
若 Path A 证明最终在 Starknet/Cairo 链上验证，Poseidon252 是 Cairo 原生哈希，
应保留；若链上/递归目标非 Starknet（或将来自研 M31 verifier AIR 反正要换 M31
原生 hash），切 Blake2s 是当前性价比最高的单一改动——与 ⑩ 同级收益、工作量
低一个量级（admission 路径 ~70 处类型引用替换已实测；全栈 30+ 文件）。**注意
通道选择与"递归 vs tagged commitment"无关**：tagged 主路径（`texas_tagged`/
`texas_canonical_air`/aggregator/dual_proof）本身就是 Poseidon252 通道的 stwo
证明，Flock 与部署路径服务端原生验证不使用它——真正的决策变量是"哪个 stwo
证明需要在链上验证"：链上验 STARK → 保留 Poseidon252；链上只验 canonical
承诺/哈希根 → 全栈换 Blake2s 收益照旧（所有 stwo prove ~6.9×）。

| 优化点 | 做法 | 预估收益（修正后） | 复杂度 |
| --- | --- | --- | --- |
| ⓪ Blake2s Merkle 通道 | 通道类型替换（4 文件 ~70 处），实验已完成并还原 | **prove -6.9× / verify -4.3× / 字节 ~0**；切换条件见上（链上验证目标） | 低 |
| ⑨ 测量归因 | ✅ **已完成**（2026-08-27，见上）：相位计时进 `prove_admission_inner`/`verify_admission_inner`（`admission.*` 记录），stwo tracing 走 `TEXAS_STWO_TRACING` | 成本模型修正为"时间∝单元数、字节∝列数"；①②⑥收益全部重估 | — |
| ⑩ Pippenger 桶化 MSM AIR | 430 条独立梯子（144K 行，log 18）改为 ~7 组 52-way MSM 桶化（c=4–6 ≈ 30–35K 行，log 16）：Merkle/扩展 ~148→~37s、Composition ~19→~6s | **prove ~197→~65–80s（唯一的大时间杠杆）**；verify 的 scope 重承诺同步 ÷4 | 高 |
| ⑩b 梯子 pinned 肢列消除 | ❌ **撤回（2026-08-27 设计复审）**：原始方案（约束读打包 scope、删 624 个 trace 肢列）不可实现——2×11-bit 肢从 22-bit 打包列解出不是域线性运算，肢必须以独立列存在；唯一可行变体（肢改为非打包 scope 预处理列、同时删打包列）净负：prove 净 -312 个 log-18 列（~-12s）但 **verify 的 scope 树重承诺 +312 列（~+12.5s）**——验证端只重承诺 scope 树，trace 列迁入 scope 的每一列都永久加重链上验证负担（Starknet 目标下尤其如此），严格得不偿失 | 撤回 | — |
| ① 专用 recurrence AIR | 梯子式固定布局 ~550 列/步（现 87.8K 列），全值公开可推导 → 零 canonicity、scope 钉死 | **时间 ~0**（修正：原估 -45% 基于伪影）；**字节 -13.3MB、verify -~1.5s** | 中 |
| ② 专用 BG 调度 AIR | 幂表/累乘拆固定行（~600 列，现 117.6K 列，最大字节单项），与①可统一为一个 BG 标量 AIR | **字节 -17.9MB**、verify -~2s | 中 |
| ②b 累加段专用行 AIR | 422 条压缩点加法现为 Fp 程序批（42.6K 列 ≈ 6.5MB）——梯子式共享行布局（每行一次 Edwards 加法 ~2.4K 列共享） | 字节 -~6MB | 中 |
| ④ 定基混合加法 | 表生成行右操作数 Z₂=1，混合加法省 D 乘链（减少 log-18 carry 对列） | prove -5~7s | 低 |
| ⑤ codec 段合并 | ✅ 已完成（2026-08，`build_ladder_codec_program`）：decode+encode 合一，梯子批 N=52 prove 18.3→16.0s / 证明 6.24→5.60MB；剩余方向见⑧ | 已兑现 | — |
| ⑧ codec 段瘦身 | 430 个 decode+encode 程序批 26.9K 列：重复基点 decode 去重 + 固定布局专用行 | 字节 -~3–4MB | 低-中 |
| ⑦ 见证生成定宽算术 | build+interact 共 ~10s 的 BigUint 商/乘换 4×u64 定点 | prove -5~8s | 低 |
| ⑥b 验证端 shape-only 段构建 | ✅ **已落地并实测**（2026-08-27）：`AdmissionSegments::build_shape_only`——三个段（梯子/标量/Fp）各增 shape-only 构造器，verify 只物化 scope 树与 trace 形状（空列），witness 重型 trace 不再生成。实测 deck-52：**verify 的 segments.build 6,365→442 ms（-93%）**，verify 全程 24.9→15.2s（其中 -5.9s 为 ⑥b 确定性贡献，其余为会话波动——本会话各 Merkle 相位较上轮 uniformly 快 ~26%，归因比值不变） | **verify -5.9s（相位级确定）** | 低 |
| ⑥ 双手合批 | 修正：时间上**近零收益**（梯子行数翻倍→Merkle 严格线性，+1 层 FRI ≈ +3%）；字节上宽段列数恒定、梯子查询微增，**每手字节约减半** | 字节 -~50%/手（摊销）；时间 ~0 | 低 |
| ③ 梯子倍乘特化 | ❌ 维持关闭（2026-08 实测否决，见历史表） | — | 不可行 |

叠加预估（2026-08-27 决策后主线：**通道保持 Poseidon252**，Starknet 对齐；
⓪ Blake2s 已实测 shelved——prove -6.9×/verify -4.3×，未来按需替换）：
**⑥b（✅ 已落地，见下）→ verify ~-6s**；**+⑦（build/interact 定宽算术
-5~8s）→ prove ~190s / verify ~13s**；**+⑩ Pippenger（行数 ÷4：Merkle
~148→~37s、组合 ~19→~5s）→ prove ~45–60s**；字节正交：**①+②+②b+⑧ →
42.7→~5–8MB**（列数计费，不受通道影响）。进 10s 以下或单证明上链仍需
proof-verifies-proof 递归（超出 stwo 2.3）或专用后端（GPU-FRI），属下一架构
阶段。**不建议动**：肢宽（11→12 位仅 ~10% 且 carry 表翻倍）、FRI 安全参数
（协议决策）、carry 表拆分与 LOG_SIZE（历史红线）。

**其余增量优化（不阻塞主线，按需排期）**：

1. ~~decode/encode 段并入梯子 AIR~~：✅ 已按"合并为单条 codec 程序批"落地
   （见上表⑤，N=1 codec 独立 FRI 成本减半）；完全并入梯子 AIR（特殊行/额外
   组件）与③受同样的列数计费约束，收益存疑，暂缓。
2. 单条信封列打包（已评估，暂缓）：仅影响"单条入 ZRS2 信封"场景（单调度
   17.9MB / 单梯子 5.6MB）。理论上 2 肢/列打包可省一半列（prove 按列数计费），
   但链/卷积约束与 LogUp range-check 都按单肢线性消费列，线性抽取肢需再造
   独立列（净零收益），而直接 range-check 22-bit 打包对需要 2^22 表（现条带
   表 2^11/2^17，log 9 下即 8192 条表列，不可行）。需要新的 lookup 表设计
   （如分段 11-bit 拆分证明 packed 值域的交互层）才有正收益，属独立工作项，
   收益不确定，暂缓。

**递归路线图（Path A 聚合器，骨架已就位）**：

1. ✅ 统一 admission STARK 骨架（`ristretto_admission_air`，已完成）；
2. ✅ **decode/encode/累加 Fp 段并入**（已完成，admission STARK v2）：
   完整 BG 点方程族（decode→梯子→encode→累加）六类组件进同一三树布局；
3. ✅ **真实 BG admission 接线**（已完成）：`prove/verify_
   ristretto_bg_admission_components` + request 包装把 BG 验证器的全部
   公式分解为 [梯子语句 + 累加行 + 编码等式（原生）+ 标量调度 STARK]，
   deck-4 实测：46 梯子 + 38 累加 + 8 等式，一份 STARK prove 11.8s /
   verify 2.37s / 15.5MB；篡改响应标量/承诺点/语句/证明字节全拒。
   deck-52 实测（含 recurrence 标量段，见下）：430 梯子 + 422 累加，一份
   STARK prove 271.9s / verify 35.3s / 43.0MB（跨会话波动 ±25–30%：2026-08-27
   同会话 A/B 四变体为 197.5s / 24.9s / 42.7MB，且证明时间对 recurrence/调度
   段不敏感——时间∝单元数由梯子 log-18 列主导，宽标量段只贡献字节与 FRI
   验证成本，见 §4.1 修正后的成本模型）；
4. ✅ **recurrence 标量段**（已完成）：`build_bayer_groth_recurrence_
   program` 把 `recurrence[i] = pc·b[i+1] − b[i]·a[i+1]` 与 `d = b[0] −
   a[0]` 的 mod-l 推导并入 admission STARK 第二标量段（语句携带
   AdmissionRecurrenceSpec，wire v4；`d == 0` 与 `b[n-1]` 比较仍为对
   pinned 输出的原生检查）；
5. ✅ **Texas Layer-1 折叠**（已完成，含多成分批）：`prove/verify_
   ristretto_admission_stark_with_texas(_batch)` 把一个或多个方法 AIR
   （BoundAir 包装，trace 列进共享 tree 1、期望行摘要素入通道、零 claim
   组件）折进 admission STARK——CreateTable 与 pk+reveal 点方程一份证明
   验证通过，篡改期望行拒绝；多成分批（2026-08-28）支持
   `Vec<TexasMethodIngredient>`，成分顺序进 FS 绑定；CanonicalAir 全方法
   接线还需给 Texas 槽加交互树管道（其 range LogUp 有非零 claim）；
6. **边界**：电路内 FRI 验证超出 stwo 2.3 能力（无 verifier-air/
   recursion crate），当前骨架是递归的"折叠"半边（多组件单 FRI +
   摘要绑定），非 proof-verifies-proof；真正的电路内验证需升级
   stwo 或自研 verifier AIR。
7. **Flock 消除路线（✅ 2026-08-28 核心已落地）**：换 STARK 通道
   （⓪ Blake2s，已实测 prove -6.9×）只便宜外层工件自身的承诺，不
   影响 Flock——Flock 的开销来自"在电路里证明位运算哈希"这一事实，
   Blake2s 与 BLAKE3 同为 ARX（且每块 10 轮 vs 7 轮，更贵），换它
   只是换一个待证明的位哈希。仓库已有直接证据：hash 层曾走
   "Blake2b + M31 lookup 栈"（现 ZR3N 绑定 STARK ~5.7MB/7s），后迁
   BLAKE3+Flock——位哈希进 M31 是实测淘汰过的方向。**✅ 核心已落地
   （2026-08-28，见 §4.0.2）**：`ristretto_poseidon2_transcript` 提供
   M31 原生 Poseidon2 transcript（CryptoTranscript 第四实现），其链语句
   作为 admission STARK 的又一个 M31 段（同骨架/同树/同一次 FRI）随
   一手一证工件自包含；剩余迁移面：poker_protocol 各证明入口与
   `texas_poker_move` 参考实现切到该 transcript（部署路径的 37 个 Flock
   归档随之并为单 M31 批或服务端原生复核）。原方案（供参照）：需把
   transcript/状态哈希换成 **M31 原生 SNARK 友好哈希**
   （Poseidon2/Monolith over M31）：链语句成为 admission STARK 的
   又一个 M31 段（同骨架/同树/同一次 FRI），递归工件自包含、部署
   路径 37 个 Flock 归档（~10MB/手、每语句 ~136KB Ligerito 固定
   成本）并为单 M31 批或服务端原生复核；代价是协议层变更
   （poker_protocol transcript、`texas_poker_move` 参考实现、已部署
   客户端兼容），π 不入 AIR 的否决不受影响（那是 BG 置换的 HVZK
   约束，与 transcript 哈希无关）。**M31 原生哈希不做 limb 模拟**——
   limb/carry/LogUp 只属于被迫非原生的 252-bit Ristretto 域；stwo 官方
   Poseidon2-M31 参考电路（`examples/poseidon`）参数：t=16 状态、8 全轮
   + 14 部分轮、S-box x^5（3 次原生乘；x³/x^7 在 M31 上不是置换——
   3²·7 | 2^31−2）、线性层纯加法+公开常数（度 1），每置换 158 列 × 1 行
   （8 置换 SIMD 打包/行），零 range-check。电路内成本：一条 ~50 置换
   的 transcript 链 ≈ 8K cells ≈ 1/100 条梯子（梯子 335 行 × 2,398 列），
   每手 37 链 ≈ 0.1% 梯子段当量——免费级；CPU 侧 ~0.2–3µs/置换（SIMD
   批处理），相对 sigma 证明的 ms 级不可见。Monolith 的 x³（2 乘）在
   M31 上不可用（非置换），其加法型 MDS 优势 Poseidon2-M31 已具备，
   效率同级——跟随 stwo 参考电路即可（注意其轮常数为占位 TODO，正式
   参数需按论文程序生成）。
8. ✅ **Poseidon2 段（已修复并健全化，2026-08-28）**：`ristretto_
   poseidon2_air` 的 Circle STARK 参数 Poseidon2-M31 段（t=16、8+14 轮、
   x^5 拆三步度 2 约束、442 列/置换）修复了三个叠加缺陷（分数位反序、
   claimed_sum 不恢复、tree-2 列数声明）并补齐消息吸收与边界绑定（见
   §4.0.2）——admission 内证明/验证/篡改拒绝全部通过，测试去 ignore。
   原"16 元 relation 度数与 blowup 1 不合"的怀疑不成立：relation 的
   combine 是仿射的（度数 1），配对约束三次，度数声明本就正确。

