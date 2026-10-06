> ⚠️ **历史存档(2026-09-05 归档)**:全部数字为 Plan D 曲线切换前的旧世界基线,
> 已被 `docs/plan_d_perf.md`(2026-09-05 重测新基线)取代;第 8-16 轮描述的
> Ristretto/admission 代码已删除。仅存优化方法论史料价值。

# poker\_texas\_air 性能报告 —— 以一手完整德州扑克为准（标准 9 座桌）

日期：2026-08-23 · 主机：Apple Silicon `Mac15,7` (aarch64) · 工具链：nightly + stwo 2.3（`--release`）
复现：`cargo +nightly run --release -p poker-hand-bench`（stwo 依赖 `#![feature]`，必须使用 nightly 工具链，stable 下报 E0554 编译失败）

## “一手完整牌局”的构成（标准 9 座桌）

基准按标准 9 座满员桌构造，为当前 canonical tagged AIR **端到端可证明的最大连续组合**
（洗牌/揭牌的 Ristretto 组合仍 fail-closed，见 TRUST\_MODEL 矩阵）：

| 批次                         | 行（VM 转换）                                                | 说明                                                                                             |
| -------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| lifecycle（11 行）            | CreateTable → JoinTable×9 → StartHand                   | 建桌、九人各带 1000 入座、开局（止于洗牌边界）                                                                     |
| hand（11 行）                 | Bet(50) → Raise(150) → Fold×8 → EndWithoutShowdown(200) | 九人 preflop：开注、加注、七连弃 + 开注者弃牌、零抽水单人结算                                                           |
| hand openings（1 个共享 STARK） | 规则字节 + 首末状态像字节                                          | `Borsh(TableRules)`→rules\_commitment 与两个 `Borsh(image)`→image\_commitment 的 lookup-Blake2b 证明 |

验证组合链：rake 配置 ← 规则字节 ← rules\_commitment ← 状态像字节 ← 像承诺 ← SMT root，
全程无 host 断言（host-zero）。AIR 侧全程打开九座位（`MAX_CANONICAL_SEATS = 9`）。

## 优化后数字（3 次运行，中值）

完整 host-zero 捆绑已落地：规则 + 首末状态像 + 两条 256 层 SMT 开销作为
**517 条语句一体证明**（`prove_canonical_hand_bundle`，经 `HashProofProvider`
接缝），替代三个独立证明（\~35s），且 admission 只验一个哈希证明。

| 组件                                     | prove               | verify       | 证明尺寸        |
| -------------------------------------- | ------------------- | ------------ | ----------- |
| lifecycle 批次（11 行，canonical STARK）     | **0.62 s**          | 0.22 s       | 1.18 MB     |
| hand 批次（11 行，canonical STARK）          | **0.62 s**          | 0.21 s       | 1.14 MB     |
| hand openings（合并 lookup-Blake2b STARK） | 5.0 s               | 1.05 s       | 1.23 MB     |
| 完整 host-zero 捆绑（+2×SMT，517 语句）         | **21.8 s**          | **10.4 s**   | 9.41 MB     |
| canonical 双批流水线并行                      | 0.84 s（原 1.25 s 串行） | —            | —           |
| **整手合计（不含 SMT）**                       | **≈ 6.2 s**         | **≈ 1.5 s**  | **3.55 MB** |
| **整手合计（完整 host-zero 含 SMT）**           | **≈ 22.6 s**        | **≈ 10.9 s** | **11.7 MB** |

两个结构性事实：

1. **批内行数在 1..=256 内不影响证明成本**（trace 域下限 log 8 = 256 行）：
   11 行与 4 行批次的 prove/verify 完全相同（\~0.62 s / \~0.21 s）。一张表在
   256 行以内追加任意多行动都不增加证明开销——“每表一证”的边际成本恒定。
2. **Blake2b lookup 开销与消息块数基本无关**（76 B 规则 ≈ 5.0 s vs
   2×1711 B 状态像 ≈ 6.1 s 独立证明时）：瓶颈是每次证明固定的 2^16 XOR
   表承诺 + FRI，不是哈希量。

## 本轮优化（12.4 s → 6.2 s，2.0×）

| 变更                                                                                                             | 效果                   |
| -------------------------------------------------------------------------------------------------------------- | -------------------- |
| 三个独立 Blake2b 证明（规则 + 首末状态像）合并为一个共享 lookup STARK（`prove_canonical_hand_openings`）                               | 开销证明 11.2 s → 6.1 s  |
| G 与 scheduler 两个子 STARK 用 `rayon::join` 并行证明                                                                   | 6.1 s → 4.9 s        |
| G 与 scheduler 验证同样并行                                                                                           | 开销验证 1.32 s → 1.05 s |
| 修复 canonical betting AIR 的 turn 回绕 bug：`(post_turn − seat)` 字段差为负时 advice 逆用 mod-16 残差，两人桌 seat 1 的一切下注行动此前不可证 | 解锁多人轮转手牌基准           |

## 剩余热点与路线图（已按"哈希层迁移二元域"决策重排）

架构分工：M31/stwo 承载 canonical 业务 AIR；Blake2b 哈希层（规则/状态像/SMT/reveal
台账）迁移到二元域证明器（Binius/Flock 类，参考吞吐 82k Blake3 压缩/秒/单核，
ePrint 2026/1329）；admission 并行验证双证明，归档接口保持递归无关。
完整 host-zero 手牌（含 SMT 2×257 层）哈希层投影：当前 M31 lookup 栈 \~26s
（固定 \~4.9s + 0.04s/块 × 543 块）→ 二元域 **\~0.06s**。

1. **哈希证明器抽象层**（已完成，`src/hash_prover.rs`）：`HashProofProvider`
   trait + 统一归档 + 防拼接语句级验证；M31-lookup 为首个后端。
   **二元域后端调研更新（2026-08，阻塞解除）**，三条可用路线按契合度排序：
   - [succinctlabs/flock](https://github.com/succinctlabs/flock)（Bünz/Rothblum/Wang，
     ePrint 2026/1329，Apache-2.0/MIT，git 依赖接入，未发 crates.io）：GF(2)-R1CS
     zerocheck+lincheck PIOP + Ligerito 多线性承诺，**端到端内置 BLAKE3/SHA-256/
     Keccak 哈希链与 Merkle 路径 prover/verifier**（flock\_chain CLI 可直接跑），
     Apple Silicon NEON 优化——与我们 517 语句哈希栈（statement 链 + SMT 路径）
     形态几乎完全对口；缺 Blake2b 编码器（可自写 R1CS 编码或顺势把链哈希切到
     已内置支持的 BLAKE3，后者与此前 blake2→blake3 评估结论一致）。研究级、
     未 production-ready，但代码完整可用。
   - [binius-zk/binius64](https://github.com/binius-zk/binius64)（Irreducible 后继，
     活跃 1.6k commits，Apache-2.0/MIT）：任意 64-bit 字非确定性电路 zk-SNARK，
     SHA-512 64KB 消息 \~128ms 示例，Blake2b 可原生编码；接口较通用但无现成
     哈希语句层，需自行搭 statement 绑定/防拼接。
   - 原版 `binius-*` crates（crates.io 0.1.x，2025-05 发布，repo 已归档只读）：
     代码真实但官方自述"含 bug、勿用于安全关键场景"，且无人维护——仅作参考，
     不选。
     接入路径：经 `HashProofProvider` 接缝新增 `FlockProvider`（首选），消费方零改动。
     **本机实测（2026-08-23，Apple Silicon，flock\_chain release 单线程）**：
     256 与 1024 步 BLAKE3 链 prove\_chain 均 **0.33s**（固定开销主导，边际压缩
     ≈ 0），verify 恒定 **0.54s**，证明 **296KB**。对照当前 M31 lookup 栈
     （\~1057 次压缩投影 prove \~26s / verify \~4.4s / 9.4MB）：prove \~40×、
     verify \~8×、证明 \~30× 缩小。编码器接口支持任意 preimage 块
     （`blocks: &[Compression]`）+ 公开链端点折叠，与我们的 scope 绑定/防拼接
     语义兼容。
     **哈希选型结论：切 BLAKE3（已完成，2026-08-23）**。自写 Blake2b 编码器 =
     仿 blake3.rs（2492 行）改 64-bit G（rot 32/24/16/63、新 IV/sigma/参数块），
     工作量数千行级且失去上游基准与维护；BLAKE3 内置、已基准、性能同级。
     **落地内容**：
   - **vendor**：flock（commit 快照）入 `third_party/flock`（workspace 排除 +
     清单内联化，path 依赖接入）。
   - **BLAKE3 Merkle 胶水（fork 新增）**：blake3 witness 布局改造——`Z_CONST`
     pin 移至尾部、`M_BASE` 对齐 512，使 slot 0..4 = \[cv, out\_lo, msg\_lo,
     msg\_hi] 满足 merkle\_path\_common 的连续 4-slot 几何（与 sha2 编码器同法）；
     新增 `MERKLE_LAYOUT` + `prove/verify_merkle_path` + 深度 256 roundtrip 与
     周期位模式测试。flock 全套 61/61 + core 332/332 绿。**上游发现**：Ligerito
     最小注册配置 m=22（256 块下限），小实例需补齐到 256 步；const-wire pin
     不得落入 padding 零区（否则 lincheck sumcheck-final 失败）。
   - **上游协议约定（重要）**：merkle shift 的 `b_bits[0]` 未被协议使用
     （约定恒 0，路径起点必须位于 level-0 消息左半），leaf-on-right 是
     fail-closed 而非可证。我们的 SMT 语义相应定义：level-1 消息恒
     `(child, sibling)`，key 第 0 位由叶摘要 `H1(key||value)` 原生绑定
     （叶消息哈希全部 64 字节公开输入），其余 255 位由协议方向位绑定。
   - **FlockProvider**（`src/blake3_flock.rs`）：预映像语句 = flock 链证明
     （cv\_0=IV、cv\_last=digest 公开端点，message 吸入 FS transcript 绑定
     witness 消息块；长度块防 padding 歧义）；SMT 路径语句串 = 单个 flock
     merkle 证明（leaf/root/方向位公开，sibling 为 witness，结构性识别：
     每个父消息包含前一摘要素半侧）。防拼接：归档携带有序语句表 +
     子证明分段重推导。
   - **哈希层切换**：rules 域 bump v2、状态像域 bump v3（BLAKE3 padded
     chain）、SMT 节点 = 单压缩 `H1(l||r)`（64 字节，leaf=`H1(key||value)`）；
     `canonical_state_hash`/rules/hand-openings/hand-bundle 全部走
     FlockProvider；`default_hash_provider()` 切换为 flock。M31 lookup 栈保留
     为 Blake2b 回退（reconstruction-binding / state-opening / reveal-opening
     等自洽 Blake2b 族不动）。
   - **回归**：全量 lib 测试 **420/420 全绿**（2855s，`RUST_MIN_STACK=32MB`，
     flock prove 在默认 2MB 测试线程栈上会溢出——测试运行需带该环境变量）；
     canonical 模块 80/80（449s）；flock vendored 套件 61/61 + core 332/332
     全绿。reconstruction-binding 族保持 Blake2b lookup 栈自洽（call context
     改绑 Blake2b 语句摘要，`precompile_binding.rs`）。
2. **Blake2b 压缩的二元域电路**：被上项取代（BLAKE3 内置编码器），关闭。
3. **SMT 514 压缩批**（已完成）：2×257 语句 → 2 个 merkle 证明，见上。
4. **M31 lookup 栈降级为回退路径**：原 A1（G/scheduler 合并）、A2（XOR
   代数化）停止投入（被迁移取代）；栈保留 feature-gate 供过渡与小批场景。
5. **canonical STARK 列瘦身（已完成）**：raked 家族 \~430 列 16-bit 范围位改为
   共享 256 项 LogUp 范围表（仿 cairo-air range-check 组件）：56 字节对列 +
   101 列 rake advice（原 476）+ 29 个 secure 交互列（单组件、配对分数、度界
   log\_size+1、平衡 claimed sum = 0），NUM\_COLUMNS 2173 → 1675。关键上游结论：
   **交互列必须按 bit-reversed 存储对齐**（MethodTrace 的 to\_evaluations 对所有
   承诺列做 bit-reverse，生成器按自然行序打包会导致 prover OODS 组合多项式
   校验失败而行级断言全过——本仓库用 256 行最小 cairo 式组件复现并定位）；
   其次 tamper 测试需无 panic 求值器（stwo 的 LogupAtRow Drop 断言会在约束
   失败展开期间二次 panic 导致 abort）。落地回归：canonical 模块 **80/80 全绿**
   （含 raked award 全链路 prove/verify 与全部篡改拒绝），bench 复测 canonical
   批证明 0.63→0.60s、证明尺寸 1.18→1.11 MB；九座位 betting 块稀疏化（低优先）。
6. **FRI/证明尺寸调优**：fold\_step 上调可显著缩证明降 verify（全局配置，
   需声音性复核与全量回归）。
7. **Binius 证明尺寸监控**：若 admission 需要小证明，走最终 SNARK 包装
   （业界主流上链模式），而非在 M31 里实现二元域验证器。
8. **Ristretto 组合线 LogUp 列瘦身（已完成，2026-08-23）**：`FpProgramAir` 全部
   per-limb 8-bit 位列与乘法 carry 16-bit 位列改为共享 256 项字节 LogUp 范围表
   （复用 canonical 的 cairo-air 式单组件配对分数模式；域下限提到 256 行，
   表值/多重性列随域条带化）。release 实测 104 行 reconstruction 批：
   prove 33.3s→**13.9s**（2.4×）、证明 26.2MB→**12.3MB**（2.1×）、
   verify 6.7→5.9s。全部 20 个 ristretto 模块 **103/103 全绿**（2311s，
   含全部 splice 拒绝用例）。调试期关键发现：单程序 scope/trace 构建
   只写前 2 行——域扩到 256 行后必须写满全域（padding 行复制末行程序）。
9. **Ristretto 二轮+三轮优化（已完成，2026-08-24）**：prove **13.9→1.84s（7.6×）**、
   verify **5.9→1.04s（5.7×）**、证明 12.3→9.55–10.0MB（域缩小后 FRI 每层
   揭示略增，尺寸持平），debug 全量 ristretto 套件 2311→~1900s。改动：
   - **prove 内嵌自验证门控**：`prove_ristretto_reconstruction_deck_accumulator`
     等尾部整 Archive 重验证改为 `TEXAS_RISTRETTO_SELF_VERIFY=1` opt-in（admission
     本就独立验证；prove 侧逐卡输出校验保留）。
   - **见证生成并行化**：104 个点加法程序构建、`trace_columns_batch`/`scope_
     columns_batch` 行映射、`fp_range_interaction` bitrev 列、scalar-mul 批语句
     构建全部 rayon 化；`modulus()`/`sqrt_m1()` BigUint 常量 OnceLock 缓存
     （此前每次调用重做 modpow）。
   - **列瘦身第二轮**（16-bit limb 因 M31 域阶 2^31−1 下 limb 乘积回绕不可行，
     改走加法等价方案）：值 `< p` 见证从 `p−value` 差 + 64 个 per-limb
     非零/逆旗标（129 列/值）改为 `value + (2^256−p)` 进位加法器（64 列/值，
     溢出即拒绝）；乘法 carry 删除冗余 magnitude 列（4→3 列，符号位直接
     与 lo/hi 字节组合）；scope 预处理列 3 字节/列打包（5280→1760 列/行）。
   - **verify 去见证重承诺**：`verify_ristretto_fp_program{,_batch}` 不再重建
     trace 见证与重承诺 trace 树比对根（该绑定由约束 + scope 树根承载），
     只保留 scope 树重建（语句绑定）；trace 宽度经免见证的 `trace_layout`
     从程序形状推导。
   - **三轮：域下限 256→128 行**（prove 再 −45%）：原 256 行下限只是"LogUp
     生成器需一条 SIMD 向量行 + 单列范围表"的历史假设——条纹化表机制早已
     支持小域，真实 SIMD 下限为 16 行。**声音性审查**：FRI 有效安全
     ≈ pow + E[唯一查询位]×log_blowup，30 查询在 LDE 域 D 的期望唯一位
     D(1−e^(−30/D))：D=512→29.0、D=256→28.3、D=32→19.5（**log 4 下限会把
     有效安全压到 ~30 bits，否决**）；定 log 7（104 行批 → 128 行域，与原
     log 8 同档），单程序与小批同样受益。
   - **三轮：语句摘要吸收**：`mix_program` 从逐 limb 吸收（104 程序 ≈19 万
     u32，verify 侧 0.48s）改为语句规范编码的 Blake2b-512 摘要（16 u32，
     碰撞抗性绑定，两侧各省 ~0.4–0.5s）。
   - **四轮：LogUp 字节配对（已完成，2026-08-24）**：relation arity 1→2
     （`FpRange16`），use 条目两两配对（value limb 对/sum limb 对/carry
     lo-hi 对——所有 tracked 块均为偶数长且邻接，配对=扁平列表 chunk 2），
     范围表换 65536 项 16-bit 条目（每条纹 3 列 mult/lo/hi，128 行域 =
     512 条纹）。交互列 8.05k→4.3k secure（32.2k→~17k base 列）。实测
     prove 1.84→**1.30s**、verify 1.04→**0.75s**、证明 10.0→**7.34MB**。
     代数平衡测试改用真实 arity-2 combine 原生验证。
   - **四轮：slot-OR/cross-key 线并行化（已完成）**：52 槽 prove/verify 全部
     rayon 并行（槽间独立）；槽内 8 个 scalar-window STARK 并行构建；
     `prove_ristretto_slot_or`/cross-key/批的尾部自验证全部门控。
   - **四轮：FRI fold_step 1→2 实测否决**：局部配置实测证明 7.34→7.52MB
     （+2.4%），与 canonical 侧旧实验（−1.5% 名义）方向一致——该配置下
     折叠层数本就少（log 7 域 + blowup 2），折叠省不掉多少 auth path，
     反而每层揭示变宽。已回退，协议配置维持 fold_step=1。
   - **五轮：slot-OR 深度批化（已完成，2026-08-24）**：52 槽的小 STARK
     层从"每槽独立证明"折叠为跨槽共享批——`ArchivedRistrettoReconstruction
     SlotOrBatchProof` 重构为：52-行 nonzero FpProgram 批 + 52-行标量加法
     批（新 `prove/verify_ristretto_scalar_addition_batch`）+ 416-行
     scalar-windows 批（新 `prove/verify_ristretto_scalar_windows_batch`）
     + 260-行合并 point-addition 批 + 每槽 2680-行 scalar-mul 批（52 个）。
     STARK 数 52×20≈1040 → 56。mul 语句 ABI 轻量化（内嵌窗口证明改为
     `(scalar, windows)` 数据，窗口证明归调用方/共享批持有），单槽
     slot-OR 与 cross-key archive 相应增加 `scalar_windows` 字段。
     **release E2E 实测**（`poker-hand-bench slot-or-deep-batch`，真/模拟
     分支代数闭合 fixture）：prove 1365.7s / verify 118.3s / 证明 1.27GB，
     含篡改 point-addition 行拒绝。**结论**：该线成本由 52×2680-行的
     全 FpProgram scalar-mul 批主导（每行 ~25k 列），小 STARK 批化消除的
     是次要项；下一杠杆为 mul 批合并或专用窗口/倍点 AIR。E2E 探针保留为
     bench 子命令（debug 测试版已删除——debug 下需 4–8 小时不可用）。
   回归：ristretto 全量 **104/104 绿**（二轮 1943s；三轮 1073s；四轮 1005s；
   五轮 107/107，973s，新增 scalar-add 批/scalar-windows 批/深度批绑定三测，
   均含 104 行 splice 拒绝）。release 复测演进：13.9/5.9/12.3MB →
   3.90/1.57/9.55MB（二轮）→ 1.84/1.04/10.0MB（三轮）→
   **1.28s / 0.84s / 7.34MB**（四轮；累计 prove 10.9×、verify 7.0×、
   证明 −40%）。
   修复：`proves_reconstruction_deck_in_one_ordered_batch_stark` 测试属性损坏
   （重复 `#[test]` 吞掉了属性），此前未在跑。
   **剩余机会**：slot-OR 线的 52 个 2680-行 scalar-mul 批合并为共享域或
   专用窗口/倍点 AIR（E2E 显示该层占 1366s 证明的绝大部分，且归档内嵌
   全部程序字节导致 1.27GB 证明）；常量出 trace（~3%）；verify 剩余 ≈0.5s
   FRI 查询揭示，受总承诺列宽约束，下一杠杆为 trace 树见证列（mul carry 11.2k
   列）的结构性压缩。
10. **showdown settlement AIR 前置（进行中，2026-08-24）**：VM 侧结算语义已用
   `poker_l1/.../settlement_fixture.rs` 锁定（4 场景：三层 all-in 阶梯、
   九座位九层满宽阶梯、rake+odd-chip 平分底池、run-it-twice 双 board 分胜；
   每场景断言守恒/确定性/无争议层免抽水，期望值逐位锁定）；
   `src/canonical_settlement_air_plan.rs` 固定列布局（9 座位/≤9 层/≤2 runout/
   hand-rank 6 字节/award 8 字节/odd-chip 与 rake 分配 advice，全部字节列
   走共享 256 项 LogUp 范围表，复用 raked-award 链）。
   **AIR 本体已落地（2026-08-24，`src/canonical_settlement_air.rs`）**：结算
   代数全约束（守恒/层平铺/逐 runout 平铺、runout 对半拆分按 runout 数与
   争议位门控、odd-chip `award = winner·share + winner∧extra` 线性分解 +
   `remainder < count` 借位链、winner⊆eligible、folded⇒不资格、无争议层
   r0=net/r1=0/免抽水），单组件 16 行复制域、scope=公开计划字节、witness=
   位/进位/借位/差值列（18677 列，读取宽度与求值消费宽度由专门测试锁定）。
   四 VM fixture（三层/九层阶梯、rake+odd-chip、run-it-twice 分胜）全链路
   prove/verify + 篡改拒绝 **10/10 绿**（≈15s debug）。单次 prove/verify 各
   \~1s 级。**层切片推导已并入（2026-08-24）**：逐层 `level` 公开 advice
   （尾部重复末水位保持非降），每座位三条借位链（`bet ≥ level`、
   `bet > prev`、`min` 选择）+ 贡献减法链，`eligible = active·(1−folded)·gt`
   一致性、`Σ active·contribution = gross` 加法器；11/11 绿（新增 bet 篡改
   拒绝）。**总 rake 公式链已并入（2026-08-24）**：`contested_gross`（争议层 gross
   加法器）×`bps`（school-mul 字节链）= product；`product = scaled×10⁴ +
   remainder`（常量乘字节链 + 除法余数 `< 10⁴` 上界）；两级 min 借位链
   （scaled vs cap、m1 vs contested\_gross）+ rake\_mode 门控后约束
   `plan.total_rake`；12/12 绿（新增 rake 少收/超收篡改拒绝、oracle 公式
   校验）。**rank↔winner 一致性已落地（2026-08-24）**：rank 以 24 位字典序值
   （cat·2²⁰ + kickers nibble 打包，< 2²⁴、3 字节）入公开 scope（含 9 座位
   底牌与双 board 牌字节）；逐 (层, runout) 以 8 级运行最大值选择链 + 9 组
   双向借位链等式约束 `winner_mask = eligible ∧ (rank = max)`，runout-1 槽
   按 `two_runouts ∧ contested` 门控。**7 张评估器电路（③-5b-2b）约束全部
   实现并入活路径，但 wire 家族在行级断言下仍有违规，默认门控关闭（17
   通过 + 1 ignore）**：本轮修复 base 绑定极性（\[X≠0] vs \[X==0]）、gt/lt
   双位绑定（绝对差逆 + gt·lt=0 + gt+lt+eq=1）、kicker\_eq 索引偏移、
   cat1 coverage 重复计数；单段位掩码下 bit 10（flush 基数）、bit 13
   （dropped·gt）仍失败于值 −1（手序 4/空座位的 flush total\_slots 读出
   gate=1 与四元计数矛盾——手读序探针与宽度常量测试均通过，指向全量
   AIR 中手块读取前的错位尚未定位）。二分工具链（HAND\_SECTIONS 20 段
   位掩码、TRACE\_AT/TRACE\_TOTAL 逐约束计数、逐行顺序断言、OrderProbe、
   空座位宽度/顺序探针）全部就绪并沉淀为代码。
   **追加取证（第二轮）**：以缩放恒等式（7·bit、11·bit、100·gate 等）取代
   此前的裸恒等式后，先前不可复现的"cat\_eq\[5]=1"读数被证伪——cat\_eq 全
   向量、flush gate、手内读取序（牌分解/直方图/花色/suited 存在性逐段
   对拍）在单手全开掩码下全部正确；裸恒等式轮次的"1"是跨约束读取混淆。
   剩余现象收敛为：HAND\_LIMIT=k 时首个违规位于第 k-1 手内（offset 随 k
   移动），同一手的约束在不同 k 下成败不一致——指向逐行顺序断言器在
   16 行循环中的跨行状态或按手发射计数假设（计数 837 vs 发射 1826/手）
   尚有一层未对账的发射族。gate/cat\_eq/读取序已排除。
   **第三轮取证（根因定位）**：HAND\_LIMIT 现象破解——k=3 时 three\_seat
   全过、失败来自 nine\_seat（场景循环逐场景断言，"row #0" 是各场景自己
   的行号）；全开掩码下 three\_seat 的首个失败固定在**空座位手**（手 3，
   board + 哨兵 \[0,0]）。**修复 1**：空座位 rank 承诺改为其 7 张牌的真实
   分类值（`native_rank_value`，新助手函数）——此前 VM plan 给 None→0，
   与牌面派生（board+\[0,0] 恰成三条 2）矛盾，rank↔scope 绑定必败。修复
   后 three\_seat 的空座位手仍在 flush 基数（bit 10）与 wire dropped·gt
   （bit 17）两族失败，且缩放恒等式对 cat\_eq\[5] 给出互斥读数（列位 0 vs
   表达式 1）——指向工具残留的自指干扰（不同 dump 环境改变发射序，跨运
   行比对 constraint #N 不可靠）。
   **第四轮（③-5b-2b 完成，2026-08-24）**：清除全部环境变量 dump 分支，
   落地零配置按族标签计数器（`HAND_FAMILY_LOG` + `attribute_rowwise_
   failure_family` 同进程断言归因测试）后三连修：(1) **flush kicker 见证
   按去重 rank 取 top-5**——空座位哨兵 \[0,0] 与公共牌同花时含重复 rank，
   必须按多重集（每张牌一票）展开，native classify 同步修复；(2) **wire
   coverage 对 presence 按槽位重复计数**（cat 7/6/3/0 各按 slots 数放
   大 dropped）——改为 presence 仅在 slot 0 计一次；(3) **缺失派生 rank
   绑定**——constrain\_hand 的 (category, kickers) 从未绑定到提交的
   rank\_values（牌面篡改可过 prove 的真正原因），补上 24 位三字节绑定
   （byte2 = cat·16+k1 等）。全开掩码行级断言四场景全过；**settlement
   套件 21/21 全绿**（四场景全链路 prove/verify + 五类篡改拒绝含
   tampered\_cards），HAND\_SECTIONS 默认全开（保留为二分工具），
   tampered\_cards\_break\_evaluation 已恢复。showdown 结算线的牌面派生
   评估器电路就此闭环。
11. **瓶颈转移预警**：哈希层与 Ristretto 二轮优化完成后，端到端剩余瓶颈为
    Ristretto 固定证明开销（\~1.3s/批）与 state\_root Poseidon252 AIR
    （host 边界必须消除；可在二元域位分解、M31 limb 或 Flock 类中择优评估）。
12. **Ristretto 11-bit limb + 变基 MSM（已完成，2026-08-24）**：
    - **11-bit limb（`FpProgramAir` 内部基数 32×8-bit 字节 → 24×11-bit，
      264≥256 bit 覆盖）**：canonicity 进位加法器新增 3-bit 顶约束（顶 limb < 8
      把 264-bit limb 和钉死在 2²⁵⁶ 以下）；加/减进位在 2048 基数下仍归纳于
      {−1,0,1}；乘法 carry 界 <2¹⁷（2·24·2047²/2048 ≈ 98304），拆
      `(lo<2048, hi<64)` 双查表：值/和 limb 走 **2048 项单查表**（128 行域 =
      16 条纹 × 2 列，替代原 65536 项字节对表的 512×3=1536 列），carry 对走
      **131,072 项 arity-2 配对表**（每乘 47 条目，条带列随批域翻倍减半）。
      M31 环绕安全余量：乘法关系整数界 ≈2²⁸·⁶ << 2³¹−1（11-bit 是单行全和
      约束下的安全上限内最优，13-bit 起需要拆约束）。scope 打包改 2 limb/列
      （<2²²）。公共 ABI（32 字节值）不变，仅证明内部格式换代。
    - **v1 教训（已否决）**：值与 carry 全走单查表时，乘法 carry 94 条目/乘、
      值 24 单条目/值，交互层条目反超 8-bit 基线（值 16 对、carry 63 条目），
      乘密集负载实测 prove +5–8%、证明 +2–5%；仅轻负载小程序大胜
      （证明 −57%）。v2 把 carry 配对成 47 条目/乘后翻正。
    - **实测（release、空闲机、顺序单跑，`ristretto_perf` 基准，
      8-bit 基线经独立 worktree 同机测得）**：压缩定点标量乘批
      N=2/4 prove 7.9→**7.5s**/14.9→**14.6s**、证明 11.19→**10.71MB**
      /15.43→**14.93MB**；MSM N=2/4 prove 9.3→**8.7s**/16.7→**15.7s**；
      单程序压缩点加法 prove 1.2→1.3s、证明 +4%（131k 表在 128 行单程序域
      条纹列最多，批域下随行数减半）；小 add/mul/sub 程序证明 +55%
      （单个乘法承担固定表列，非生产路径）。生产路径（reconstruction 批、
      标量乘批、MSM——全部 ≥128 行批域）净收益 −2…−6% prove、−3…−4% 证明。
    - **变基 MSM（新能力，`ristretto_msm_air.rs`）**：`prove_ristretto_msm`
      纯组合三层既有批 STARK——标量 4-bit 窗口分解批 + 每标量 335 行压缩
      定点乘批 + N−1 行压缩点加法串行累加批——零新 AIR；验证器逐行确定性
      重建、窗口↔标量↔基点↔累加链四重绑定，空批/单对带累加等边角全部
      fail-closed。MSM N=4：prove 15.7s / verify 2.3s / 归档 22.3MB。
13. **按审计顺序的性能与信任边界轮（已完成，2026-08-25）**：
    - **slot-OR 微 STARK 并行化**：`prove_ristretto_scalar_windows_batch` 与
      `prove_ristretto_scalar_addition_batch` 内嵌的每标量 canonical 微 STARK
      从串行 `iter()` 改 `par_iter()`（52 槽深批原 572 个串行 PoW+FRI）。
      实测深批 prove 1365.7→**1176.3s**（−14%，含同期编译抢核干扰，干净
      机器下更好），归档 1.27→1.246GB。
    - **flock Ligerito Slim profile**：四处 `Blake3Setup` 从 Fast（rate 1）
      切换 Slim（rate 2）。实测 hand bundle 证明 **1.45MB→0.76MB（−48%）**、
      全手牌 tagged 证明 **3.62→2.93MB（−19%）**，prove/verify 时间持平
      （3.49s/3.08s）。另：flock witness 在 debug 深递归会爆 2MB 测试线程栈，
      prove 现运行于专用 64MB 栈 rayon 池（`flock_pool().install`）。
    - **state_root host 重算移除（信任边界消除）**：root 定义改为
      `BLAKE3("zchain.texas_poker.state_root.v1" || hot-v30 bytes)`（与
      flock 链同函数；ObjectDb-absence 占位表用固定哨兵 preimage 仍有可证
      明语句）。`verify_roots` 不再由 host 重算 Poseidon252，改为要求
      `ArchivedStateRootBindingProof`（`state_root_binding.rs`）：flock 证明
      恰好覆盖 `(pre, post)` 两个 `(domain||hot bytes, root)` 语句，验证器
      从 transcript 绑定的 image 确定性导出端点后交给哈希证明，任何拼接/
      乱序/替换 fail-closed。绑定证明随 `CreateTableProof`/`MethodProof`、
      `ArchivedMethodProof`、`DualProofBundle`（信封升 v2，新增 root-binding
      段）、`ArchivedComponentProof` 全链路携带；同输入绑定有确定性缓存。
      生产 release guard 保留：`cfg(test)` 豁免 release 测试 harness，
      `RUSTFLAGS='--cfg=texas_release_tests'` 显式豁免 release 集成测试。
    - **BigUint 见证削减**：`modulus()` 改返回 `&'static BigUint`（免每调
      clone），builder 与 witness 的乘法商/余改单次 `div_rem`（除法减半）。
    - **测试加速（release 化）**：移除自引用 dev-dependency（集成测试改
      `--features test-helpers` 显式开启）后，`cargo test --release --lib`
      **450/450 全绿仅 482s**（debug 全量 >2h）；release 集成测试
      `RUSTFLAGS='--cfg=texas_release_tests' cargo test --release
      --features test-helpers --tests` 全部通过（含 dual-proof v2 信封
      7/7、outer aggregate 4/4 修复两处 root 字节解码）。
      同标量多基（批量解密 sk·C1ᵢ）可复用同一窗口分解见证再省一份。
    - 回归：`ristretto_fp_program_air` 35/35、MSM 3/3、ristretto 全模块套件全绿。
14. **Ristretto 见证算术原生化 + 编排去 round-trip 轮（已完成，2026-08-25）**：
    - **域算术后端原生化**：`curve25519-dalek` 4.x 的 `FieldElement` 是
      `pub(crate)` 无法导入，改依赖 **fiat-crypto 0.2**（即 dalek 内部编译
      所用、同源形式化验证的 u64 后端）。`ristretto_fp_program_air` 新增
      `fp25519` 模块，decode/encode 的 inverse-sqrt、`nonnegative_sqrt`、
      模逆全部从 `BigUint::modpow`（除法约减）换到惰性约减 Fe；期间定位
      并修正 INVERT 指数常数（p−2 首字节 0xeb），用分阶段 oracle 对照
      钉死。sqrt_ratio 重写为 dalek 单链 `r=(u·v³)·(u·v⁷)^((p−5)/8)`
      （幂链 2–6 条→1 条，偶根约定 fail-closed 保留）；modulus/sqrt_m1/
      negative_edwards_d 全部 `OnceLock` 缓存。字节一致性由 BigUint 旧
      算法 oracle 对照测试 + 全量套件双保障，AIR 约束零改动。
    - **witness 冗余削减**：decode inverse-sqrt 全局 memo（纯函数）+ 倍加
      行 left==right 短路（256/335 行各省一次链）；`trace_tracked_columns`
      改走 shape-only `trace_layout`（模板 witness 不再整体重算）；
      `ProgramWitness` 携带 canonicity/limbs 消除二次分解；6 处 prove 路径
      自验证统一 `ristretto_self_verify_enabled()` 门控（verify 公开入口
      一行未动）。
    - **BLAKE3 链摘要去重**：`chain_steps` 纯函数 prove/verify 共用；
      digest 流式化（不再物化 blocks 向量，省 ≥32KB/次）；prove 侧直接
      复用链终端 cv（压缩量减半）；verify 侧不再重建 blocks 取 steps。
    - **stage-4 去 round-trip**：`prove_outer_aggregate` 内对刚 prove 产物
      的 crypto 重验 3→1（receipt 签发所需的 native Stark 验证保留，总数
      不增；跨进程/字节输入的全量验证 fail-closed 保留）；`children/
      tasks.to_vec()` 深拷贝、整 bundle 重复 encode 尺寸校验（改纯长度
      计算 `encoded_len`/`validate_package_lengths`）、`clone_anchor`
      encode→decode 往返全部消除；公开 verify API 与 wire 格式未动。
    - **实测（ristretto_perf，release+nightly，对照第 12 条空闲机基线）**：
      压缩定点标量乘批 N=2 prove 7.5→**6.6s（−12%）**、N=4 14.6→
      **12.8s（−12%）**；变基 MSM N=2 8.7→**8.0s（−8%）**、N=4
      15.7→**14.2s（−10%）**；证明字节不变，verify 侧同步受益（单程序
      点加 verify 717ms）。
    - **完整一手牌（poker-hand-bench，不含 Ristretto 密码学阶段）**：
      bundle prove 2.75→2.70s、hand 批 verify 210→**185ms（−12%）**；
      TOTAL prove 3.59s / verify 3.09s / 2.93MB，较第 13 条基线
      （3.49s/3.08s/2.93MB）总体持平——本轮主战场在 Ristretto witness
      与 stage-4 聚合重验路径，hand-bench 不经过该路径，属预期。
    - 回归：ristretto 套件 **110/110**（1 ignored 为既有）、flock 4/4、
      e2e dual-proof 7/7、outer aggregate 4/4（`RUSTFLAGS=
      '--cfg=texas_release_tests' cargo +nightly test --release
      --features test-helpers`）。
15. **剩余优化轮：编排局部 + 组合路径核查 + 协议级双实验（已完成，
    2026-08-25）**：
    - **编排局部**：`verifier.rs` StarkProof 深拷贝改部分移动（FRI 层 Vec
      免拷贝）；`state_root_binding` 缓存加 1024 容量 FIFO 淘汰（长驻
      prover 内存有界）；tagged receipts 改轻量 `decode_commitments()`
      （bincode `Deserializer::from_slice` 流式前缀解析，只读 config+
      commitments，不反解 MB 级 FRI 尾部）；`aggregate_digest` 预分配
      + 每 child 哈希 rayon 并行（按索引序拼接，摘要字节不变）；
      `same_task` 删除冗余 `canonical_command_bytes` 末项比较（其输入
      method_kind/raw_args 已被逐字段比较，两次 borsh 序列化纯冗余）。
    - **program_air 局部**：trace 全路径列式物化（`from_columns`/
      `set_column`，消除 per-row clone 与跨列散写及预零化）；`FpProgramAir`
      构造时预计算 `scope_ids`/`canonicity`（evaluate 免数百次 format!
      与重算）；witness 入口一次性 `Vec<BigUint>` 预转换 + 恒不触发校验
      降级 debug-only；点选择器去重键改 BLAKE2b 流式指纹（免数百 KB×16
      序列化）；批量归档改 owned 变体（免 N×335 program 深拷贝）；MSM
      累加链前 rayon 预热 decode memo。端到端 prove 持平（FRI/承诺主导），
      分配/带宽削减为后续批规模放大留出空间。
    - **组合路径核查**：`prove_ristretto_point_decode/encode/edwards_addition`
      组合式路径生产调用方为零（host-zero-trust 重构时已全部迁移至
      program AIR 折叠版），组合式仅存测试，无需迁移。
    - **协议实验一（carry 对表拆分）— 实施后回退**：删除 131,072 项
      FpCarry17 对表，carry 拆 FpRange11 lo + 64 项 FpRange6 hi。全测试
      过、小程序 prove −42%/证明 −73%，但乘法密集生产路径显著回归
      （scalar-mul 批 +14%、MSM N=4 prove 14.3→15.7s +10%），超预设 2%
      红线且与第 12 条"纯 11-bit 单表回归"教训同构（interaction 条目数
      是乘密集路径真瓶颈）——按实测裁决回退，对表方案保留。
    - **协议实验二（LOG_SIZE 7→6）— 实施后回退**：单程序地板降 6 后
      测试仍绿、单程序点加 prove −30%，但 carry 对表 stripes 1024→2048
      致小程序证明 +50%、verify +45%，且承诺域缩小带来 FRI 查询去重
      损失（30 queries 有效 distinct 下降）——回退至 7，128 行地板的
      声音性注释维持成立。
    - **完整一手牌（poker-hand-bench）**：bundle prove 2.70→**2.47s**、
      verify 2.69→**2.44s**；hand 批 verify 210→**183ms**；流水线双批
      0.89→**0.81s**；**TOTAL prove 3.59→3.27s（−9%）/ verify 3.09→
      2.82s（−9%）**，tagged 证明 2.93MB 不变。
    - 回归：ristretto 110/110、flock 4/4、e2e dual-proof 7/7、outer
      aggregate 4/4、state_root_binding 2/2、tagged/orchestrator 16/16
      （release+nightly）。
16. **flock 子证明并行化 + Setup 电路缓存（已完成，2026-08-25）**：
    - **可行性研究结论**：多链并入单链不可行（chain proof 仅单链 cv
      穿线结构）；批 merkle `path_log>0` 要求 P 条路径共享同一 root，
      而 bundle 的前后两个 state root 不同，无法并入；更小 m 的
      Ligerito 配置不存在（m=k_log+n_log 由 R1CS 尺寸决定，Slim(m=22)
      已是最小注册实例，Fast profile 实测证明 +92% 已否决）。
    - **关键发现**：`csc_lincheck_circuit` 缓存是每个 `BlockR1cs` 实例
      私有——每次 `Blake3Setup::with_profile` 都重付一次 ~21M 非零的
      CSC 折叠电路构建，prove/verify 侧每条子证明各付一份。
    - **实现**（仅 `src/blake3_flock.rs`，证明格式与字节完全不变）：
      ①`segment_statements()` 把语句序列切段（prove/verify 共用同一
      切分），prove 侧在 flock_pool（64MB 栈池）`into_par_iter` 并行
      生成各子证明（每个子证明的 FsChallenger 由域分隔+语句字节独立
      种子，无共享转录顺序，并行安全）；②verify 侧先串行完成段↔归档
      配对与布局校验（逐语句 fail-closed 不变）再并行验证，按段序
      返回首个错误；③`blake3_setup()` 按 n_blocks 全局缓存
      `Blake3Setup`，消除每子证明的 CSC 电路重建。
    - **实测**（3 次稳定复测）：hand bundle prove 2.47–2.70→**0.61s
      （−75%）**、verify 2.44–2.69→**1.50s（−39%）**、证明字节
      758,584B 不变；**TOTAL prove 3.27–3.42→1.45s（−56%）/ verify
      2.82–2.90→1.88s（−34%）**，tagged 2.93MB 不变。verify 收敛到
      ~3 个子证明墙钟（5 个并发 FRI 验证受内存带宽限制，硬件上限）。
    - 回归：flock 4/4（含两个 fail-closed 篡改拒绝测试，未削弱）、
      state_root 13/13、e2e dual-proof 7/7、outer aggregate 4/4、
      create_table 10/10、ristretto 110/110、tagged 16/16
      （release+nightly）。

**完整一手牌实测（2026-08-23，Apple Silicon Mac15,7，BLAKE3/flock 后端）**：

- lifecycle 批 verify 224.6ms / hand 批 verify 210.0ms（canonical AIR 不变）；
  流水线双批 prove **0.89s**；
- 完整 hand bundle（rules + 2 状态像 + 2 SMT 路径，517 语句 → 3 链证明 +
  2 merkle 证明）：prove **2.75s** / verify **2.70s** / 证明 **1.45MB**；
- **TOTAL：prove 3.64s / verify 3.14s / 3.62MB**。对照切换前 M31 lookup 栈
  （bundle prove 21.7s / verify 10.0s / 9.4MB，总计 22.6s/10.9s）：bundle
  prove **7.9×**、verify **3.7×**、证明尺寸 **6.5×** 改善；验证侧原
  G/scheduler 热点（stwo 常量表承诺树重建）随迁移整体消失。
- 后续压缩空间：5 个子证明各有 \~0.5s 级固定 verify 开销，可经 (a) 多链
  并入单链/批 merkle（path\_log>0），(b) slim/secure profile 与更小 m 的
  Ligerito 配置注册，(c) 递归包装聚合，进一步逼近 \~1s/手。
  FRI fold\_step 1→2 实验（canonical 侧）：证明尺寸 −1.5%、时间持平，收益不抵
  声音性复核成本，维持 1。

## 第 17 轮：scalar-mul 归档 wire 压缩与 release 基准（2026-08-26）

本轮针对 slot-OR 归档中可由 `(scalar, windows, base)` 确定重建的
Fp-program 行做了字节级压缩。新的 `RSMB`/version-1 wire 只携带 statements、
认证 STARK 字节和 claimed sum；解码端重建并校验程序行与 statement output，旧
Borsh 格式仍可在 wire 边界读取，因而不改变证明语义或篡改拒绝规则。

冷启动 release microbench（Apple Silicon，`cargo +nightly run --release`）：

| 场景 | prove | verify | 归档/证明 |
| --- | ---: | ---: | ---: |
| 完整 canonical 手牌 | 2.005 s | 396 ms | 约 2.98 MB |
| Ristretto accumulator（104 rows） | 1.61 s | 0.88 s | 7.14 MB |
| compressed scalar-mul（N=52） | 233.5 s | 10.1 s | **6.54 MB** |

同一 N=52 fixture 的旧归档约 102 MB；新 wire 降至约 6.54 MB（约 −94%），
主要收益来自移除 52 条 scalar-mul schedule 中重复嵌入的 335-row programs。
本轮未改变 scalar-mul trace 域大小，因此证明时间仍由 FRI/承诺主导；下一步若
继续压缩域大小，应单独进行协议格式与基准评审。

回归：`RUSTFLAGS='--cfg=texas_release_tests' cargo +nightly test --release
--features test-helpers`，469 passed、0 failed、4 ignored；所有集成测试和
doctest 均通过。

## 方法说明

- 计时为墙钟，单次冷启动（twiddle/列池缓存跨证明复用属正常生产路径）。
- 两批次按真实发生顺序串行计入总计；openings 是一手牌一次的固定开销。
- bench 驱动器（`hand-bench/src/main.rs`）本身通过全部 witness 校验与 AIR
  证明/验证（含九座位轮转、加注重置 acted、终局 reset 投影），等价于一组
  端到端正确性测试。
