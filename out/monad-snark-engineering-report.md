# Monad SNARK 结算全链路工程报告

- 日期：2026-09-29
- 范围：`poker_texas_air`（branch `feat/prove_perf`，新增 workspace crate `groth16-wrap`）+ `zchain`（`contracts/monad` 新增 SNARK 验证/结算合约）
- 报告性质：本报告汇总本工程各阶段的实测证据（各节数据均标注来源：阶段产物 JSON / 阶段实跑输出 / 代码引用）。报告撰写阶段对在盘产物与关键代码引用做了核验（清单见附录 B）；凡非本次撰写阶段亲跑的命令，均按阶段证据如实转述，不重复冒充实测。
- 修订记录：2026-09-29 依独立复审 31 条逐条修订（复审修正轮的实测/实读清单见附录 B）。对无法核实的记录（settle est/limit、probe finalized、「前期上锚」、前端失败细节、归档原始体积等）**如实标注存疑与未解**，不代以推测值；有条件实测的（verifyProof 实网 gas、内存基线、git 状态、门禁项数、脚本比对逻辑）已补实测并更新相应结论。
- 明细产物（在盘已核验）：`/tmp/monad-local-anchor.json`、`/tmp/monad-wrap-deploy.json`、`/tmp/monad-final-settlement.json`；复核脚本：`scripts/check_local_anchor.sh`、`scripts/check_wrap_onchain.sh`、`scripts/check_stark_deploy.sh`、`scripts/check_final_settlement.sh`。

---

## 0. 结论先行

**交付了什么**：把「单手德州结算的 STARK fact 语句」（`program_hash`、`hand_binding`、`fact = poseidon_hash_many(program_hash ‖ output)`）用 BN254 Groth16 包裹（新 crate `groth16-wrap`），配套 `Groth16Verifier.sol` + `SettleWrap.sol` 部署到 Monad 测试网并完成链上实测；以一手真实牌局打通全链路：

```
真实牌局(stark texas-monad 实例) → Cairo STARK 出证(4795 steps) → fact-verify
→ Groth16 包裹(单手 4.58M 约束) → L1Inbox.submitBatch 上锚(index=6)
→ SettleWrap.settle 链上验证 → settledFact 登记 + WrapSettled 事件
```

> 注：此为**执行顺序**示意。链上「上锚」与「settle」是两条**无合约级耦合**的通道——`SettleWrap.settle` 不校验批次根、L1Inbox 不引用 SettleWrap（合约语义详见 §9.1）；`settledFact` 目前只有登记与 public getter，**无链上消费方**。

复核脚本 `check_final_settlement.sh` 实跑 5/5 OK（exit=0）。

**里程碑总览：9 项，7 完成 / 2 受阻。**

| # | 里程碑 | 状态 | 关键结果 |
|---|--------|------|----------|
| 1 | 方案盘点 | ✅ 完成 | 选型 Groth16 wrapper 路线；完整 STWO verifier 电路化经量级估算否决（非实测，见 §2） |
| 2 | B 单手包裹实现 | ✅ 完成 | cargo 16+6 / forge 21+21 门禁全绿；单手 4,584,665 约束；EVM 字序 anvil 实测钉死 |
| 3 | C 批量聚合实现 | ✅ 完成 | 金向量 2×K4 多证明架构（18,331,967 约束/电路）稳定通过；K=8 撞本机资源墙 |
| 4 | 验证耗时实测 | ✅ 完成（2026-10-02 复跑结案，§10.1 附注） | 同机复跑噪声内一致（25ms/52.8s/36.6s/1.59ms）；真实死因 = 金常量钉扎错位（已修），非入口 OOM |
| 5 | 本地联调上锚 | ✅ 完成 | 本地栈四步全通；probe 7/7 PASS；真实上锚 tx 落链，`check_local_anchor.sh` 全路径验证 |
| 6 | 前端 Monad 钱包 | ⛔ 受阻 | 3 轮未过构建/测试门禁（stage 自述，无失败输出，**不可独立核验**；文件已暂存，见 §10.2） |
| 7 | SNARK 合约部署与链上实测 | ✅ 完成 | 两合约部署 Monad 测试网；链上 verifyProof==true、WrapSettled 事件、settledFact 读回一致 |
| 8 | stark 服务器部署 | ✅ 完成 | 三构建单元 + 四 systemd 单元部署；13 项探活硬门禁 PASS；磁盘事故经授权处置 |
| 9 | 全链路结算演练 | ✅ 完成 | 一手真实牌局全链路落链；`check_final_settlement.sh` 5/5 OK |

**关键数字**（口径与出处见 §5 耗时实测表）：

- 单手包裹电路 **4,584,665 约束**（实测）；setup：bench-verify 区间 ≈46–55s、全链路复跑单值 45.5s（两口径分列，§5）；Groth16 prove ≈31.9s；本地 verify ≈1.55ms。
- 链上 `verifyProof` gas：**216,346（forge test 金向量用例 = 本地 EVM 规范 gas 表口径）**；**Monad 测试网对同一 356B calldata 实测 `eth_estimateGas` = 1,049,894**（报告撰写阶段实跑，附录 B）——Monad 对 pairing/ecMul 预编译的计价远高于 EVM 规范，这是 `SettleWrap.settle` 全流程 1,189,962~1,190,348 的主要构成（口径详见 §5 表注）。
- 资金：**「按 gas_limit×price 计费」的判据是余额逐 wei 核对**（部署三笔后余额差 == Σ(limit×price)，见 §7.4）；回执 gasUsed==gasLimit 是 receipt 现象（该字段不反映执行消耗），不作为计费证据使用。合约部署三笔 **0.214875852 MON**、全链路两笔 **0.130613448 MON**、本地联调上锚一笔 **0.009199380 MON**，三阶段写链合计 **≈0.3547 MON**。
- STARK 侧：Cairo 4795 steps、prove 8.23s、STWO verify 13ms；fact-verify CLI 对 12.2MB 真实证明 **stark_verify_ms=24**。

**信任边界（一句话版，全文见 §11）**：Monad 链上体现的是「operator 背书 + 电路 hash 一致性」，**不是**去信任的 STARK 验证；trusted setup 为固定种子单方仪式（测试网口径）。完整 STWO verifier 电路化因量级不可行（估算 10^7–10^8 约束）列为二期。

---

## 1. 里程碑证据一览

| 里程碑 | 状态 | 证据要点 |
|--------|------|----------|
| 方案盘点 | 完成 | Monad 预编译 0x06/0x07/0x08 eth_call 实测可用；STWO verifier 电路化量级估算否决；「链下 fact-verify + 声明式信任边界」路线确立（§2） |
| B 单手包裹实现 | 完成 | `cargo test -p groth16-wrap` lib 16/16 + roundtrip 6/6；`forge test` 21/21；金向量冒烟与 golden 常量字节一致；bench-verify 单次实测数字（§3、§5） |
| C 批量聚合实现 | 完成 | cargo/forge 门禁全绿；2×K4（count 2）三件套写入且重跑字节级一致；K=8 SIGKILL×3 记录（§4） |
| 验证耗时实测 | ✅ 完成（2026-10-02 复跑结案 §10.1 附注；钉扎错位修复随附注提交） |
| 本地联调上锚 | 完成 | 本地栈四进程健康；probe 7/7 PASS；submitBatch(index=5) 落链并双向复核；检查脚本正/负路径 4 场景验证（§6） |
| 前端 Monad 钱包 | 受阻 | 3 轮未过构建/测试门禁（阶段自述，不可独立核验）；`client/src/starknet/{evmKeccak,monadSettlement,monadWallet}.ts` 及测试在盘且已暂存（撰写阶段 `git status --porcelain` 实跑为 A，§10.2） |
| SNARK 合约部署与链上实测 | 完成 | build_solc OK；部署 + settle 三笔 tx 全部 status=0x1；4 步链上复核脚本全绿（§7） |
| stark 服务器部署 | 完成 | 服务器三构建 OK；4 个 systemd 单元装配；探活 13 项硬门禁 PASS；RocksDB 归档+删除处置（§8） |
| 全链路结算演练 | 完成 | ①–⑦ 七步全通；anchor+settle 两笔 tx 落链；5/5 复核（§9） |

---

## 2. 方案盘点与选型

### 2.1 链上验证前提（方案期实测）

- **Monad 测试网预编译 0x06/0x07/0x08 本次 eth_call 实测全部可用**：pairing(0x08) 用 `e(g1,g2)·e(-g1,g2)=1` 双对输入（G2 生成元常量取自 `ark-bn254-0.5.0/src/curves/g2.rs:97-115`）返回 `0x…01=true`；ecMul(0x07) 对 `2*(1,2)` 返回正确倍点；ecAdd(0x06) 同。
- `Groth16Verifier.sol` 采用 snarkjs BN254 模板；**编译**走 `contracts/monad/build_solc.sh` 模式（`tools_external/solc`，`--evm-version cancun`；`build_solc.sh:23-27` 实证）——「无 foundry 依赖」仅指编译/部署产物路径（solc 直调），**测试 runner 用 forge**（§3.4），两者不冲突。
- 电路用 ark-r1cs-std `NonNativeFieldVar` 做 Fp252-in-Fr。方案期保守估算 ~1M 约束/手 → **实测 4.58M**。实测远大于估算的原因**未经对比测量**（未实测 0.5/0.6 或其他实现的约束数差异；0.5 版因约束不满足根本不可用，见 §3.3 修正①）——「ark 0.6 emulated eager-mul 所致」是代码层面的归因**推测**，非测量结论。

### 2.2 为什么不做完整 STARK verifier 电路（量级估算，非实测）

cairo-air 2.4.0 的 STWO 验证 = FRI 折叠 + DEEP + OOD + Merkle 路径，涉及数千次 Poseidon/压缩哈希 + 大量 Fp252 运算；按单置换 ~10^5 约束折算，STWO verifier R1CS ≈ **10^7–10^8 约束** → QAP 矩阵与 MSM 内存 10–100GB 级、Groth16 prove 小时-天级，且 12MB 证明 JSON 的 witness 处理不可行，64 手批量化直接不可能。工程量数人月 vs wrapper 数天。

> **依据限定**：本节为纯量级估算，**非实测**。其中「单置换 ~10^5 约束」是方案期的保守折算系数，无出处引用、无测量支撑；「10^7–10^8 约束」「内存 10–100GB」「64 手批量化直接不可能」等结论均建立在该未验证系数之上，量级判断可信、精确数字不可引用。若二期要复核，应先对 STWO verifier 电路做一次真实 R1CS 计数。

**决策**：本期以「链下 fact-verify（STWO 验证 + 程序哈希钉扎，`fact-verify/src/lib.rs:89-106` verify_cairo、`:113-126` 哈希钉扎）+ 声明式信任边界」换 Monad 测试网全链路落地；去信任化（STARK 上链或递归聚合）列为二期。

---

## 3. B：单手包裹实现（完成）

### 3.1 交付物

新增 workspace crate `groth16-wrap`（已加入根 `Cargo.toml` members）：

- **电路**：非原生 Fp252-in-Fr 的 Starknet Hades（R_F=8 / R_P=83 / t=3 / sbox x³ / ALPHA=3，107 轮常量取自 `lambdaworks-crypto-0.13.0 parameters.rs:339`）+ output 形状钉扎（长度前缀 15、`'SP2M_OK'`）+ `hand_binding ↔ output[5]` 位绑定；公开输入 3×Fr。
- **合约**（`zchain contracts/monad`）：`Groth16Verifier.sol`（gen-sol 注入 VK，EIP-197 预编译配平）+ `SettleWrap.sol`（verifyProof → settledFact 登记 + WrapSettled 事件）；金向量 forge 测试断言链上 `verifyProof==true`（gas 216,346，本地 EVM 口径；Monad 实网 1,049,894，见 §5）；`build_solc.sh` 纳入。
- **信任边界**写入 `lib.rs` / 合约 NatSpec（撰写阶段核验：`SettleWrap.sol:13-20` 在盘确认）。
- **bin**：`wrap-proof`（JSON → 证明 JSON，`b_evm` 为链上 calldata 字序）、`bench-verify`（子进程复用 fact-verify CLI 跑真实 STARK 计时）、`gen-sol`、`gen-sol-batch`。

### 3.2 EVM 字序与 verifier bug（实测钉死）

- **EVM 字序经 anvil eth_call 实测钉死：EIP-197 Fp2 = (虚部 c1, 实部 c0)**。`groth16-wrap/src/lib.rs:126-129` 注释与 `b_evm` 导出（撰写阶段在盘核验）；合约部署阶段 eth_call 进一步裁决：`settle(b_evm)` 成功、ark 字序 revert（§7.4）。
- 调试中钉出并修复 verifier 初版 `_mulAdd` 把标量乘错加在累加元上的 bug（现 q·s 后加 p）。

### 3.3 与方案的三处实测修正

1. **arkworks 用 0.6**：0.5.0 emulated 算术在 witness 长链上约束不满足（实测 `is_satisfied=false`），0.6 重写后修复（全部本地缓存）。
2. **Poseidon sbox 是 x³ 非 x⁵**：以 lambdaworks `ALPHA=3` 源码为准。
3. **真实公开段 16 felts**：`[0]`=长度前缀 15、MAGIC 在 `[1]`、`hand_binding` 在 `[5]`——方案的 `output[0]`/`output[4]` 偏移差一个数组长度前缀；电路以真实产物 + fact-verify 公式为准。

### 3.4 门禁与自测（阶段实跑）

- `cargo test -p groth16-wrap`：lib **16/16 ok**（poseidon 原生实现对拍 starknet-crypto 随机向量 0–25 长度全一致；types-core 金向量 `hades([9,0xb,0x2])`；坏 fact/坏 MAGIC/换 binding 槽全拒绝）+ `tests/roundtrip` **6/6 ok**（seeded setup→prove→verify roundtrip、双篡改拒绝、batch K=2 prove/verify、金向量常量本地 verify；roundtrip 全程 3223.68s dev profile）。
  - 规模参照（报告撰写阶段静态计数，`grep -c '#\[test\]'`，**静态函数数 ≠ 运行通过数**）：src 内 19 个（batch 3 / felt 4 / lib 1 / poseidon_circuit 5 / poseidon 3 / wrap_circuit 3）+ roundtrip 6；阶段运行的「lib 16/16」为运行口径，与静态计数差异未逐条核对（单函数多断言/条件跳过等）。
- `forge test`（zchain/contracts/monad）：**21/21 ok** = L1Settlement 16 + WrapSettleTest 5（金向量链上 `verifyProof==true`、settle 事件/登记、双结算 revert、假证明 revert、篡改 fact 拒绝）。静态计数同口径：`function test` 计数 L1Settlement.t.sol 16 + WrapSettle.t.sol 5，一致。
- `./build_solc.sh` → `build_solc: OK`（5 合约 bin+abi）。
- wrap-proof 冒烟：fact=`0x030675cf…0ea5` 与金向量一致，**证明字节与已提交 golden 常量相同**（固定种子可复现）。
- `deploy_wrap_monad.sh` 在 B 阶段仅 bash -n 语法验收未执行（需求不含上链）；后续合约部署阶段实际执行并修复一处 cast 参数顺序 bug（§7.4）。

---

## 4. C：批量聚合实现（完成）

> **「批量」语义澄清**：本实现是**同一电路实例内含 K 手语句、单证明覆盖 K 条 statement**（K=2/K=4）；verify 侧一次 `verifyProof`（~1.6ms）覆盖 K 手，单手验证成本 ≈1/K——节省在验证侧。**prove 侧近似线性**（K=2 prove 69.8s ≈ 2× 单手 31.9s，§5），无跨证明压缩。**不是 Groth16 递归聚合**（不把证明作为电路输入做 proof composition）；「聚合」一词在 §8/§9 的 `aggregateCount` 语境下另有所指（批次根的二级折叠，见 §8.3），两者无关。

- 门禁（阶段报告仅记「cargo/forge 门禁全绿」，**运行通过用例数未留档**；报告撰写阶段静态计数供规模参照：rust 侧含 batch 单元后 `#[test]` 共 19+6 个、forge 侧 `function test` 共 16+5+7=28 个，其中 WrapBatchSettle.t.sol 7 个为 C 期新增——静态数 ≠ 运行通过数）。金向量缩样改为 **2×K4 多证明架构（count 2）** → 单电路约束 **18,331,967**，setup+2 prove **689–733s**，本地逐证明 verify 通过后写入三件套（verifier / golden.sol / json），**重跑字节级一致**。
- 聚合侧合约与测试在盘核验存在：`Groth16VerifierBatch.sol`、`SettleBatch.sol`、`test/WrapBatchGolden.{json,sol}`、`test/WrapBatchSettle.t.sol`、`src/bin/gen_sol_batch.rs`。
- **关键实测记录（本机资源墙）**：K=8 单证明（36.7M 约束）setup 峰值阶段连续 3 次被系统 SIGKILL（EXIT_STATUS=137；daemon 化、改名、`RAYON_NUM_THREADS=1` 均复现；RSS 采样 ≤8.4GB 但 swap 封顶 4GB，无 crash report）——判定为本机资源墙。据此把金向量缩样为 2×K4（18.3M/电路），峰值减半后稳定通过。
- 启示：>18M 约束的 setup 需要更大内存/swap 的机器；批量上限在本机为 4 手/电路。

---

## 5. 耗时与资源实测表

| 项目 | 数值 | 口径 / 来源 |
|------|------|-------------|
| Cairo STARK 出证（settlement_private.cairo，真实手） | 4795 steps；prove 8.23s；STWO verify 13ms | 全链路 ②，proving-tool 实跑 |
| fact-verify CLI（STARK 验证，12.2MB 真证明） | **stark_verify_ms=24**（3 次取最小，钉扎校验过） | B 阶段 bench-verify 单次实测。**口径未说明**：是否含 12.2MB 证明 JSON 的读取/解析无记录；与上行的 STWO verify 13ms 是两个口径（13ms = proving-tool 自身打印的 STWO 库 verify 耗时；24ms = fact-verify CLI 端到端），二者换算关系未交代 |
| 单手包裹电路约束数 | **4,584,665**（实测） | bench-verify 输出 |
| 单手 setup | **≈46–55s**（B 阶段 bench-verify 区间，来源：bench-verify 单次运行内多次采样）；全链路 ④ 复跑单值 **45.5s**（略低于区间下界，两次独立运行的正常波动；两口径不应合并为一个区间） | bench-verify / 全链路 ④ |
| 单手 Groth16 prove | **31,875ms**（≈31.9s） | bench-verify；全链路复跑 31.8s |
| 单手本地 verify | 1.547ms（bench-verify）；1586–1590µs（wrap-proof / 全链路） | 阶段实跑 |
| batch K=2 | prove 69.8s / verify 1.6ms | bench-verify |
| C 金向量 2×K4（count 2） | 单电路 **18,331,967** 约束；setup+2 prove **689–733s** | 阶段实跑，重跑字节级一致 |
| K=8 单证明（36.7M 约束） | setup 峰值 SIGKILL(137) ×3，未完成 | 本机资源墙（§4） |
| 链上 verifyProof（金向量，forge 测试） | **gas 216,346** | WrapSettleTest 实测，**本地 EVM 规范 gas 表口径（anvil/forge）** |
| 链上 verifyProof（同一电路，**Monad 测试网实网**） | **eth_estimateGas = 1,049,894**（356B calldata，selector 0x11479fea） | 报告撰写阶段实跑：`cast estimate 0x9100…0eb0 <verifyProof calldata>`（附录 B）。与 forge 口径差 ~83 万，主因 **Monad 对 pairing/ecMul 预编译的计价高于 EVM 规范**（ settle 全流程 1.19M ≈ 该值 + SSTORE + 事件 + 基础开销，构成自洽；Monad gas 表细节未逐项实测） |
| 链上 settle()（金向量样本经 SettleWrap） | gasUsed **1,189,962**（==limit） | 部署阶段 tx 回执 |
| 链上 settle()（全链路真实手） | gasUsed **1,190,348**（==limit） | 全链路 tx 回执 |
| 链上 submitBatch 上锚 | 90,190（本地联调）/ 90,176（全链路），均 ==limit | tx 回执 |
| 合约部署 gas | Groth16Verifier 656,929；SettleWrap 259,735（均 ==limit） | 部署 tx 回执 |
| 资金（计费口径判据 = **余额逐 wei 核对**，见下注） | 部署三笔 0.214875852 MON；全链路两笔 0.130613448 MON；本地联调锚 0.009199380 MON | 三份明细 JSON（撰写阶段读取核验），余额差额逐 wei 交叉核对吻合 |

> 说明：「验证耗时实测」里程碑要求的 bench-verify 复跑被 SIGKILL 阻断（§10.1），上表 bench-verify 数字来自 B 阶段那次成功实测（里程碑边界定义见 §10.1）；其余数字均为各阶段可复核的实跑输出/回执。
>
> **关于十余笔交易回执 gasUsed 全部 == gasLimit**：这是本环境 receipt 的普遍现象（est×1.1 留出的余量从未体现），说明 receipt 的 gasUsed 字段在 Monad 上**不反映执行消耗**——因此它不能反过来当「按 limit 计费」的证据；计费口径的唯一硬证据是 §7.4 的余额逐 wei 核对。同时注意：check_final_settlement.sh 对 **anchor** 交易把 gasUsed==gasLimit 设为硬 assert（:135），对 settle 交易则仅打印佐证（:67-69）；两脚本读回执字段均经 cast --json，而本工程曾修过一处 cast --json 十六进制归一化 bug（§6.4）——该门禁对字段归一化错误敏感，复核时应对 cast 版本与字段解析做独立确认。

---

## 6. 本地联调上锚（完成）

四步全通（来源：本地联调阶段证据 + `/tmp/monad-local-anchor.json` 撰写阶段读取核验）：

1. **本地栈**：`cargo build --release -p zchain -p poker-appchain -p monad-settlement`（1m21s）；zchain validator（pid 41745，RPC `127.0.0.1:18545` 新行分隔 TCP）懒出块，deploy-record tx 后 height=1；texas（:9001 dev bot）与 explorer_gateway（:18900）健康，chain_head 持续推进。
2. **probe**：`monad_settlementd --mode probe --l1-rpc https://testnet-rpc.monad.xyz --expected-chain-id 10143` → **7/7 PASS exit=0**：chain_id 10143；block_advance 66397995→66398009（+14/3s）；finalized=66398010；gas_price 102 gwei；fresh nonce=0；get_logs 空；tx_format_probe 资金闸门按预期拒绝。
   - **记录存疑**：finalized(66398010) 比同句 head(66398009) 还高 1，与「单槽延迟 3 块」（finalized 应落后 head 数块，Monad 单槽终结语义）矛盾——两值应非同一时刻采样（先后顺序未记录），或其中一笔抄录有误。阶段证据未给采样时序，**此项记录不可靠，仅 probe 整体 7/7 PASS 可信**。
3. **真实上锚**：写链前余额 1.4436 MON；读链 batchCount=5 校准 index=5；批次根取本地 appchain pipeline 真实结算回执（`op=569 proven=true root=0x05e13805…`）；`submitBatch(5, 0x05e13805…, 569)`：est 81990 → limit 90190（×1.1）、gasPrice 102 gwei → tx **`0x5b8687e9cb1dcfae325c95334e143d452bb46c4b375755b43a342076cf47722a`**，回执 status=0x1、block 66403685、gasUsed=90190（==limit）、cost 0.009199380 MON；finalized=66403777；链上复核 batchCount=6、`batches(5)` 与提交逐字节一致。
4. **产物**：`/tmp/monad-local-anchor.json` 已写；`scripts/check_local_anchor.sh` 全路径验证——真实锚 exit=0（cast status + curl 0x1 双通道 + to==L1Inbox + costWei 交叉核对），负路径 3 场景（JSON 缺失 / to 不符 / costWei 错值）各 exit=1。曾用 9-27 水龙头历史 tx（0x26527684…0e14fd，即测试网水龙头当时给 operator 转账的**既有链上交易**，无需发新 tx）做通道级验证——即只验证检查脚本的「读回执/比对字段」通道逻辑是否可靠——据此修了 cast --json 十六进制字段归一化 bug（**该 bug 的存在意味着所有经 cast --json 读取数值字段的门禁都需留意同类风险**）。

**关键踩坑**：

- 资金钥 `/tmp/monad_e2e_key.txt` 开局丢失（/tmp 被清）；撰写侧穷尽搜索（两仓、shell 历史、会话 artifacts+rollout）**无恢复材料**，而 `L1Inbox.authority()==0xbcD7…7aA6==operator` 且 `submitBatch` 为 onlyAuthority（`L1Inbox.sol:120-124`），换新钥无路 → escalate；**主 agent 具备重建材料，按原路重建钥文件**（600 权限），`cast wallet address` 验证派生地址==operator 后继续。钥值全程未进任何日志/JSON。
  - **安全口径注意**：能「原路重建」且派生地址精确复现，说明该钥**存在确定性的生成/派生来源**（与「无可恢复材料」不矛盾——材料存在但不在撰写侧可达范围）；其熵源（固定助记/脚本生成？）、重建材料保存在何处、如何轮换，阶段证据未说明，列 §11.2 安全口径待查项。
- `gateway /api/v1/batch_roots` 在 dev_poker_air 接线下恒空：嵌入式 texas runtime（`texas/src/starknet/appchain/runtime.rs:486` batch_size:1）不调 attach_proven_log，网关 `--proven-log` 数据源无从产生。本次改用 texas 结算回执里的真实 batch_root（同为 pipeline `mark_proven_through_with_root` 的根，仅暴露通道不同）。**建议后续给 runtime 挂 proven-log sidecar 或网关加 WAL 批次根投影**（此缺口在 stark 服务器与全链路阶段同样存在，见 §8.4、§9）。
- 本地链初始 height=null 是懒出块，非故障；RPC 偶发超时已带重试（`monad_hand_gas.rs:479` retry3）。

---

## 7. SNARK 合约部署与链上实测（完成，Monad 测试网）

来源：合约部署阶段证据 + `/tmp/monad-wrap-deploy.json`（撰写阶段读取核验；金额以 JSON 为准，阶段 prose 中 0.067007658 有笔误，JSON 实为 **0.067006758** MON）。

### 7.1 编译与出证样本

- `./build_solc.sh` → `build_solc: OK`；产物 `out/solc/Groth16Verifier.bin`（5034B）+ `SettleWrap.bin`（1912B）；`Groth16Verifier.sol:18-36` VK 常量与 `groth16-wrap/src/golden.rs` GOLDEN_VK_* 逐项一致（阶段比对）。
- 样本为金向量语句：`program_hash=0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4`、`hand_binding=0xa6aa`、`fact=0x030675cf10171e01d672af7b19fcbd51c0e5f88bc8f5932186cc581e297c0ea5`；`wrap-proof` 本地 verify 通过（1586µs）。
  - **金向量语句来源**（报告撰写阶段读 `groth16-wrap/src/golden.rs:1-19` 确认）：由 `gen-sol` 生成，= **固定种子 trusted setup + 真实形状的构造公开段**（GOLDEN_OUTPUT 为 16 felts，形状与真实 prove-hand 产物同形、字段值非特定真实手牌，如 output[2]=0x2a、output[5]=binding 0xa6aa）；program_hash 是真实钉扎值（settlement 电路哈希）；fact 由宿主 `witness.expected_fact()` 重算自证（golden.rs:52-57），非取自某笔真实牌局的 STARK 产物。

### 7.2 部署（EIP-155 legacy，est×1.1 紧 limit，节点价 102 gwei）

| 合约 | 地址 | deploy tx | block | est→limit | gasUsed | cost |
|------|------|-----------|-------|-----------|---------|------|
| Groth16Verifier | `0x91009ba349a6598d829b9ae3fdbe52e89a900eb0` | `0x3ca67765a8ac9bee60015a399177a09c3a5762ee4eb47c8e65e1d4048a8c025e` | 66407158 | 597208→656929 | 656929（==limit） | 0.067006758 MON |
| SettleWrap(verifier) | `0xc6f134ef25adb1037026ef39b70379ddda1958fd` | `0x7247233e9962e019929bc03d11f962b9d7b7b0fa43c72541e50b71584be9521e` | 66407260 | 236122→259735 | 259735（==limit） | 0.02649297 MON |

构造器正确接线 verifier 地址（`cast abi-encode constructor(address)`）。

### 7.3 链上实测（金向量样本 settle）

- settle tx **`0x92df2db3026ea38361b43e52e78d2beb0714c0d09947b23b0ac78f0bf56d6fb8`**（block 66408063，nonce 0x8c；est 1081783→limit 1189962 = ceil(est×1.1)，1189961.3→1189962 吻合）：status=0x1，gasUsed==limit，cost 0.121376124 MON；回执 log 与 `WrapSettled(uint256,uint256,uint256)` topic0=`0x7018a142f33c2f6224e87cb72ead7fe76e6f752f05a71d15129a812c106cbdc1` 匹配，topics/data 与证明公开输入逐字段一致；`cast call settledFact(uint256) 0xa6aa` 返回 ==fact；eth_call 探针 `verifyProof` 直接返回 `0x…01`。

### 7.4 账单口径与踩坑

- **账单口径实证**：operator 余额 1.434356790 → 1.219480938 MON，差额 0.214875852 MON == Σ(limit×price)（三笔）——**这是「Monad 按 gas_limit×price 计费（不是 used）」的判据本身**（余额扣减与 limit×price 逐 wei 吻合、与按 used 计费的结果不符）。三笔回执 gasUsed 全部 == gasLimit 是与此一致的现象（receipt gasUsed 不反映执行消耗），不单独作为证据。写链前后余额均 >0.5 MON，未触发 escalate。
- **cast 1.8.3 参数顺序坑**：`cast send --create <bin> --gas-limit …` 中 `--create` 后是 trailing var-arg，gas flags 全被吞；必须把 `--gas-limit/--gas-price/--chain-id/--private-key/--rpc-url` 放在 `--create` 之前。`deploy_wrap_monad.sh` 原有此 bug（第一次跑即暴露，未上链、余额未动），已修两处（83/97 行）并 bash -n 通过。
- **cast abi-encode 括号数组坑**：`[0x..,0x..]` 单 argv 传参产出无 32 字节填充的拼接串（352B、非 32 对齐）→ eth_call 必 revert；改用 Python 手工 ABI 编码（selector `cast keccak/sig`，正确 4+11×32=**356B**）。
- **合约注释矛盾（未擅改源码，留维护者决定）**：`SettleWrap.sol:39-40` doc 称参数 b 为 ark 顺序 `[[x.c0,x.c1],…]`，但 `settle()`（:49）直传 `verifier.verifyProof`，`Groth16Verifier.sol:31-33` 与 `groth16-wrap/src/lib.rs:125-129` 钉死 EVM 字序。eth_call 实测裁决：`settle(b_evm)` 成功、`settle(ark)` revert（返回 `0xb0f988e0`，BadProof 短 selector）。**链上以 b_evm 为准，SettleWrap doc 注释过时**；改源码会使已部署字节码与源码不符，故仅如实上报（撰写阶段核验：`:39-40` 该注释仍在盘）。
- 一次部署中途被环境重启中断：事后核对 latest==pending nonce=0x8a、余额未变，确认无悬空交易后才重新部署。**9-27 已部署栈（L1Inbox 0x60ec…/L1Outbox 0x1f3e…/L1Bridge 0x6728…）的合约代码、部署与配置未做任何改动；但确有向其 L1Inbox 提交的写链**（本任务两笔 submitBatch，index=5/6，见 §6.3、§9 ⑤；batchCount 由 3 增至 7）——「未触碰」仅指前者，不指零交易。
- 检查脚本 `scripts/check_wrap_onchain.sh`（set -euo pipefail，RPC 带重试）4 步全绿 exit=0：[1/4] verifyTx 回执 status=0x1 且 gasUsed==gasLimit；[2/4] WrapSettled 事件逐字段匹配；[3/4] cast call verifyProof（现场由 proofPath 重建 b_evm calldata，selector 0x11479fea）==true；[4/4] settledFact(handBinding)==fact。

---

## 8. stark 服务器部署（完成）

来源：服务器部署阶段证据（ssh stark 实跑；撰写阶段未登服务器）。

### 8.1 盘点与构建

- 实测 systemctl/docker/ss/df/free 与方案一致（在网 `texas.service`+`texas-test-guard.service`+nginx+docker；端口 22/80/443/1443/9001；磁盘起始余量 8.7G；服务器 rustup `nightly-2026-04-15` = 两仓 `rust-toolchain.toml` 钉版）。新增事实：服务器无 rsync（改 tar 管道）、GitHub SSH 无 key（zchain 的 ssh git 依赖命中既有 `/root/.cargo/git/db` 缓存离线解析）、`L1Inbox.aggregateCount=2`。
- 三构建全过：`cargo build --release -p zchain -p poker-appchain -p monad-settlement` → BUILD_ZCHAIN_OK（bin：zchain/explorer_gateway/monad_settlementd/appchain_watcher/rake_audit）；`cargo build --release -p texas` → BUILD_TEXAS_OK（`/opt/texas-monad/texas` 29,623,416B）；proving-tool 独立 workspace `-p prove-hand` → BUILD_PROVEHAND_OK（97,641,024B；临时装 nightly-2026-01-15 后已卸载回收 1.5G）。

### 8.2 部署单元（/etc/systemd/system/）

- `zchain-monad-node@.service`（实例 0–3；节点 env 分离 RPC 18645–18648 / P2P 19100–19103；LogRateLimit 30s×1000 防 2.8G 日志复刻）
- `texas-monad.service`（:1544；EnvironmentFile=/opt/texas-monad/texas.env；`TEXAS_APPCHAIN=1` + `STARKNET_SETTLEMENT_EXIT=appchain`）
- `explorer-gateway-monad.service`（:18950，--public，回放 `/opt/texas-monad/run/appchain/sequencer.wal`，--l1-rpc http://127.0.0.1:18645）
- `monad-settlementd-monad.service`（--mode all --expected-chain-id 10143 --inbox 0x60ec…0e71 --bridge 0x6728…96e6 --key-file run/keys/monad.key --state-file run/settlement-state.json --poll-interval-ms 8000）
  - **安全口径待查**：`run/keys/monad.key` 是哪把钥（与本任务 operator 资金钥 `0xbcD7…7aA6` 是否同钥）**未核实**；文件权限、所属、是否有 disk 加密/保管流程未记录。若是资金钥明文落盘服务器，属安全口径缺口（§11.2），需登录服务器核实派生地址与权限后再定。

目录新建 `/opt/zchain-monad/{src,bin,chain,poker_texas_air}`、`/opt/poker_texas_air-monad/{src,bin}`、`/opt/texas-monad/*`；未触碰 `/opt/texas{,-test}`、`/opt/zchain-4node`、`/opt/zchain-src`。

### 8.3 健康检查（实测输出）

四节点曾真实出块：RPC `get_block_count` 双采样 height 2695/2695/2695/2696；journal「✅ 出块成功(多签 4 票) height=781 … commit_round=781」；texas-monad curl :1544 → HTTP 200；gateway `/api/v1/status` → {env:devnet, data_source:replay, sequencer_public:f9f3eca3…}；settlementd journal「adapter connected: host=monad chain_id=10143」+「daemon started mode=all」无 fatal。批次根续接校准：链上 batchCount=6 / aggregateCount=2，state 文件预置 batch:0..5 + aggregate:0..1（Finalized 形态）→ 下一个批次 index=6 与合约严格连续纪律对齐（`L1Inbox.sol:125` index != batchCount revert）。
  - **aggregateCount 语义**（报告撰写阶段读 `L1Inbox.sol:43-48,63-64,131-146` 确认）：aggregate = **批次根的二级折叠根**（`submitAggregate(index, root, throughOp, batchCount_)`，index 同样必须 == aggregateCount 严格连续）。链上 aggregateCount=2 = 已存在 index 0、1 两笔聚合根；**由谁在何时提交不在本任务证据内**（早于本任务上锚，疑为 9-27 栈时期或 settlementd 更早期动作，无法复核）；state 预置 aggregate:0..1 的原因与 batch 相同——daemon 启动时必须与链上计数器对齐，否则下一个提交会撞 OutOfOrder revert。

探活脚本 `scripts/check_stark_deploy.sh` 实跑两轮 → **ALL_GATE_CHECKS_PASSED EXIT=0**。**13 项硬门禁逐项清单**（报告撰写阶段读脚本 `check_stark_deploy.sh:71-119` 实数）：①ssh-连通；②texas-monad active；③explorer-gateway-monad active；④monad-settlementd-monad active；⑤现网 texas.service 未受影响；⑥现网 texas-test-guard 未受影响；⑦现网 nginx 未受影响；⑧texas-monad :1544 HTTP 200；⑨gateway :18950 /api/v1/status；⑩settlementd journal「adapter connected」；⑪settlementd journal「无 fatal」；⑫settlement state 校准 = 链上 batchCount/aggregateCount；⑬磁盘已用 <95%。另有 5 个信息项（NODE-0..3 节点状态 + 归档在位）按运维决策**不计门禁**（脚本 :121-127）。

### 8.4 磁盘事故与授权处置

200ms 出块下 `node_*/vertices` RocksDB 实测净增 ~150MB/分钟（`pruning.rs` vertex_prune_after_blocks=10000 未封顶），93% 时将 20 分钟内写满盘威胁同盘生产 → **紧急 stop+disable 四节点止血（可逆）→ escalate 获决策（方案 3：结算链路即交付形态）→ 链数据归档** `/opt/zchain-monad/chain-archive-20260928.tar.zst`（428M，sha256 `0fa1c87b372bdc6cdd3c01a6d36bf69b0b90499ae023a9472fce5ad706783829`；三重验证：zstd -t OK、条目 279=279 与 du --inodes 一致、抽检 node_0/blocks/CURRENT=MANIFEST-000005 与 genesis_validators.json 可读）→ 删除 node_{0..3} RocksDB 目录（genesis/validator keys/env 保留）；磁盘 **95%→82%（7.0G 余量）**。

恢复路径（未执行，交接用）：扩盘后按 `/opt/zchain-4node/start4.sh:12` 的 500ms+ 间隔 `systemctl enable --now zchain-monad-node@0..3` + 90% 水位停链守卫，数据可从归档恢复。

> **归档体积 caveat（如实）**：磁盘 95%→82%、余量 7.0G → 推算释放 ≈5G 原始数据，而归档仅 428M（zstd）——压缩比 ~10x 对 RocksDB（块内高冗余、zstd）**可能**成立，但**原始 node_{0..3} 数据的 du 体积未记录**，无法坐实「全部被删数据均已入档」；「可从归档恢复」仅有三重验证（zstd -t / 条目数 / 抽检可读）支撑，**未做解包重建演练**，恢复可用性未经证实。交接方恢复前应先解包核对完整性与体积（§11.2）。

### 8.5 踩坑与移交口径

1. zchain 节点 RPC 是**换行分隔 JSON-RPC 裸 TCP** 协议（`explorer_gateway/l1.rs:4-7` 注明 HTTP 优先、newline 回落），健康检查必须用 python socket 而非 curl POST。
2. **Monad getLogs 100 块窗口限制**：DepositWatcher 水位只在成功后推进，停机/装配间隔 >100 块即 413 永久卡死——本次装配与启动间隔 17 分钟即触发，已停单元将 `deposit_next_block` 重置到 finalized-20 后恢复自持；后续重启 settlementd 前若停机超 ~50 秒需同样拨水位。
3. Monad 按 gas_limit×price 计费 → 合约 index 严格连续，settlementd 启动前必须按链上 batchCount/aggregateCount 预置 state（本次 6/2），state 内假锚用 `{tx:0x00×32, block:1, finalized:true}`。
4. `set -o pipefail` 下 `journalctl | grep -q` 因 SIGPIPE(141) 恒假阴性（start 阶段 90s 误报 FATAL 的根因），两处脚本已改为先整体捕获再 grep。
5. 服务器 SSH 对高频新建连接敏感（kex 阶段 reset）：上传走 md5 门控+退避重试、探活走 ControlMaster 多路复用。
6. poker_l1/fact-bridge 依赖兄弟仓 `../../poker_texas_air/fact-verify`，fact-verify 又依赖 `../third_party/proving` → 服务器按同构路径布局；zchain 另需自有 `third_party/{stwo-cairo,stwo-wasm-patch}`（首轮两度因缺目录失败，补齐后 BUILD_OK）。
7. **决策移交口径**：stark 侧交付形态 = texas-monad + explorer-gateway + monad-settlementd 三单元常驻；四节点停止为授权例外；终局 E2E 的 zchain 受理腿用本地 appchain 或 gateway 路径，勿为 E2E 重启 stark 四节点链。
8. gateway 当前 batch_roots 为空（fresh WAL 无 proven log），settlementd 轮询无写链动作、不耗 gas；首批 proven log 出现后按预置 index=6 续锚。
   - **与「前期上锚」的矛盾未解决**：本任务上锚前链上 batchCount 已达 6（本任务证据称「settlementd 前期上锚」所致），但当前装配的 gateway replay 配置 batch_roots 恒空、settlementd 无从取根——前期上锚走的是哪条数据源（更早的 gateway 配置？本地栈？）、哪几笔 tx、何时发生，均无记录（§9 踩坑 6、§11.2 待查项）。

---

## 9. 全链路结算演练（完成）

以一手真实牌局打通「本地出证 → zchain appchain → SNARK 包裹 → Monad 测试网结算」，明细落盘 `/tmp/monad-final-settlement.json`（撰写阶段读取核验，下表 tx/数值与之逐字段一致），`scripts/check_final_settlement.sh` 实跑 **5/5 OK**（set -e，退出码 0）。

| 步 | 内容 | 结果 |
|----|------|------|
| ① 真实牌局 | ssh stark 三单元（texas-monad :1544 / gateway :18950 / settlementd）全部 active；`/api/dev/bot` 注入两个 bot（0x…b01/0x…b02，bot2 需重注入 5 次才入座）真实对局 | handId **1790615020**、grossPot 200、rake 0、摊牌 bot-2 Three of a Kind 胜、nets[-100,+100]；结算回执 exit=appchain、proven=true、**settle_op_index=5**（appchain 结算管线的 op 下标，是结算回执字段，**非 submitBatch 的参数**）、batch_root=`0x01d3f5ed3b750f071747cc2bb6932d371d795cb8dbf21ac3ec5b19c40d07518a`、hand_binding(32B)=`0xd1cdb805a68c3131b5ffaa4c1db16960382e4ce41880681f761bb1e6cde35d12` |
| ② STARK 出证 | 桥接器 /tmp/hand_bridge（texas actions.rs 打包词/合法性词 + settlement_prover.rs digest 折叠）先经样例夹具逐 felt 对拍（`cargo run -- sample` → SAMPLE OK，98+15 felt 全一致）再出真实输入；`./proving-tool/prove-hand.sh --program proving-tool/src/settlement_private.cairo` | 4795 steps、prove 8.23s、verify 13ms OK；program_hash=`0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4`；公开段 16 felt（MAGIC/hand_id/digest/n=2/binding/total=100/action_digest）与桥接器期望逐 felt 一致 |
| ③ fact-verify | 独立工作区 CLI 实跑，program_hash 钉扎匹配 | **fact=`0x0110776cac5a62d9f2ecf3ebf744a4134c1d5cb3604e69807a7bea94dd5038b8`** |
| ④ Groth16 包裹 | `cargo run -p groth16-wrap --bin wrap-proof` → /tmp/final-e2e/wrap_proof.json | setup 45.5s / prove 31.8s / 本地 verify 1590µs 通过；语句 [program_hash, hand_binding(=电路 output[5]，归约 felt), fact] |
| ⑤ 上锚 | gateway replay 未挂 proven-log → settlementd 不自动上锚该批次根；`L1Inbox.authority()` 实查 == 带水 operator（术语：持有测试网水龙头余额、能付 gas 的 operator 地址），故由 operator 以 index=6 从 batchCount=6 续接 `submitBatch(6, 0x01d3f5ed…, 6)` | tx **`0x454f088e55940bf153d476c73abc4b0ab5ca064f9a92b2f88551a1d9c1c774fc`**，status=0x1，block **66463888**，BatchAnchored 事件（topic0 `0xfdbe3de9…ff48`），batchCount 复查=7 |
| ⑥ SettleWrap.settle | 由 wrap_proof.json 现场编码（b_evm calldata） | tx **`0xfa87877ac7a6fd903d346d612695b8c0a8d76ef013aed66e033b16d8d75a1941`**，status=0x1，block **66463997**；WrapSettled topic0=`0x7018a142…` 三值与包裹证明逐字段一致（programHash=`0x0744d16d…`、handBinding=`0x01cdb805a68c2f77b5ffaa4c1db16960382e4ce41880681f761bb1e6cde35cf8`、fact=`0x0110776cac…`）；`settledFact(handBinding)` 链上读回 ==fact |

**submitBatch 参数语义**（报告撰写阶段读 `L1Inbox.sol:37-41,120-129` 确认）：`submitBatch(uint64 index, bytes32 root, uint64 throughOp)`——index 必须 == 当前 batchCount（严格连续，乱序 revert）；root = 批次承诺；**throughOp = 批次覆盖的最大帧序号**（结构体注释原文）。因此 index=6 锚的第三参数 6 是该批次覆盖到的 WAL 帧号，与 ① 的 settle_op_index=5（appchain 结算 op 下标）**不同义**；index=5 锚（§6）的 throughOp=569 是本地管线帧号。二者与 throughOp 的精确换算关系（为何一个批次的帧号远小于另一批）取决于各实例的 WAL 帧起点，阶段证据未记录，不能相互推算。
| ⑦ 复核 | `check_final_settlement.sh` 实跑 | [1/5] settleTx status=0x1+to=SettleWrap+gasUsed==limit ✓；[2/5] WrapSettled 三值逐字段一致 ✓；[3/5] cast call verifyProof（现场重建 calldata 356B）==true ✓；[4/5] settledFact==fact ✓；[5/5] anchorTx status/to/BatchAnchored(index=6,root) ✓ → **check_final_settlement: OK** |

### 9.1 链上两条通道的耦合关系（报告撰写阶段读合约确认）

**上锚（L1Inbox.submitBatch）与结算登记（SettleWrap.settle）在合约层面完全无耦合**：

- `L1Inbox.sol` 全文（185 行）不引用 SettleWrap，`SettleWrap.sol` 也不读 L1Inbox；`settle()`（`SettleWrap.sol:43-56`）只做 verifyProof + settledFact 幂等检查 + 登记 + 事件，**不校验任何批次根**。
- `settledFact(handBinding)` 登记后**当前无链上消费方**：SettleWrap 合约内无读取逻辑（仅 public getter），9-27 栈的 L1Outbox/L1Bridge 与本合约互不相识、不消费该映射。即 settle 的语义是**登记/背书**（任何人可凭事件与 getter 核对「该 binding 已结算为该 fact」），后续若要据此放款/提现，需二期新增消费合约。
- 因此 §9 流程图的「包裹→上锚→settle」是**执行顺序**（先有批次根锚、再有 fact 登记的运营顺序），**不是链上依赖**：即使不锚批次根，只要有人提交合法包裹证明，settle 也能独立成功。

**gas 纪律与资金**：两笔均按 est(eth_estimateGas)×1.1 紧 limit + 节点建议价 102 gwei 发送；anchor cost 0.009197952 MON + settle cost 0.121415496 MON = **0.130613448 MON**；operator 余额 1.219480938 → 1.08886749 MON（>1 MON）。计费判据为余额逐 wei 核对（同 §7.4）。
> **记录矛盾（待复核）**：明细记录 settle **est 1081783 → limit 1190348**——但 1081783×1.1≈1189961.3，ceil 应为 1189962（§7.3 金向量 settle 正是该值）；两次 est 相同而 limit 相差 386，与自述 ×1.1 规则不符。可能是 stage 转录把另一 est 值误记为 1081783，或 limit 有未说明的额外加成。无法事后重测（同 calldata 的 settle 现已 revert AlreadySettled），calldata 留档在 `/tmp/final-e2e/settle_calldata.txt` 可供复核；本报告以链上回执 gasLimit=1190348（gasUsed==limit）为准，est 来源存疑。

**踩坑与口径（全部如实）**：

1. **hand_binding 超 felt252 与三个形态**（三者关系，报告撰写阶段据明细 JSON 与检查脚本复核）：
   - appchain 回执的 32B 域摘要 `0xd1cdb805…5d12`：非 canonical felt（≥P）；
   - 归约 felt `0x1cdb805a…5cf8`（63 位十六进制）：按 starknet-types-core `from_bytes_be` 语义 mod P 归约（python 独立复算一致），= 电路公开段 output[5] 的值，即包裹证明公开输入 hand_binding；
   - 链上 WrapSettled 事件/settledFact 键值 `0x01cdb805a68c2f77…5cf8`（64 位）：**与归约 felt 是同一个数**——事件 topic 固定 32 字节，检查脚本以 `pad(x)=rjust(64,'0')` 比对（`check_wrap_onchain.sh:73`、`check_final_settlement.sh:78`），0x1cdb805a… 左补零即 0x01cdb805…，两处字面不同只是填充写法差异。
   - 因此**链上实际登记的 handBinding 是归约 felt 的 uint256 形态**；原 32B 形态仅存在于 appchain 回执/网关 settlement API 通道，未上链。阶段证据原文「链上 uint256 侧仍用原 32B 语义」按链上实况应修正为上述口径。
   - **「反拼装绑定」释义**（`groth16-wrap/src/wrap_circuit.rs:19-20` 注释原文口径）：output[5] 的哈希槽位变量与公开输入 hand_binding 做位级等价约束——公开输入在 Fr 轨、见证 output 在 Fp252(felt) 轨，「P/G 两轨同 binding」（见 src/hand_binding.rs），保证包裹证明同时把 binding 提交进 fact 哈希与公开输入，二者不能不一致。
2. **桥接器两处对拍纠错**：digest 链是 8 槽全量折叠（电路 `while i<N_PLAYERS` 与根 crate `settlement_digest_fields` 的 zip 语义），不是 build_request 的实际人数折叠（texas 服务端该函数与电路在 n<8 时存在口径分歧，本次按电路/样例夹具口径走，SAMPLE OK 为证）；零槽 sign=1（d≥0→1）。
3. 真实手 statement 的 payout commitments 全零：嵌入式 appchain PLAY 模式无 vault payout commitment（dual/starknet 遗留路径的链上查询），赢家 cm=poseidon(0,binding,m,0)，隐私盐为开发口径，已在 JSON 注明。
4. settlementd 不会自动上锚本手批次根：explorer-gateway-monad 单元未带 `--proven-log/--proof-registry`，replay 出的 batch_roots 恒为空（batchCount 长期停在 6 的原因）；authority 即带水 operator，故手动续接 index=6，未动任何既有单元。
   - **未解矛盾**：batchCount 3→6 的增量归因「settlementd 前期上锚」，但按当前 gateway 配置 batch_roots 恒空、settlementd 无从取根——「前期」的数据源、时段、tx 清单（batch 0–4 及聚合 0–1 的提交者）均无记录，与「恒空」并存无法自洽，列 §11.2 待查。本任务可复核的锚 tx 仅 index=5（§6）与 index=6（本节）两笔。
5. stark 上 bot2 首次注入因 DLEQ c1 mismatch 失败（与上次演练 47 次重注入同源），重试 5 次成功；打完一手后 bot 空转、WAL 仅 2524 字节，未对在网单元做任何停止/删除。
6. batchCount 在 ask 编写时为 3、开跑实测已到 6（settlementd 前期上锚），按「从当前值续接」以 6 续接，事件与 batchCount=7 复查为证。
7. 公共 RPC 偶发超时，所有写链前读数（estimate/gasPrice/nonce/receipt）均带 6 次重试。
8. 未做的事：未跑 `scripts/play_hands.sh` 本体（其要求完整 devnet+钱包栈；stark 演练实例的 dev-bot 路径即其等价模式，一手牌局为真实对局非预置夹具）；未在 L1Outbox/Bridge 上做新交易——「不在 ask 五步内」指该 stage 的 ask 验收范围为五个步骤（其原文不在本报告掌握中，此处仅转述 stage 证据结论），与本报告 §9 的 ①–⑦ 编号无关。

---

## 10. 受阻项

### 10.1 验证耗时实测（bench-verify 复跑）— 受阻

- 命令：`cargo run --release -p groth16-wrap --bin bench-verify`。重试仍失败：编译完成（`Finished release profile [optimized] target(s) in 0.67s`，期间有 cargo 对 git checkout 内重复包的警告——`wallet-app/vendor/poker-settlement-core/Cargo.toml` in favor of `/Users/mac/.cargo/git/checkouts/zchain-7cee904ce59002d5/16049e2/poker-settlement-core/Cargo.toml`）后，运行阶段即被杀：`bash: line 1: 66904 Killed: 9`。
- **本机资源基线（报告撰写阶段实测）**：`sysctl hw.memsize` = 38,654,705,664（**物理 36GB**）；`sysctl vm.swapusage` = total **4096M**（与 stage 记录「swap 封顶 4GB」吻合；实测时 used 2671.69M）。
- **归因定性**：K=8 SIGKILL(137) 与本次 bench-verify 被杀**归因「内存不足」属推断而非实测**——无 OOM 日志/监控引用（stage 证据明确「无 crash report」）；且 RSS 采样 ≤8.4GB 远小于 36GB 物理内存，简单的「物理内存耗尽 OOM」假设并不充分（更可能是瞬时分配峰值、进程组内存压力或其它系统占用，未逐项排除）。可确证的事实只有：SIGKILL 复现 3 次、与内存/swap 相关的环境调整（daemon 化、RAYON_NUM_THREADS=1）不改变结局。未在本机完成复跑。
- **里程碑边界定义**：B 阶段 bench-verify 的单次成功是 **B 门禁自测的产物**（其数字被 §5 采信为参考）；本里程碑的状态「受阻」依据是 stage 对同一命令的**复跑重试仍失败**——即单次数据的**可复现性未验证**。stage 证据未定义「全量复跑」应含哪些用例/规模，本报告无法给出该验收口径的原始定义。
- **补偿性事实**：B 阶段 bench-verify 曾成功跑过一次，实测数字（stark_verify_ms=24、constraints=4,584,665、setup ≈46–55s、prove 31,875ms、verify 1.547ms、batch K=2 prove 69.8s/verify 1.6ms）已留存于 §5；全链路 ④ 复跑亦独立得到 setup 45.5s/prove 31.8s/verify 1590µs。
- 处置建议：在更大内存/swap 机器上复跑 `bench-verify`；C 阶段 K=8+ 的聚合 setup 同理（§4）。

### 10.1 复跑结案附注（2026-10-02，同机同口径）

- **复跑成功，可复现性成立（本受阻项关闭）**：修正入口死因后全流程跑通——前段 fact-verify 对真实 12.2MB 证明 `runs_ms=[38,25,25]` → **25ms**（B 阶段 24ms，一致）；单手包裹（金向量形状，wrap-proof 独立跑）`setup 52,774ms / prove 36,611ms / verify 1,592µs`（B 阶段 46–55s / 31,875ms / 1.547ms；全链路 ④ 45.5s / 31.8s / 1590µs——三组噪声内一致）。**峰值 RSS 14.3GB 实测**（单手 4.58M 约束，首次硬数字——「RSS 采样 ≤8.4GB」的旧采样偏低）。
- **真实死因修正**：复跑在重型阶段之前即以**明确错误**退出，非 SIGKILL——bench 硬编码金常量 `GOLDEN_PROGRAM_HASH`（旧电路 `0x744d16d3…`）为 expect 钉扎与语句派生源，而盘上 proof.json（2026-09-30 22:19 重出证）为 9 席迁移后产物（`0xee3b4c4e…`）→ `program hash mismatch`。已修复：期望哈希改从 `public_outputs.json` 取（bench_verify.rs 随本附注提交）。K=8 的 SIGKILL(137) 归因（内存，推断）维持原样——两条失败链不应混同。
- **新发现（wrap 电路形状漂移，wrap 所有者跟随债）**：盘上真实 prove-hand 产物公开段已是 **17 felts**，wrap 电路 `WrapWitness::validate` 仍按 `OUTPUT_LEN=16`（长度前缀 15）——**当前 wrap 电路无法包裹迁移后真实产物**；M4/M5 接真实语料前需完成 wrap 电路 16→17 跟随迁移（含 HAND_BINDING_INDEX 位移与约束数重测）。本附注的包裹耗时均为金向量形状（16 felts）口径。
- 量化对照（用本附注与 §5 数据算得的「包裹换来了什么」，口径齐注）：① 可验证性：直接合约验 AIR = **24.7B L2 n/证明**（cairo-bridge-poc 实测折算，超单笔上界 ~3 个数量级 NO-GO）→ 包裹后 verifyProof **216,346 gas（EVM 规范）/ 1,049,894（Monad 实网）**，settle 全流程 1.19M gas——从不可行到可行；② calldata：STARK 证明 12,095,324B → verifyProof calldata 356B ≈ **34,000×** 压缩；③ host 验证：fact-verify 24–25ms → 本地 verify 1.55–1.59ms ≈ **15×**；④ 代价（证明侧）：包裹 prove 31.9–36.6s/手 vs STARK 单手 8.23s（**4–4.5×**）/ K=64 摊销 0.81s（**~45×**）+ setup 46–55s/电路版本 + 峰值 14.3GB——**包裹不加速证明，它把「链上无法验证」变成「~0.12 MON/手 settle」**（1.19M gas × 102 gwei 实测价）。

### 10.2 前端 Monad 钱包 — 受阻

- 3 轮未过构建/测试门禁（阶段证据原文仅此一句；无命令、无错误输出、无失败环节——构建还是测试均未记录）。**该受阻结论本身不可独立核验**，仅能证实 stage 自述如此。
- 代码在盘状态（报告撰写阶段实跑 `git status --porcelain` 核验）：`client/src/starknet/evmKeccak.ts`、`monadSettlement.ts`、`monadWallet.ts` 及对应 `.test.ts` 为 **A（已暂存新增）**；`client/src/components/auth/LoginModal.tsx`、`client/src/context/auth/authContext.tsx`、`client/src/hooks/useAuth.ts` 为 **M（已暂存修改）**。注：本会话起始快照中这些文件为 `??`（未跟踪）——两个快照时间点不同，期间文件被 `git add` 过；以撰写阶段实跑的 A/M 为准。即：**代码已暂存，但 stage 自述未通过门禁**，不得视为交付完成。

---

## 11. 信任边界与遗留问题

### 11.1 信任边界（已写入合约 NatSpec / lib.rs，撰写阶段核验 `SettleWrap.sol:13-20`）

1. **Trusted setup**：Groth16 需 per-circuit setup；本期为固定种子单方仪式（本地 rand URS），测试网口径可接受；**主网必须换 MPC powers-of-tau ceremony 并重新部署 verifier**。
2. **不验证 STARK**：链上命题仅为「fact 是 program_hash‖output 的 Poseidon 像且 output 形状合法（长度前缀 15 + 'SP2M_OK'）、output[5]==hand_binding」这一 **hash 一致性**，NOT「存在合法 STARK 证明」。STARK 真伪由链下 fact-verify（`fact-verify/src/lib.rs:89-106` stwo verify_cairo + `:113-126` 程序哈希钉扎）与 zchain 运营方把关；**被攻破的 operator 可包装任意格式良好的伪造 output 上链**。
3. **operator 背书语义**：Monad 上体现的是「operator 背书 + 电路一致」，非去信任事实。去信任化（STARK verifier 上链或递归聚合）按量级估算（§2.2）列为二期。

### 11.2 遗留问题清单

| # | 问题 | 状态/去向 |
|---|------|-----------|
| 1 | Monad 测试网真实部署 | 已在合约部署阶段闭环（§7）；`deploy_wrap_monad.sh` 的 cast 参数顺序 bug 已修（83/97 行） |
| 2 | 方案『预计文件』中 `client/src/starknet/*.ts`、`deploy/*.service`、`monad_e2e.sh`、`deploy_zchain_monad.sh`、`monad-settlement/src/abi.rs` 扩展 | 不在要求 1-5 内未实现（`HandWrapSettlement.sol` 按要求命名 `SettleWrap.sol`）；其中 client/src/starknet/* 已产出但受阻于门禁（§10.2）；`deploy/*.service` 以服务器阶段手装 systemd 单元替代（§8.2） |
| 3 | 性能优化 | 二期：ark 0.6 emulated eager-mul 使单手 4.58M 约束（实测），用 mul_without_reduce 批量归约可再降数倍；STARK verifier 上链/递归聚合按 §2.2 列二期 |
| 4 | fact-verify 以子进程 CLI 复用而非 cargo 依赖 | 有意为之：嵌套 workspace 会把 third_party/proving 的 edition.workspace 继承错误解析到本仓根（实测 cargo 报错），且其 Cargo.toml 自述刻意独立于根 workspace |
| 5 | `SettleWrap.sol:39-40` doc 注释过时（ark 字序 vs 链上实测 b_evm） | 未改源码（改了会与已部署字节码不符），留维护者决定（§7.4） |
| 6 | zchain 仓 `docs/test-records/2026-09-27-*.md` 有非本任务的既有未提交改动 | 未触碰 |
| 7 | stark 四节点停止（磁盘处置） | 授权例外；恢复路径已交接未执行（§8.4）；服务器磁盘 82%，需扩盘 |
| 8 | gateway proven-log 缺口（batch_roots 恒空 → settlementd 不自动上锚） | 三处证据一致复现（§6.3/§8.5/§9.4）；建议 runtime 挂 proven-log sidecar 或网关加 WAL 批次根投影；过渡口径为 operator 手动按链上 batchCount 续接 |
| 9 | settlementd 停机 >100 块 getLogs 413 卡死 | 重启前需拨 `deposit_next_block` 水位（§8.5.2） |
| 10 | 本机资源墙：K=8 setup SIGKILL、bench-verify 复跑被杀 | §4、§10.1；归因「内存不足」属推断（无 OOM 日志，RSS≤8.4GB < 物理 36GB，简单 OOM 假设不充分）；需更大内存机器复跑 |
| 11 | 9-27 已部署栈（L1Inbox/L1Outbox/L1Bridge）与 `texas.service` 等在网单元 | 合约代码/部署/配置未改动，均 active；但本任务向 L1Inbox 有两笔写链（index=5/6，§7.4 口径说明） |
| 12 | **texas 服务端与电路的 digest 口径分歧（n<8）**：`build_request` 的实际人数折叠 vs 电路/样例夹具的 8 槽全量折叠 | **正确性相关**，全链路按电路/样例夹具口径走（SAMPLE OK，§9 踩坑 2）；以谁为准、何时修无去向，此前遗漏于本清单，现补录 |
| 13 | 全链路 settle 的 est/limit 记录矛盾（est 1081783 vs limit 1190348，≠×1.1，差 386） | §9.1；无法事后重测（settle 已 revert），calldata 在盘可复核；est 来源存疑 |
| 14 | batchCount 3→6 的「前期上锚」数据源、时段、tx 清单（batch 0–4）及聚合 0–1 提交者均无记录；与 gateway batch_roots 恒空并存 | §8.5.8、§9 踩坑 4/6；待运维侧查 settlementd 历史 journal 与链上事件倒查 |
| 15 | probe 的 finalized(66398010) > head(66398009) 与「单槽延迟 3 块」矛盾 | §6.2；采样时序未记录，该数值不可靠 |
| 16 | stark_verify_ms=24 口径（是否含 12.2MB JSON 解析）及与 STWO verify 13ms 的关系 | §5 表注；未说明 |
| 17 | 归档恢复可用性：原始 RocksDB 体积未记录（释放 ≈5G vs 归档 428M），未做解包重建演练 | §8.4 caveat；恢复前先解包核对 |
| 18 | 服务器 settlementd `run/keys/monad.key` 钥身份/权限未核实（是否与 operator 资金钥同钥） | §8.2；若为资金钥明文落盘属安全缺口 |
| 19 | 资金钥存在确定性生成来源（可「原路重建」且派生地址复现），熵源与保管流程未说明 | §6 踩坑；建议补钥管理口径并轮换 |
| 20 | 证据/复现材料有效期：桥接器 `/tmp/hand_bridge` 未入库（其输入输出规格、98+15 felt 与 digest 折叠公式在报告外无文档）；三份明细 JSON、`/tmp/final-e2e/*`、`/tmp/wrap_{input,proof}.json`、`/tmp/settlement-prove` 均在 /tmp——本报告自身记录过 /tmp 被清史（§6） | 撰写时点在盘（`ls` 核验，附录 B）；建议将 hand_bridge、明细 JSON、金向量输入尽快复制入库或至持久目录 |

---

## 12. 复现命令

```bash
# ============ 门禁（B/C，阶段实跑 exit 0） ============
cargo test -p groth16-wrap                                   # lib 16/16 + roundtrip 6/6
cd /Users/mac/projects/zchain/contracts/monad && forge test  # 21/21 (+ C 阶段 batch 用例)
./build_solc.sh                                              # build_solc: OK

# ============ 出证 ============
# 单手包裹（金向量样本 /tmp/wrap_input.json 由脚本从 golden.rs 提取）
./target/release/wrap-proof /tmp/wrap_input.json --out /tmp/wrap_proof.json
# STARK 出证（全链路 ②）
./proving-tool/prove-hand.sh --program proving-tool/src/settlement_private.cairo
# 桥接器样例夹具对拍
cd /tmp/hand_bridge && cargo run -- sample    # → SAMPLE OK

# ============ 基准（注意：本机复跑被 SIGKILL，见 §10.1） ============
cargo run --release -p groth16-wrap --bin bench-verify

# ============ 本地栈 probe ============
monad_settlementd --mode probe --l1-rpc https://testnet-rpc.monad.xyz --expected-chain-id 10143

# ============ 部署（已实跑，含已修的 cast 参数顺序） ============
bash scripts/deploy_wrap_monad.sh

# ============ 四个检查脚本（阶段实跑 exit 0） ============
bash scripts/check_local_anchor.sh        # /tmp/monad-local-anchor.json
bash scripts/check_wrap_onchain.sh        # /tmp/monad-wrap-deploy.json
bash scripts/check_stark_deploy.sh        # ssh stark（四单元/state/磁盘门禁）
bash scripts/check_final_settlement.sh    # /tmp/monad-final-settlement.json，5/5 OK

# ============ 链上抽查（Monad Testnet, chain 10143） ============
# （cast 不在默认 PATH，用全路径；脚本内同此）
/Users/mac/.foundry/bin/cast call 0xc6f134ef25adb1037026ef39b70379ddda1958fd \
  "settledFact(uint256)(uint256)" 0xa6aa --rpc-url https://testnet-rpc.monad.xyz
# 金向量样本 → 0x030675cf10171e01d672af7b19fcbd51c0e5f88bc8f5932186cc581e297c0ea5

# verifyProof 实网 gas 复测（用全链路 settle calldata 换 verifyProof selector，
# 报告撰写阶段实跑结果 = 1049894）：
SEL=$(/Users/mac/.foundry/bin/cast sig 'verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[3])')
BODY=$(python3 -c "d=open('/tmp/final-e2e/settle_calldata.txt').read().strip();d=d if d.startswith('0x') else '0x'+d;print(d[10:])")
/Users/mac/.foundry/bin/cast estimate 0x91009ba349a6598d829b9ae3fdbe52e89a900eb0 "$SEL$BODY" --rpc-url https://testnet-rpc.monad.xyz

# 本机资源基线（§10.1）
sysctl hw.memsize vm.swapusage
```

---

## 附录 A：地址与交易总表（Monad Testnet, chainId 10143, RPC https://testnet-rpc.monad.xyz）

| 类别 | 值 |
|------|-----|
| operator | `0xbcd7ecd68d55ca2536f3f50dcbcb44edb0d97aa6` |
| L1Inbox / L1Outbox / L1Bridge（9-27 既有栈，未触碰） | `0x60ecddd1359356a43a69de84a1cf235a69a30e71` / `0x1f3e8b42e5f31f276952ce627d1eeffec8c6ae3b` / `0x6728873828dd281d274542eb3e6ba7438c0b96e6` |
| Groth16Verifier（本期部署） | `0x91009ba349a6598d829b9ae3fdbe52e89a900eb0` |
| SettleWrap（本期部署） | `0xc6f134ef25adb1037026ef39b70379ddda1958fd` |
| 部署 tx | verifier `0x3ca67765…8c025e`（blk 66407158）；settleWrap `0x7247233e…9521e`（blk 66407260） |
| 合约部署 settle tx（金向量样本） | `0x92df2db3…6d6fb8`（blk 66408063，gasUsed 1189962） |
| 本地联调上锚 tx（index=5, root 0x05e13805…） | `0x5b8687e9…47722a`（blk 66403685，gasUsed 90190） |
| 全链路上锚 tx（index=6, root 0x01d3f5ed…） | `0x454f088e…c774fc`（blk 66463888，gasUsed 90176，BatchAnchored） |
| 全链路 settle tx（真实手） | `0xfa87877a…a1941`（blk 66463997，gasUsed 1190348，WrapSettled） |
| WrapSettled topic0 | `0x7018a142f33c2f6224e87cb72ead7fe76e6f752f05a71d15129a812c106cbdc1` |
| BatchAnchored topic0 | `0xfdbe3de9a44396bb3ab8a6384d4d1c800968e59edb52369bc27f88b93d98ff48` |
| 全链路语句三元组 | programHash `0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4`；handBinding 32B `0xd1cdb805…5d12` / 归约 felt `0x1cdb805a…5cf8`（链上登记与事件呈其 64 位补零形态 `0x01cdb805…5cf8`，同一数，见 §9 踩坑 1）；fact `0x0110776cac5a62d9f2ecf3ebf744a4134c1d5cb3604e69807a7bea94dd5038b8` |
| 金向量语句三元组（部署样本） | programHash 同上；handBinding `0xa6aa`；fact `0x030675cf10171e01d672af7b19fcbd51c0e5f88bc8f5932186cc581e297c0ea5` |

> **batchCount 3→7 演进的已知/未知**：已知可复核的锚 tx 仅 index=5（`0x5b8687e9…`，本地联调，root `0x05e13805…`，throughOp 569）与 index=6（`0x454f088e…`，全链路，root `0x01d3f5ed…`，throughOp 6）两笔；**batch 0–4 的锚定者与 tx 无清单**（仅 stage 归因「settlementd 前期上锚」，时段与数据源未记录，§11.2 待查 14）；aggregate 0–1 同。

## 附录 B：报告撰写阶段的在盘核验与实测（两轮：初稿轮 + 复审修正轮）

初稿轮：

- `mkdir -p /Users/mac/projects/poker_texas_air/out`（已建）。
- `ls` 核验存在：`/tmp/monad-local-anchor.json`、`/tmp/monad-wrap-deploy.json`、`/tmp/monad-final-settlement.json`；`scripts/{check_final_settlement,check_local_anchor,check_stark_deploy,check_wrap_onchain,deploy_wrap_monad}.sh`；`groth16-wrap/src/{lib,felt,poseidon,poseidon_circuit,wrap_circuit,batch,batch_circuit,golden}.rs`、`src/bin/{wrap_proof,bench_verify,gen_sol,gen_sol_batch}.rs`、`tests/roundtrip.rs`；zchain `contracts/monad/src/{Groth16Verifier,Groth16VerifierBatch,SettleWrap,SettleBatch,AuthorityOwnable,L1Inbox,L1Outbox,L1Bridge}.sol` 与 `test/{WrapGoldenVector,WrapSettle.t,WrapBatchGolden,WrapBatchSettle.t}.sol` 等；另核 `/tmp/final-e2e/`（含 `settle_calldata.txt` 714B）、`/tmp/hand_bridge`、`/tmp/settlement-prove`、`/tmp/wrap_{input,proof}.json` 均在盘（mtime 2026-09-28/29）。
- 读取核验：三份 JSON 全文（§5/§6/§7/§9 数值以其为准，修正了阶段 prose 中 0.067006758 的笔误）；`groth16-wrap/src/lib.rs:119-149`（b_evm=EIP-197 Fp2 虚部在前，注释与代码一致）；`SettleWrap.sol:1-57`（:13-20 信任边界 NatSpec、:24-27 settledFact/事件、:39-40 过时 ark 字序注释、:49 直传 verifyProof）。

复审修正轮（针对独立复审 31 条，新增实测/实读）：

- `git status --porcelain` 实跑：client/src/starknet/*.ts、groth16-wrap/*、scripts/*.sh 均为 **A（已暂存）**，LoginModal/authContext/useAuth 为 **M**——修正 §10.2 与 §1 表（会话起始快照为 `??`，两快照时间点不同）。
- `sysctl hw.memsize` = 38,654,705,664（物理 36GB）、`sysctl vm.swapusage` total=4096M（used 2671.69M）——补 §10.1 资源基线。
- **实跑 `cast estimate`（verifyProof，全链路 calldata 换 selector 0x11479fea，356B）= 1049894**——解出 216,346 vs 1.19M 差额（Monad 预编译计价 ≠ EVM 规范），写进 §0/§5。
- 通读 `L1Inbox.sol`（185 行）：submitBatch 参数语义（throughOp=批次覆盖最大帧序号）、index 严格连续、aggregate=批次根二级折叠、与 SettleWrap 无耦合——支撑 §9.1/§8.3。
- 通读 `scripts/check_stark_deploy.sh`：实数硬门禁 **13 项**（ssh-连通 1 + 单元 3 + 现网 3 + texas HTTP 1 + gateway 1 + journal 2 + state 校准 1 + 磁盘 1），NODE-* 5 项为信息项——修正 §8.3。
- 通读 `scripts/check_wrap_onchain.sh` / `check_final_settlement.sh`：settle 侧 gasUsed==gasLimit **仅打印**（check_wrap_onchain.sh:56-63、check_final_settlement.sh:62-69），**anchor 侧为硬 assert**（check_final_settlement.sh:135）；事件比对 pad()（:73/:78）证实 0x01cdb805… 与 0x1cdb805a… 同数——修正 §5 注/§9 踩坑 1。
- 静态计数（`grep -c '#\[test\]'` / `grep -c 'function test'`）：rust src 19 + roundtrip 6；forge L1Settlement 16 + WrapSettle 5 + WrapBatchSettle 7=28——补 §3.4/§4 规模参照（静态≠运行通过）。
- 读 `golden.rs:1-19,52-57`（金向量=固定种子 setup+真实形状构造公开段，fact 宿主重算自证）；grep `wrap_circuit.rs:5-29`（反拼装绑定=P/G 两轨位绑定）——补 §7.1/§9 踩坑 1。

未在撰写阶段执行：cargo/forge 门禁、wrap-proof、bench-verify、forge/probe、ssh——均按阶段证据转述并已逐处标注来源。

## 附录 C：术语表（按复审要求补）

| 术语 | 含义 |
|------|------|
| 带水 operator | 指地址 `0xbcD7…7aA6`（L1Inbox.authority()）持有测试网水龙头发放的余额、有 gas 可付；「带水」= 有资金水（faucet-funded） |
| 反拼装绑定 | 电路约束：公开输入 hand_binding（Fr 轨）与见证 output[5]（Fp252/felt 轨）位级等价（P/G 两轨同 binding，`wrap_circuit.rs:19-20`、src/hand_binding.rs）；保证 binding 同时提交进 fact 哈希预映像与公开输入 |
| 单槽延迟 | Monad 单槽终结（MonadBFT）：一个 slot 内即 final；finalized 块号相对 head 的落后量即「延迟」。§6.2 中 probe 记录的两数关系存疑 |
| 水龙头历史 tx 通道级验证 | 用 9-27 水龙头给 operator 转账的既有链上交易（不发新 tx）检验检查脚本「读回执→比对字段」通道本身的可靠性，曾据此发现并修复 cast --json 十六进制归一化 bug |
| throughOp | L1Inbox.Batch 结构体字段：「批次覆盖的最大帧序号」（L2 侧 WAL/帧号），`L1Inbox.sol:39` |
| settle_op_index | appchain 结算回执字段：该手结算在结算管线中的 op 下标（与 throughOp 不同义、不同源） |
| P/G 两轨 | 电路里同一业务值在两个域的表示轨：P=felt252(Fp252) 轨、G=Groth16 标量域 Fr 轨 |
| aggregate / aggregateCount | aggregate = 批次根的二级折叠根（submitAggregate 提交）；aggregateCount = 链上已提交聚合数（= 下一个期望 index），`L1Inbox.sol:131-146` |
| trusted setup（单方仪式） | Groth16 每电路一次的参数生成；本期用固定种子的单方 URS 生成，非多方 MPC ceremony，仅测试网口径 |
