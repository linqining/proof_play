> ⚠️ **历史存档(2026-09-05 归档)**:仓库迁移蓝图(P0-P6)已全部执行完毕。
> 仍存续的收尾项(主网交易 / strk20.json / demo 视频)由 `docs/TODO.md` §五接管;
> 部署权威见 `poker_contracts/DEPLOYMENTS.md`。

# STRK20 黑客松提交仓库整合执行计划（zgame → poker_texas_air）

> 目标：把 `/Users/mac/projects/zgame` 中**实际使用**的代码复制到 `/Users/mac/projects/poker_texas_air`，使后者成为自包含、可独立构建、可直接提交 STRK20 Private Sprint（RFP-03 Poker）的仓库。
> 本文档本身不迁移任何代码，只是执行蓝图。执行时按 Phase 0 → 6 顺序推进，每个 Phase 一次或多次独立 commit（服务于 "Build in public" 评审项）。

---

## 0. 背景

### 0.1 黑客松要求（来自 strk20.starknet.io/hackathon）

**Four steps（四个步骤）**

| # | 步骤 | 说明 |
|---|------|------|
| 1 | **Apply** | 填写报名表，选择一个 RFP（本项选 **RFP-03**）或自带 idea |
| 2 | **Build in public** | 公开 GitHub 仓库开发，每个 sprint 在社区论坛发周报 check-in 帖 |
| 3 | **Ship to mainnet** | 必须在 Starknet **主网**完成至少一笔 STRK20 交易（不必是完整游戏，deposit + withdraw 即可） |
| 4 | **Nothing to submit** | 无需单独提交材料：截止时扫描仓库与 `strk20.json` manifest |

**Four criteria（四项评审标准，合计 100%）**

| 权重 | 标准 | 本计划的对应动作 |
|------|------|------------------|
| 30% | **STRK20 integration depth** | PokerVault 1:1 STRK20 筹码、买入/结算走隐私池、主网至少一笔 STRK20 交易（§7） |
| 30% | **Working mainnet product** | server + client + 合约在 sepolia 可跑通 → 主网最小路径（§6 部署指导） |
| 25% | **Innovation** | Mental poker V2（无受信 dealer，超出 RFP-03 建议的最简 trusted-dealer 版本）、Lean 4 形式化 reconstruction V3、P/G 双证明体系（§4） |
| 15% | **Documentation & open-source quality** | 双语 README、快速启动指南、LICENSE/NOTICE、CI（§2 §5 §6） |

### 0.2 RFP-03《Provably fair poker where cheating is mathematically impossible》要点

- **Mental poker 协议**：洗牌/发牌无可信方，每步可验证（未用牌不泄漏任何信息）。
- **STARK**：dealer 每条街证明（shuffled range / hand strength / terminal legality）。RFP 原文明确：**"STARK verifier (the L2 doesn't need to be on mainnet yet — the RFP explicitly asks for it 'eventually')"** —— STARK 验证器暂不要求上主网（见 §3）。
- **STRK20 作为筹码**：玩家把 STRK20 存入隐私池换筹码，买入/下注/结算经由池子（谁能看到多少筹码 = 池子策略）。
- **Reveals**：底牌私有；结算后的手牌历史公开。
- **不要求**：游戏引擎上链（可离链）、主网部署隐私池（测试网即可）、隐私池桥接（用最简单方案）。

### 0.3 两仓库现状（勘查结论）

- `zgame`（分支 `feat/starknet`，**16 个已修改文件 + `proving-tool/`、`third_party/` 未入库**）：
  - `texas/`（~36k LOC）：axum+socket.io 游戏服务器、完整德州状态机、Starknet 结算（dual_settle/paymaster/mirror/submit）、relayer、`snops` CLI。**已通过绝对路径依赖 `/Users/mac/projects/poker_texas_air/{poker_l1, poker_texas_air, poker_protocol(ptx_protocol)}`** —— 运行时栈事实上横跨两个仓库。
  - `client/`（React18+Vite，~17k LOC TS）、`client-wasm/`（wasm-bindgen 桥）。
  - `proving-tool/`：Cairo1→cairo-vm→Stwo prove→verify 的 `prove-hand` CLI（nightly-2026-01-15，独立 workspace，实测 10s（小）/29s（整手），proof 1.5MB）。
  - `third_party/proving/`：vendored starkware-libs/proving（~344k LOC，含本地 patch）+ corelib-2.19.4。
  - `poker_protocol_lean/`：Lean4+Mathlib 形式化（发现 reconstruction V2 不健全并给出已证明的 V3）。
  - 遗留（Sui/Aleo）：`sui-serialization`、`texas_poker_move`、`texas_zchain`、`crates/aleo-*`、`.move_home` 等。
- `poker_texas_air`（分支 `main`，工作树干净）：
  - AIR/settlement 工作区（stwo 2.3、texas_tagged/texas_canonical_air、hand_binding、starknet_settlement 等）。
  - `poker_contracts/`：Cairo/Scarb 合约（PokerToken、PokerVault、PokerVaultAnonymizer、PokerSettlement、PokerDualSettlement）。sepolia 已部署前 4 个中 3 个（DualSettlement 地址为空）。
  - 与 zgame **同名 5 个 crate 双向分叉**（core 7 文件、poker_protocol 29、bg 2、abi 2、proofs 8 存在差异）。
  - `strk20.json` 存在但缺口多：DualSettlement 未部署、class_hash 全空、transactions/demo 为空。
  - **无 LICENSE 文件**（Cargo.toml 却声明 `MIT OR Apache-2.0`，不符）。
  - README 为英文技术状态备忘录：无快速启动、无部署、无双语。

---

## 1. 代码迁移计划

### 1.1 迁移范围决策：**复制（copy），不移动（move）**

理由：保留 zgame 作为历史归档与回滚保险；`feat/starknet` 分支的未提交工作先在 zgame 内提交并打 tag（`zgame-migration-source`），形成可追溯的迁移源快照；迁移后在 poker_texas_air 内冻结 zgame，此后所有演进只在 poker_texas_air。

### 1.2 迁移清单

**复制（按优先级）**

| 源（zgame/） | 目标（poker_texas_air/） | 说明 |
|---|---|---|
| `texas/` | `texas/` | 游戏服务器 + Starknet 结算 + relayer + snops；需剥离 Sui 依赖（见 P2） |
| `client/` | `client/` | React 前端；排除 `node_modules`、`dist`、`.env*`（密钥类） |
| `client-wasm/` | `client-wasm/` | 撤销其独立 `[workspace]` 声明，纳入主 workspace（wasm 目标单独用 wasm-pack 构建） |
| `sui-serialization/` | `sui-serialization/`（暂留，标记 deprecated） | client-wasm 的传递依赖、零依赖小 crate；P3 评估能否直接删除 |
| `proving-tool/` | `proving-tool/` | 独立 workspace 保持 excluded（nightly-2026-01-15 锁定在其 rust-toolchain.toml，不泄漏主 workspace） |
| `third_party/proving/` + `corelib-2.19.4` | `third_party/proving/` | vendored，保留上游 Apache-2.0 LICENSE；patch 清单写入 `third_party/PATCHES.md`（上游 commit dd1787b）；`.gitignore` 排除其 `target/` |
| `poker_protocol_lean/` | `poker_protocol_lean/` | 非 cargo 成员；形式化证明是 Innovation 25% 的核心素材 |
| `docs/*.md`（plan-b/c/d、p3-metrics、starknet-rfp-submission） | `docs/` | 与现有 docs 合并；`starknet-rfp-submission.md` 改写为 §4 的 RFP 对齐文档 |
| zgame 侧 5 个共享 crate 的**增量** | 并入现有同名 crate | 见 P1 归一策略（不是整目录覆盖） |

**不迁移**：`texas_poker_move/`、`texas_zchain/`、`.move_home/`、`crates/aleo-*`、`zgame_aleo/`、`client-wasm-aleo/`、`proving/`（空壳）、`chain/`、`.DS_Store`、一切 `target/`、`node_modules/`、`.env*`（**`texas/.env`、`.env.dev` 含部署私钥，绝不复制、绝不提交**；只带 `.env.example` 模板）。

### 1.3 目标仓库结构

```
poker_texas_air/
├── Cargo.toml            # workspace：现有成员 + texas + client-wasm；exclude proving-tool、third_party
├── src/ …                # AIR 主 crate（现状保留）
├── poker-protocol-{abi,core,bg,proofs}/   # 归一后的唯一真源（见 P1）
├── poker_protocol/       # 同上，版本统一为 0.3.0
├── poker_l1/  vm-common/  hand-bench/      # 现状保留
├── texas/                # [新] 游戏服务器（去 Sui、去绝对路径）
├── client/               # [新] React 前端
├── client-wasm/          # [新] 浏览器密码学/验证 WASM
├── proving-tool/         # [新] prove-hand CLI（独立 workspace，excluded）
├── third_party/proving/  # [新] vendored Stwo（excluded，保上游 license）
├── poker_protocol_lean/  # [新] Lean4 形式化
├── poker_contracts/      # Cairo/Scarb 合约（现状保留）
├── docs/                 # 合并后文档 + RFP03_ALIGNMENT.md
├── fuzz/  tests/  scripts/ .github/        # 现状保留 + CI 扩展
├── README.md             # 英文（默认）+ README.zh-CN.md
├── LICENSE               # BSL 1.1（§2）
├── NOTICE / THIRD_PARTY_NOTICES.md
├── strk20.json           # 补全缺口（§7）
└── EXECUTION_PLAN.md → docs/EXECUTION_PLAN.md（本文档）
```

### 1.4 分阶段执行

**P0 准备与安全审计（0.5 天）**
- zgame：提交全部未提交改动（16 个修改文件 + `proving-tool/` + `third_party/`），打 tag `zgame-migration-source`。
- poker_texas_air：新建分支 `feat/consolidate-zgame`；审计两仓库 `.gitignore`（确保 `.env*`、`target/`、`node_modules/`、`proving-tool/output/`、`.DS_Store` 全部排除）；`git log` 确认历史中无私钥泄漏。
- 产出：干净迁移源 + 安全基线。验证：`git status` 两仓库干净。

**P1 共享 crate 归一（1–1.5 天，全计划最高风险项）**

问题：5 个同名 crate 双向分叉，且 zgame 的 `poker_protocol` 是 0.2.0、本仓库是 0.1.0，`texas` 同时依赖两者（本仓库副本以别名 `ptx_protocol` 引入做 JSON 重解析）。

策略（本仓库为唯一真源）：
1. 以 poker_texas_air 现状为基线（CI 绿、合约类型绑定在此侧）。
2. 移植 zgame 独有文件：`zk_shuffle/bayer_groth/`、`poker_protocol/tests/`、`poker-protocol-proofs/tests/{plan_d_perf,stark_curve_regression}.rs`、`reconstruction_soundness.md`，以及 zgame 未提交的 `stark_curve.rs`/`lib.rs` Plan D 改动。
3. 对内容分叉文件（`z_poker/**`、crypto 模块、`precompile.rs`、`bg/proof.rs`、`transcript_ext.rs`、`v3_tests.rs`）逐个 diff 合并：保留本仓库的 secp256k1/bn254 sigma 与 settlement 新增，吸收 zgame 的 STARK 曲线 Plan D 优化。
4. **裁判是两侧测试集**：每合并一批文件就同时跑两侧测试（含 `plan_d_perf`、`stark_curve_regression` 与本仓库 `bn254/secp256k1` 向量测试）。borsh 编码兼容性是隐性约束（client-wasm/合约 calldata 依赖），任何序列化改动必须回归向量测试。
5. 版本统一：归一后 5 crate 按统一版本（建议 0.3.0）发一版，workspace.dependencies 集中声明。
- 验证：`cargo test --workspace` 全绿；两侧历史测试全部保留并通过。

**P2 texas 迁入与 Sui 剥离（1 天）**
- 复制 `texas/`，Cargo.toml 改写：绝对路径依赖 `poker_l1`/`poker_texas_air`/`ptx_protocol` → workspace 内相对依赖；P1 完成后**删除 `ptx_protocol` 双依赖**（单一 `poker_protocol`）。
- 剥离 Sui：删除/feature-gate `src/sui_*`（events/grpc/graphql/webhook）与 socket/main 中的 listener 接线；移除 `sui_sdk`、`sui-*`、`tonic`、`prost-types`、`sui-serialization` 依赖与 `legacy-bls` feature（legacy BLS 是 Sui 时代遗产）。
- 依赖版本归一进 workspace.dependencies（thiserror 1→2、borsh 1.5→1.7 等对齐）。
- 验证：`cargo check/test -p texas` 通过；本地起服 + smoke 一手牌。

**P3 client + client-wasm（0.5 天）**
- 复制 `client/`（排除 node_modules/dist/env 密钥），`.env.example` 模板化（server URL、钱包与 RPC 配置）。
- `client-wasm/` 去独立 workspace 声明、纳入主 workspace；`sui-serialization` 若仅剩序列化工具用途则评估内联删除，否则按 deprecated 保留。
- 验证：`wasm-pack build` + `pnpm install && pnpm build`；浏览器连本地 server 完整打一手牌。

**P4 proving-tool + third_party（0.5 天）**
- 原样复制两个目录；主 workspace `exclude` 两者；`.gitignore` 加 `third_party/proving/target/**` 与 `proving-tool/{target,output}`。
- 写 `third_party/PATCHES.md`：上游 commit、每个 patch 的动机（gas disabled 编译配置、PublicSegmentContext entrypoint builtins 等，proving-tool/README 已有素材）。
- 验证：在 proving-tool 目录内 `./prove-hand.sh` 冒烟（工具链由其 rust-toolchain.toml 自动切换为 nightly-2026-01-15，不影响主 workspace 的 nightly-2026-04-15）。

**P5 Lean + docs 合并（0.5 天，可与 P4 并行）**
- 复制 `poker_protocol_lean/`（含 README、SECURITY_RECONSTRUCTION.md）；在主 README 的 Innovation 章节链接其结论（V2 不健全的机器检查反例 + V3 修复与 soundness 定理）。
- 合并 zgame docs；把 `starknet-rfp-submission.md` 改写为 `docs/RFP03_ALIGNMENT.md`（§4 的映射表）。
- 处理文档漂移：README 与 `HOST_ZERO_RISTRETTO_AIR.md` 仍描述已移除的 Ristretto 路径 → 标注 superseded/归档说明（活跃规范是 `docs/design/DUAL_PROOF_PROTOCOL.md` v2.3）；修正 selector 数量不一致（20 vs 23）。

**P6 全链路验证 + CI（0.5 天）**
- `cargo test --release --workspace`（现有 ci.yml 口径）+ `scarb build/test`（poker_contracts）+ `wasm-pack` + `pnpm build` + `prove-hand` 冒烟。
- CI 扩展：新增 scarb job、wasm-pack job、pnpm build job（proving-tool 不进 CI，README 说明本地运行）。
- sepolia 重部署：跑 `deploy_sepolia.sh`，**部署 PokerDualSettlement**，回填 strk20.json 全部 class_hash 与交易哈希。
- 合并回 main，开始 "Build in public" 周报。

### 1.5 风险表

| 风险 | 等级 | 对策 |
|---|---|---|
| P1 crate 合并引入类型/序列化不兼容（client-wasm、合约 calldata） | 高 | 双侧测试集逐批回归；borsh 向量测试；必要时保留 ptx_protocol 别名一版过渡 |
| Sui 剥离触碰 socket 接线导致运行时行为变化 | 中 | 剥离前先在 zgame 侧跑通 e2e 基线；剥离后同用例复测 |
| nightly 工具链冲突（pta nightly-2026-04-15 vs proving-tool nightly-2026-01-15） | 低 | proving-tool 独立 workspace + 自带 rust-toolchain.toml（现有机制原样保留） |
| third_party 体积拖慢 clone / 触发平台限制 | 低 | 排除 target；如超限改为 submodule + patch overlay（备选方案已注明） |
| 泄漏 .env 私钥 | 致命 | P0 审计 + .gitignore + 提交前 `git ls-files` 复查；.env.dev 已 gitignore，保持不入库 |

---

## 2. License：商业使用不免费（要求 2）

**现状**：两仓库自有代码均无 LICENSE 文件；poker_texas_air 的 Cargo.toml 声明 `MIT OR Apache-2.0` 与"商业不免费"的目标矛盾，必须改。

**选定方案：Business Source License 1.1（BSL 1.1，SPDX: `BUSL-1.1`）**
- 源码公开可读可构建（source-available），满足黑客松"公开仓库"要求；
- 默认禁止商业使用，通过 **Additional Use Grant** 明确豁免：非商业用途、学习研究、以及 STRK20 黑客松评审/演示用途免费；
- 设 **Change Date**（建议 4 年上限内取 2029-12-31），到期自动转为 **Change License: Apache-2.0**；
- 我们作为版权人保留双许可（商业授权）权利。

备选：PolyForm Noncommercial 1.0.0（一刀切禁商用、无自动转正）——除非明确想要最严格条款，否则不推荐，BSL 的"到期转 Apache-2.0"对社区更友好。

**落地步骤（P5 内完成）**
1. 根目录 `LICENSE`：BSL 1.1 全文 + Licensor 信息 + Change Date + Change License + Additional Use Grant。
2. 所有自有 crate 的 `license = "MIT OR Apache-2.0"` → `license = "BUSL-1.1"`（均 `publish = false`，不影响发布）。
3. `NOTICE` / `THIRD_PARTY_NOTICES.md`：**第三方代码不可也不得改许可** —— `third_party/proving`（StarkWare, Apache-2.0）、stwo/cairo-lang/cairo-vm（Apache-2.0）、starknet-rs（MIT）、RustCrypto/curve25519-dalek 等（MIT OR Apache-2.0）、vendored flock（MIT/Apache）。vendored Apache-2.0 代码本身任何人都可商用，这是上游权利，与自有代码的 BSL 并存不冲突，NOTICE 中写清楚边界。
4. README 增加 License 章节，说明"源码可读、非商业免费、商业需授权、到期转 Apache-2.0"。

**与评审标准的权衡（必须知晓）**：15% 的 "open-source quality" 通常偏好 OSI 开源许可，BSL 非 OSI 认证。缓解：以文档质量、CI 完整度、贡献指南、第三方合规 NOTICE 补足；且 hash 项目（Sentry/HashiCorp）先例使其在评审中不至于被视为"闭源"。

---

## 3. Prover 服务暂不部署：host 验证 + 客户端可验证（要求 3）

**现状事实（勘查确认）**
- `texas` 的 `STARKNET_SETTLE_MODE=linear|proved`：`proved` 模式会导出 workload JSON 并调用 `STARKNET_PROVER_URL`，但该 HTTP client 是**必然报错的 stub**，因此确定性回退 `linear` —— 即**当前不存在任何独立 prover 服务**，证明由运行方（host/operator）在本地用 `proving-tool` 完成。
- `strk20.json` 的 `proof_policy` 已经如实声明：**P 层**（secp256k1 direct-sigma）由 PokerDualSettlement 合约**链上 EC_OP 内置件验证**；**G 层**（Stwo circle-STARK）**host 验证**（operator attests，Phase 2 前的过渡态）。

**提交时点的官方口径（写入 README 与 strk20.json）**
1. **不部署独立 proved/prover 服务**。G 层 STARK 证明由 operator host 本地生成（`proving-tool`，实测整手约 29s、proof 1.5MB）并在 host 侧验证后，以 operator 签名/承诺的形式进入结算；链上只强验证 P 层 sigma（EC_OP）。
2. **客户端可以独立验证，不必须信任 host**：`client-wasm` + `poker_protocol::browser_proof_bundle` 把证明 bundle 下发到浏览器本地验证（zgame 8/29 已落地 browser-verified WASM 路径）。任何人都能在本地复算 G 证明，把 host 信任降级为可用性依赖而非正确性依赖。
3. **这是 RFP-03 明文允许的阶段性状态**：原文 "STARK verifier (the L2 doesn't need to be on mainnet yet — the RFP explicitly asks for it 'eventually')"。
4. **路线图（README Roadmap + docs/design/DUAL_PROOF_PROTOCOL.md 对齐）**：Phase 2 = G-STARK 验证器合约上链（cairo_verifier 方向）；Phase 3 = 独立 prover 服务（把 STARKNET_PROVER_URL 从 stub 变成真实端点），host attestation 随之移除。

**落地**：README 英/中文各一节 "Trust model & proof policy"，附上述 P/G 分层图；`strk20.json` 的 `proof_policy` 保持该口径并把 demo 指向"浏览器验证 G 证明"的录屏。

---

## 4. 靠近 RFP-03（要求 4）

**定位**：按 IDEAS.md 选择 **RFP-03（Gaming）**；叙事采用 zgame `docs/starknet-rfp-submission.md` 的定位并更新——我们不只是 RFP 的最简 trusted-dealer 版本，而是 **mental poker V2：无受信发牌方**， dealer 的每一步都是密码学证明对象。

**RFP-03 要求 → 本仓库映射表（落为 `docs/RFP03_ALIGNMENT.md`）**

| RFP-03 要求 | 仓库对应物 | 状态 |
|---|---|---|
| Mental poker（无可信洗牌/发牌） | `poker_protocol`（ElGamal + Bayer-Groth shuffle）、`poker-protocol-{core,bg,proofs}` sigma 证明族、`poker_protocol_lean` V3（Lean 证明 soundness） | ✅ 已有 |
| Dealer STARK 证明义务（每条街 range/strength/terminal） | `proving-tool`（Stwo circle-STARK；当前跑的是建模 hand-verify sigma 批的 bench 程序） | ⚠️ Phase 1 为主机验证 + bench 程序；真实 `hand_verify.cairo` 电路为 Phase 2（RFP 允许 eventually） |
| STARK 引擎 | stwo 2.3（AIR crate）+ vendored proving stack | ✅ |
| STRK20 = 筹码（隐私池买入） | `poker_contracts`：PokerToken（本地测试代币）、PokerVault（1:1 STRK20 存取）、PokerVaultAnonymizer（隐私池 + ZK 买入 + paymaster 中继，plan-b 文档） | ✅ sepolia（RFP 明言测试网即可） |
| 底牌私有 / 手牌历史公开 | hole cards 私有（mental poker 加密）；PokerSettlement 链上聚合摘要、单调手数区间、Poseidon 承诺 | ✅ |
| 引擎可离链 / 不要求主网隐私池 / 池桥最简化 | 服务器离链；sepolia 部署；无跨链桥 | ✅ 按最简路径 |

**补齐动作**
1. P5 产出 `docs/RFP03_ALIGNMENT.md`（上表 + 每条证明义务的实现指针）。
2. strk20.json 补全（§7）：RFP 字段选 RFP-03、部署记录、demo。
3. README 项目简介第一段直接呼应 RFP-03 标题措辞（"provably fair, cheating is mathematically impossible"→我们以 mental poker + 双证明体系落地）。
4. Innovation 叙事（25% 权重的弹药）：Lean 形式化发现并修复 reconstruction V2 不健全问题；P（链上 EC_OP sigma）/ G（Stwo STARK）双证明分层；host-zero 演进路线。

---

## 5. README 双语，默认英文（要求 5）

- `README.md`：**英文，默认入口**。顶部语言切换链接 `[English](../../README.md) | [简体中文](../../README.zh-CN.md)`。
- `README.zh-CN.md`：完整中文翻译（同一结构，不是摘要）。
- 结构大纲（两版一致）：
  1. 标题 + 一句话定位（呼应 RFP-03）+ badges（CI、license BUSL-1.1、RFP-03）
  2. Why：作弊在数学上不可能 —— mental poker V2、P/G 双证明
  3. Architecture：目录结构图 + 数据流（client ↔ texas server ↔ Starknet 合约 ↔ prover）
  4. **Trust model & proof policy**（§3 口径，含 G 层暂 host 验证、浏览器可独立验证的说明）
  5. **Quick Start**（§6）
  6. **Deployment**（本地 devnet / sepolia / 主网最小路径）
  7. RFP-03 alignment 摘要 + 链接 `docs/RFP03_ALIGNMENT.md`
  8. Formal verification（Lean）亮点
  9. Roadmap（Phase 2 链上 G-STARK、Phase 3 prover 服务）
  10. License（BSL 1.1 说明）+ 第三方 NOTICE 链接 + Contributing
- 现有 README 的技术状态叙述移入 `docs/STATUS.md`（信息有价值但不是落地页）；同时修复文档漂移（Ristretto 叙述 → 标注已被 secp256k1/bn254 路径取代）。

---

## 6. 启动与部署指导（要求 6，README 主体章节）

**Quick Start（本地）**
```
前置：rust(nightly-2026-04-15)、scarb+snforge(starknet 2.11)、node+pnpm、wasm-pack
1. cargo test --workspace                 # Rust 工作区
2. (cd poker_contracts && scarb build && snforge test)
3. wasm-pack build client-wasm --target web
4. ./scripts/local_deploy.sh              # 本地 devnet 起 PokerToken/Vault/Settlement
5. cargo run -p texas                     # 游戏服务器（.env.example → .env）
6. (cd client && pnpm install && pnpm dev) # 浏览器客户端，打一手牌
7. (cd proving-tool && ./prove-hand.sh)    # [可选] G 层 STARK 本地证明演示
```

**Deployment**
- **sepolia**：`poker_contracts/deploy_sepolia.sh`（sncast declare/deploy；所需 env：SNCAST_ACCOUNT/URL/OWNER/PROVER/INITIAL_SUPPLY；细节已在 SEPOLIA.md，README 收纳为正式章节）；部署后回填 strk20.json。
- **主网（黑客松 step 3 硬性要求）**：至少一笔 STRK20 主网交易（deposit + withdraw 即可，不必是整局游戏）；在 PokerVault 主网最小部署与直接 STRK20 转账两案中按当时主网 STRK20 合约状态选最简者，交易哈希写入 strk20.json。
- **配置与安全**：所有 env 走 `.env.example` 模板；私钥永不入库。

**CI**：现有 ci.yml（check/test/release 集成测试）保留，新增 scarb / wasm-pack / pnpm 三个 job。

---

## 7. 收尾清单（对应 Four steps / Four criteria）

- [ ] Step 1 Apply：报名表选定 RFP-03（人工动作）
- [ ] Step 2 Build in public：P0–P6 每阶段独立 commit 到 main；每周 check-in 帖
- [ ] Step 3 Ship to mainnet：≥1 笔主网 STRK20 交易，哈希入 strk20.json
- [ ] Step 4 自动扫描项：strk20.json 补全（PokerDualSettlement 部署地址、全部 class_hash、transactions、demo_video、demo_url；token/proof_policy 保持真实口径）
- [ ] Criterion 1（STRK20 深度 30%）：Vault 买入/结算走池 + 主网交易记录
- [ ] Criterion 2（可用产品 30%）：Quick Start 一条命令链可复现；demo 视频录"浏览器验证 G 证明"
- [ ] Criterion 3（创新 25%）：README/ALIGNMENT 文档讲清 mental poker V2 + Lean V3 + P/G 双证明
- [ ] Criterion 4（文档与开源 15%）：双语 README、LICENSE/NOTICE、CI、CONTRIBUTING

## 8. 时间表汇总（净工作量约 4.5–5.5 天）

| 阶段 | 工期 | 关键产出 |
|---|---|---|
| P0 准备 | 0.5d | 源快照 tag + 安全审计 |
| P1 crate 归一 | 1–1.5d | 5 crate 单一真源、双侧测试全绿 |
| P2 texas 迁入 | 1d | 去 Sui、去绝对路径、server 可跑 |
| P3 client/wasm | 0.5d | 浏览器完整对局 |
| P4 proving/third_party | 0.5d | prove-hand 冒烟 + PATCHES.md |
| P5 Lean/docs/license/README | 0.5–1d | 双语 README、LICENSE、RFP 对齐文档 |
| P6 验证/CI/部署 | 0.5d | 全链路绿 + sepolia/主网记录 + strk20.json 完整 |
