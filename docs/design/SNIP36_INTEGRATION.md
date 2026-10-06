# SNIP-36 接入设计（in-protocol proof verification → DAPV）

> **Summary (EN).** The single design doc for SNIP-36 integration; decision
> record: dual-proof in one (§3). **Phase 1 is shipped** — dual v5
> (`verify_and_settle_dapv_stark_private_v3`: in-protocol SNIP-36 verification
> with fact-registry fallback) deployed on Starknet mainnet 2026-09-07, with
> real SNIP-36 private transactions on mainnet; deployment/wiring details in
> `poker_contracts/DEPLOYMENTS.md`. Remaining follow-ups (prover tooling, SNOS
> form) are tracked in `docs/TODO.md`. Binding scheme and settlement
> algorithm: see `docs/SOUNDNESS.md` (P-layer pillar). Chinese is the working
> language of this spec.
>
> 状态：**Phase 1 已落地（dual v5，2026-09-07 主网）**——
> `verify_and_settle_dapv_stark_private_v3`（SNIP-36 协议内验证 +
> fact-registry 降级双门）已部署主网，主网已有真实 SNIP-36 私密交易。
> 决策记录：hand_verify 形态裁决 = **双证明合一**（§3）。
>
> **2026-09-06 核对修订**：SNIP-36 **未被废弃**——已随 Shinobi 升级于
> **2026-04-21 主网激活**（Starknet v0.14.2），现为 STRK20/strkBTC 隐私的
> 核心基础设施。此前文档中"SNIP-36 新版本不支持"系对 prover 工具链版本
> 问题的误传，不是协议状态；协议侧无等待项，缺口全部在我方（§5）。
> 原执行计划（`plan-snip36-execution.md`）已删除，见 git 历史。
> 关联：`docs/SOUNDNESS.md`（绑定方案/结算验证算法，原 DAPV_SOUNDNESS §9-10）、
> `poker_contracts/DEPLOYMENTS.md`（部署档案）、
> `docs/TODO.md`（任务状态以 TODO 为准）。

## 1. SNIP-36 机制（与 fact-registry 的对照）

SNIP-36 = **协议内 S-Two 证明验证**（Starknet v0.14.2+）：不再部署
Cairo verifier 合约 + fact registry，由协议/共识直接验证 stwo-cairo 证明。

| | fact-registry（现状） | SNIP-36（目标） |
| --- | --- | --- |
| 证明验证方 | 运营侧离线验证，人工登记 fact | 协议在 tx 执行内验证 |
| 信任锚 | 运营方背书（residual trust） | Phase 1：sequencer/consensus 验证（**同级**残差信任，非 SNOS）；后续：SHARP 集成 → 以太坊 L1 终局验证（真升级） |
| 合约消费 | `settlement_facts.read(fact)` | `get_execution_info_v3_syscall().tx_info.proof_facts` |
| 注册动作 | `register_settlement_fact`（prover/owner 门控） | **无注册**——`create_proof` 入口（发 `to_address=0` 的 L2→L1 消息）是被证明对象 |
| fact 公式 | `poseidon([program_hash, segment])` | `proof_facts[8] = poseidon(合约地址, 0, payload_len, payload)`；`facts[2] = virtual_OS_prog_hash` |
| 证明数据位置 | 不上链 | `proof` 字段（uint32 数组）只经 gateway/mempool 传播，**不进 calldata、不进区块**（绕过 5K felt calldata 上限——这正是 SNIP-36 的动机） |
| 计费 | 一个 felt 的存储 | **125（传播）+ 5（存储）= 130 L2gas/byte + 10M L2gas 基础**；规范示例 500KB ≈ 75M L2gas（生产锚点，STRK20 隐私在用） |

流程：一笔 INVOKE_V3（调 `create_proof` 形态入口）不广播 → 证明服务
（`starknet_os_runner::starknet_proveTransaction`，被证明对象是**虚拟
Starknet OS** 程序形态）对照参考区块状态离线执行产出证明 → 提交时
携带 `proof`/`proof_facts` 字段，tx hash 附加 `proof_facts_hash` →
sequencer 验证后传播 → settle 入口内读 `proof_facts` 做绑定断言。

## 2. 仓库现状与关键判定（2026-09-06，二次核对修订）

- **协议侧无等待项**：SNIP-36 已主网激活（2026-04-21）。此前"新版本不
  支持"的判断撤销；工作全部在我方形态适配与成本压缩。
- **证明系统同族**：proving-tool 管线已是 `Cairo1 → compile → run →
  witness → stwo prove`（`proof.json`/`public_outputs.json`），无需换
  证明系统。但 SNIP-36 被证明对象是**虚拟 Starknet OS 程序**形态——
  我方 Cairo 程序需适配 `starknet_proveTransaction` 的执行/证明上下文，
  不是裸 prove-hand 产物直连（§5 #1 的实质）。
- **证明尺寸实测（2026-09-06，felt 计数 × 4B 二进制估算）**：
  settlement 电路 12.2MB JSON ≈ 575k felts ≈ **2.30MB**；hand-verify
  composed 19.5MB JSON ≈ 879k felts ≈ **3.52MB**。对照生产锚点
  500KB（≈75M L2gas）：超锚点 **4.6×/7×**（≈300M/460M L2gas）——
  不是不可行，是需要参数收紧 + 批聚合摊薄（§3a）。注意 hand-verify
  评估实测证明尺寸与手数基本无关（1 手 14.3MB vs 10 手 14.1MB），
  即**批聚合不增加证明字节**，单位成本随批大小线性下降。
- **合约侧硬前提缺口**：cairo **2.11.4** 的捆绑 corelib **不含**
  `TxInfo.proof_facts`（`strings scarb | grep -c proof_facts` = 0；
  `third_party/corelib-2.19.4/corelib/src/starknet/info.cairo:323` 已含
  `pub proof_facts: Span<felt252>`）。消费路径要求 **cairo ≥ 2.12**——
  这是一次编译器迁移（92 个 snforge 测试 + casm 哈希 + 字节码上限全部
  重验），归入 §5 的 SNIP-36 腿，不与零风险项混做。
- **libfuncs 已放开**：`poker_contracts/Scarb.toml` `[cairo]
  allowed-libfuncs-list.name = "all"`（`get_execution_info_v3_syscall`
  在白名单之外；当前代码未用白名单外 libfunc，零行为变化）。
- **后端入口选择已预埋**：`STARKNET_DAPV_SETTLE_ENTRY` = `v2`（默认，
  可随时回退）| `proved_private`（双 fact，dual v4 已上链）| `snip36`
  （v3 入口选择器已预埋，**合约侧随 cairo ≥2.12 迁移上链后生效**——
  选中后发往现网会 revert，属预期）。

## 3. 裁决：hand_verify 形态 = 双证明合一（ADR-2026-09-06-1）

**决定**：SNIP-36 路径下不再保留独立的 hand_verify 证明——把
hand_batch σ 批量校验（ρ 折叠 MSM）**并进 settlement_private 电路**，
单证明覆盖「批次校验成立 ∧ 结算派生正确」。

理由：
1. **避开 EC_OP 在 SNIP-36 下的不确定性**：hand-verify form-① 是原生
   stwo AIR（非 Cairo 程序），根本进不了 SNIP-36；form-②（Cairo EC_OP
   composed）可以，但 EC_OP builtin 在虚拟 OS 上下文的支持需单独验证。
   并进 settlement 电路后 EC 方程与现有电路共用证明上下文，一处验证。
2. **省一半证明费**：SNIP-36 证明数据费 ≈ 10M L2gas 基础 + 130/byte；
   两张证明 → 一张。
3. **fact 结构消解**：`p_batch_commitment` 进公开段（尾词或替换
   `hand_verify_program_hash` 绑定），合约双 fact 断言退化为单 fact。

**代价与边界**：
- 电路步数增加：σ 折叠 MSM ≈ 每手 700 方程（2 人手 ~90 条）→ Cairo
  EC_OP 步数线性放大，prove 时间与 proof 尺寸重估（现 2048 步基线）。
- `p_batch_commitment`（`poseidon(hand_binding, poseidon(p_batch words))`)
  必须由电路内部重算（输入 = 批次词），不能作为外部断言——否则证明
  只覆盖「给定承诺的结算」而非「真实批次的结算」。
- 双 fact 入口（`verify_and_settle_dapv_proved_private`）保留至合一
  电路上链，作为过渡期双保险；届时退役
  `set_hand_verify_program_hash`（owner 门控，天然可退役）。

### 3a. 附记（2026-09-15，ADR-2026-09-15-1）：合并撤销——canonical 全手证明承载

单一状态重构 + canonical AIR 全手贯通（见 `docs/STATUS.md` 2026-09-14/15
三节：VmSession 单一状态、控制轨迹 → canonical 行链、
`full_hand_control_trace_proves_through_showdown_display` 全通）落地后，
本 ADR 的三条理由被**逐一结构性消解**，电路合并不再实施：

1. **EC_OP 不确定性 → 结构性消解**：σ 批量校验维持 Plan D native 验证
   边界（hand-verify-native AIR），**永不进入 SNIP-36 被证明交易**——
   v3 结算交易（create_proof + settle）只含 Poseidon/存储/escrow 调用，
   无 EC 方程；σ/牌局正确性由 canonical 全手证明链（`HandProofBinding`，
   `hooks.rs::build_appchain_hand_proof`）承载，两条信任锚各司其职。
2. **省一半证明费 → moot**：SNIP-36 主腿本来就只提交一张 proved 交易
   （v3 结算）；"两张证明"只发生在 proved_private 双 fact 入口——该入口
   进入退役路线（见下）。
3. **fact 结构消解 → 改形**：canonical 行链的终态承诺
   （`post_state_commitment` / pre-post state roots）即整手绑定，随
   `HandProofBinding` 走 appchain 结算出口；dual 合约 fact 公式
   `poseidon(program_hash, segment)` **保持不变**（v6 兼容，不破坏
   fact-verify/proving-tool 工具面）。

**新裁决**：
- settlement_private 电路**冻结**为 fact-registry 降级腿专用（现版，
  不并入 σ）；
- SNIP-36 主腿 = create_proof 交易虚拟 SNOS 证明 + v3 双门（现状即终态）；
- `proved_private` 双 fact 入口与 `hand_verify_program_hash` 的退役条件
  改为：**canonical-backed settlement 接线完成**（HandProofBinding 进
  Starknet 结算出口，Stage 3）后随 v7 移除；v6 不动它们（保持
  proved_private 过渡保险可用）。
- v6 构建指纹：scarb 2.19.4，sierra_program 15,791 felts / 34 入口。

## 4. 合约 v3 双门入口设计（cairo ≥2.12 上链时实施）

```cairo
/// P2-M5：SNIP-36 优先、fact-registry 降级的双门私密结算。
/// calldata 与 v2 完全一致：[hand_binding, hand_id, segment(15)]。
fn verify_and_settle_dapv_stark_private_v3(
    ref self: ContractState,
    hand_binding: felt252,
    hand_id: u64,
    segment: Span<felt252>,
) {
    // ……（与 v2 相同的注册侧/公开段断言：magic/hand_id/binding/digest/
    //    action_log/n 范围）……

    // —— 双门：SNIP-36 优先，fact-registry 降级 ——
    let exec = get_execution_info_v3_syscall().unwrap_syscall();
    let facts = exec.tx_info.proof_facts;
    let snip36_ok = !facts.is_empty() && {
        // facts[2] = virtual_OS_prog_hash 必须等于钉死电路哈希
        *facts.at(2) == self.circuit_program_hash.read()
        // facts[8] = 消息哈希：poseidon([本合约地址, 0, payload_len, payload])
        // payload 即 segment（create_proof 入口发出的公开段）——逐 felt 重算比对
        && *facts.at(8) == message_hash_for_segment(get_contract_address(), segment)
    };
    if !snip36_ok {
        // 降级：fact-registry（过渡期信任锚，与 v2 同门）
        let program_hash = self.circuit_program_hash.read();
        assert!(program_hash != 0, "Circuit program hash not set");
        assert!(
            self.settlement_facts.read(fact_for_segment(program_hash, segment)),
            "Settlement fact not registered"
        );
    }
    // ……（与 v2 相同的私密派奖：escrow + claim_cms + amounts_hidden）……
}

fn message_hash_for_segment(self_addr: ContractAddress, segment: Span<felt252>) -> felt252 {
    let mut h = PoseidonTrait::new();
    h = h.update(self_addr.into());
    h = h.update(0);
    h = h.update(segment.len().into());
    let mut w: u32 = 0;
    while w < segment.len() { h = h.update(*segment.at(w)); w += 1; }
    h.finalize()
}
```

> 注意：`facts[8]`/`facts[2]` 的槽位与消息哈希公式以 SNIP-36 最终规范
> 为准；上链前用 sepolia 真实 proof_facts 样本对拍一次再冻结常量。
> **2026-09-14 修订**：`facts[2]` 的绑定根不是本方电路哈希而是 Starknet
> 虚拟 OS program hash——实现与裁决见 §5（dual v6）。

## 5. 缺口状态表（2026-09-14 三次修订：#1/#2/#4 工程落地）

| # | 工作项 | 状态 |
| --- | --- | --- |
| 7 | Phase 1 安全边界落档（本文 §1/§2） | ✅ 2026-09-06（同日修订：协议已主网激活，无协议等待项） |
| 3a | libfuncs `all`（Scarb.toml） | ✅ 2026-09-06（构建 0 错、snforge 92/92） |
| 0 | **证明瘦身实测**（SNIP-36 直连的先决量化项） | ✅ **2026-09-14 实测完成**（`scripts/slimming-matrix.sh`，8 配置矩阵，数据见 §6）：**推荐参数 `p3`（pow26/b2/q35/fs4）在 96-bit 等安全下 bincode −43%（1.31MB→750KB）、bzip2 wire −51%（1.02MB→501KB，达标 ≤500KB 级）、JSON −53%**；证明耗时 6.7s→11.3s（异步结算可接受）。朴素 70→30（p1）证伪：blowup=1 下仅 56-bit——尺寸优势是假象，p3 以同等尺寸保住全安全。`cairo_serde` 格式对本电路不可用（未启用 builtin 触发 vendored 栈 panic，已隔离并记录）。b≥3 在 36GB 机器上临界 OOM。**注：SNIP-36 腿上链证明是虚拟 SNOS 执行（参数由 Starknet 证明服务定），本矩阵约束的是 fact-registry/zchain 腿的自有证明尺寸** |
| 3b | 合约 proof_facts 消费路径（§4 v3 入口） | ✅ 2026-09-07 上链（dual v5）；**2026-09-14 修正**（见下） |
| 5 | hand_verify 形态裁决 = 双证明合一（§3 ADR） | ♻️ **2026-09-15 撤销合并（§3a 附记 ADR-2026-09-15-1）**：canonical 全手证明承接 σ/牌局正确性，settlement_private 电路冻结为降级腿专用，proved_private 退役条件改挂 Stage 3（canonical-backed settlement） |
| 1 | 电路改造为 create_proof 入口 + 虚拟 SNOS 形态适配 | ✅ 2026-09-14：**两笔交易模式落地**（对齐 starknet-privacy 参考实现）——合约新增 `emit_settlement_proof_message`（create_proof 第一笔：校验公开段 + 发 `to=0、payload=segment` 的 L2→L1 消息，不写存储不结算），v3 为携带 proof 的第二笔；`validate_settlement_segment` 两笔共享同一组完整性断言。**被证明对象 = 该合约交易的虚拟 SNOS 执行，独立 settlement_private 电路仅服务 fact-registry 降级腿** |
| 2 | 证明管线切换（自托管 prover 客户端） | ✅ 2026-09-14：`texas/src/starknet/snip36.rs`——`Snip36ProverClient`（`starknet_proveTransaction` JSON-RPC：`{block_id, invoke}` → `{proof(b64), proof_facts, l2_to_l1_messages}`，错误码 24/55/61/1000/-32005 映射）+ `ProvedInvokeV3` 原始交易构造/签名/广播。**哈希链与 sequencer 逐位对拍**（官方主网向量：同笔交易无 facts `0x1d47…2219` / 有 facts `0x6d88…7276`，`transaction_hash.json` 条目 2/3）。自托管服务本身 = `docker run ghcr.io/starkware-libs/starknet-privacy/transaction-prover`（无鉴权，须内网；RPC_URL 须 v0.10 节点）——ops 部署项 |
| 4 | 提交工具（Invoke V3 `proof`/`proof_facts` 字段扩展） | ✅ 2026-09-14：`snops prove`（构造+签名 create_proof 交易 → prover 证明 → 产物落盘）+ `snops submit-proof`（读产物 → v3 结算交易携 proof(uint32)/proof_facts → `add_invoke_transaction` 原始广播）+ **服务内自动接线**（`STARKNET_DAPV_SETTLE_ENTRY=snip36` + `STARKNET_SNIP36_PROVER_URL` 时，`submit_dual_settlement` 自动两笔交易提交，失败自动回退 v2 fact-registry 腿——mock 端到端测试覆盖）。starknet-rs 0.17 无 proof 字段支持，故全程手拼 JSON + 自算哈希（模块单测 + 官方主网向量对拍） |
| 8 | snforge mock + sepolia 复现 | ✅ mock 部分（`cheat_proof_facts`，v3 模块 8/8 + 服务内接线 mock e2e 2/2）；**对拍工具已就绪**：`snops dump-proof-facts --tx-hash <真实 proved 交易>` 一键拉取并逐槽解读 proof_facts；**sepolia 真实样本采集仍 ⏳**（P4：跑一笔真实 proved 交易后执行该命令，冻结 `VIRTUAL_SNOS_VARIANT`/`virtual_snos_program_hash`/消息哈希槽位） |

**2026-09-14 修正（dual v6 待重部署）**：v5 的 SNIP-36 门断言
`facts[2] == circuit_program_hash`（本方结算电路哈希）系对布局的误读——
真实 `proof_facts[2]` 是 **Starknet 虚拟 OS（VIRTUAL_SNOS）的 program
hash**（`starknet-privacy` ProofFacts 序列化第 3 字段；0.14.3 回归样本
`0x602b02cff498684f…`），电路绑定只通过 `facts[8]` 消息哈希成立。已修
正为：`facts[1] == "VIRTUAL_SNOS"`（program variant）∧ `facts[2] ==
virtual_snos_program_hash`（新增 owner 钉扎存储，部署后 owner 须
`set_virtual_snos_program_hash` 写入真实值）∧ `facts[8]` 消息哈希不
变。**v5 上该门等于只认 fact-registry 降级腿（真实 SNIP-36 交易会被
拒）——重部署 dual v6 前不要发真实 proved 交易。** 合约测试
112/112（新增 8：v3 门 ×4 + create_proof ×3 + 降级 ×1）。

**cairo ≥2.12 迁移**：✅ 2026-09-07 完成——scarb 2.19.4 + snforge 0.63.0
（与证明侧 vendored corelib 2.19.4 同版，双工具链合一）；casm 36,508 felts；
测试命令：
`PATH=~/.local/opt/toolchains/scarb-2.19.4/bin:~/.local/opt/toolchains/snforge-0.63.0/bin:$PATH snforge test`。

**SNIP-36 两步提交流程（ops runbook，sepolia 先行）**：`segment` 为
15 个 felt 的十进制/十六进制逗号串（与 v2 calldata 完全同形）。
```bash
# 0. 自托管 prover（内网，RPC_URL 指向 v0.10 节点）
docker run --rm -p 3000:3000 -e RPC_URL=https://<node>/rpc/v0_10 \
  ghcr.io/starkware-libs/starknet-privacy/transaction-prover
# 0'. owner 钉扎虚拟 OS 哈希（dual v6 部署后一次性；值以 sepolia 实测为准）
snops --url $RPC --pk $PK --addr $OWNER invoke --contract $DUAL \
  --fn set_virtual_snos_program_hash --calldata 0x602b02cff498684fae3d66016137978fdad45a5036878a57257689d4f3f6ccb
# 1. create_proof 交易 → 证明 → 产物落盘 proof.json
snops --url $RPC --pk $PK --addr $ADDR prove \
  --contract $DUAL --fn emit_settlement_proof_message \
  --calldata "$BINDING,44,$SEG_0,$SEG_1,…,$SEG_14" --out proof.json
# 2. v3 结算交易 + proof/proof_facts 上链
snops --url $RPC --pk $PK --addr $ADDR submit-proof \
  --contract $DUAL --fn verify_and_settle_dapv_stark_private_v3 \
  --calldata "$BINDING,44,$SEG_0,$SEG_1,…,$SEG_14" --proof_file proof.json
# 3.（或）服务内自动两笔提交：结算时自动 prove → submit，失败回退 v2：
#   STARKNET_DAPV_SETTLE_ENTRY=snip36
#   STARKNET_SNIP36_PROVER_URL=http://127.0.0.1:3000
#   STARKNET_SNIP36_L2_GAS=0x5f5e100        # 可选，OS 执行 gas 上限
# 4.（对拍）真实 proved 交易样本逐槽解读：
snops --url $RPC dump-proof-facts --tx-hash $TX
```

## 6. 证明瘦身实测数据（2026-09-14，#0 落档）

复现：`proving-tool/scripts/slimming-matrix.sh`（8 配置；每配置
prove + 四格式落盘 + `--check-only` 独立复核）。对象：settlement_private
电路（5,374 步）；机器：本机 36GB（b≥3 临界 OOM 记录在案）。
安全公式 = `pow_bits + log_blowup × n_queries`（stwo `FriConfig::security_bits`）。

| 配置 | sec_bits | proof.json | bincode 原始 | bzip2 wire | prove | verify |
| --- | --- | --- | --- | --- | --- | --- |
| p0 默认（26/1/70/fs1） | 96 | 12,211,591 | 1,310,318 | 1,017,617 | 6.7s | 12ms |
| p1 26/1/**30**（对照） | **56 ⚠** | 6,651,602 | 739,998 | 495,220 | 7.4s | 8ms |
| p2 26/**2**/35/fs1 | 96 | 7,840,359 | 835,638 | 588,161 | 15.5s | 8ms |
| **p3 26/2/35/fs4（推荐）** | **96** | **5,798,765** | **750,262** | **500,868** | **11.3s** | 9ms |
| p6 26/2/47/fs2（加强参照） | 120 | 7,851,874 | 933,046 | 674,472 | 14.1s | 10ms |
| p7 26/2/35/fs1/llb3 | 96 | 7,679,252 | 827,670 | 578,354 | 11.7s | 8ms |
| p4 26/3/24 | 98 | OOM（36GB 三试两 kill；成功次 prove 64.7s） | | | | |
| p5 26/4/18 | 98 | OOM | | | | |

（单位：字节；`p{n} pow/blowup/queries/fold_step/last_layer`。）

**结论**：
1. **等安全瘦身成立**：p3 相对 p0——bincode −43%、bz2 −51%、JSON −53%，
   96-bit 不变；bz2 wire 501KB 达到"≤500KB 级"目标。prove +69%（6.7→11.3s）
   换尺寸，异步结算流程可接受。
2. **朴素 70→30 证伪**：p1 只有 56-bit（安全塌方），且尺寸与 96-bit 的
   p3 几乎相同——"省尺寸"的正确姿势是 `b↑q↓`，不是裸砍 queries。
3. **fold_step=4 是最大的免费杠杆**：p3 vs p2 再省 ~10%（层更少、查询
   路径更短），安全公式不变。
4. **blowup≥3 在 36GB 机器不可用**（并行证明器内存随 blowup 放大）；
   生产若需 b2 以上的安全余量，先解决证明机内存。
5. 口径注记：bincode 原始字节 = 链上分块对象计费口径；bzip2 = zchain
   wire；SNIP-36 腿上链的是虚拟 SNOS 证明（参数由 Starknet 证明服务决定），
   本表约束自有证明的全部出场场景（fact-registry 腿存档/zchain 对象）。
   `cairo_serde` 对本电路不可用（未启用 builtin 触发 vendored 栈
   `air.rs` unwrap panic；prove-hand `--all-formats` 已隔离该路径并落档）。
