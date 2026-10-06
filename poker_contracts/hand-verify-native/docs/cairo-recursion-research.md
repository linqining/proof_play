# hand_verify 递归证明 —— Cairo 路线调研与选型（2026-09-06）

> 任务来源:`docs/plan-snip36-execution.md` P3.3 双证明合一/ADR-2026-09-06-1（该执行计划已删除，见 git 历史）
> + spike README 的 v2 升级路径(「sigma 证明递归聚合」)。结论先行:
> **递归证明 = Cairo 路线递归信封(本仓库 `cairo/src/recursion.cairo` +
> `src/recurse.rs`)**,生产聚合升级路径 = vendored proving 栈的
> circuit 递归(资产已在 `third_party/proving/`,见 §2)。

## 1. 生态递归实现盘点(调研结论)

### 1.1 Starkware 生产递归栈(vendored `third_party/proving/` 全量在库)

完整管线 = **SHARP 式「验证证明的证明」**,四层:

```
Cairo 程序(hand_verify) ──stwo-cairo──▶ CairoProof(proving-tool 的 proof.json)
        │
        ▼  crates/cairo_verifier:cairo-verifier 电路(Rust, circuits DSL)
        │   消费 cairo_air::CairoProof,把「验证该证明」建为电路
        ▼  crates/circuit_prover + leaf_prover:电路证明(leaf)
        ▼  crates/stwo_run_and_prove_recursive_tree:
        │   circuit_multiverifier 两两配对折叠二叉树(深度 ⌈log2 N⌉),
        │   公共 padding 目标使所有节点同形,奇数节点向上携带
        ▼  stwo_cairo_verifier/(Cairo 程序 stwo_circuit_verifier):
            根证明由 Cairo verifier 消费(链上/最终验证入口)
```

关键资产与状态:

| 资产 | 位置 | 状态 |
| --- | --- | --- |
| 电路级 STARK verifier | `crates/stark_verifier/`(merkle/circle/channel/fri_proof/constraint_eval) | 在库,配 `proof_from_stark_proof` 桥(stwo `ExtendedStarkProof` → 电路格式) |
| cairo-verifier 电路 | `crates/cairo_verifier/`(消费 `cairo_air::CairoProof`) | 在库 main;CPU-AIR 版 Cairo verifier 程序已冻结到 `cairo-verifier-frozen` 分支(README 注明) |
| 递归树折叠 | `crates/stwo_run_and_prove_recursive_tree/` | 在库,带 e2e 测试 + registry JSON(`test_data/circuit_registry.json`) |
| 电路 registry 参数 | `leaf_prover/tests/data/circuit_registry_canonical_small.json` 等 | 在库(`circuit_params --registry` 产物) |
| 端到端示例 | `crates/stark_verifier_examples/`(simple AIR → 电路验证 → 篡改负例) | 在库,可作参考实现 |

工程量评估:leaf_prover / recursive_tree 需要编译整个 circuit 栈
(circuits DSL + circuit_prover + cairo-vm),且 registry 必须覆盖我方
trace log size 的 cairo-verifier 电路条目;这是**生产聚合管线**
(SHARP/SNIP-36 aggregation 同型),不是一次 session 的 spike 范围。

### 1.2 stwo 上游(Lambdaclass/crates.io 2.3.0)

- `stwo` 2.3.0 **无内置递归组件**(src 只有 core/prover/tracing,无
  recursion 模块);原生 AIR 递归(在 M31 电路里验 FRI/Merkle/DEEP)
  上游仍在路上。
- stwo-cairo 官方 README 给出的递归 = **Cairo verifier 程序**
  (「Verify a proof inside Cairo (recursive)」)——即 §1.1 的栈,
  递归支持点在 Cairo 程序层,不在 stwo AIR 层。

### 1.3 Cairo 路线可用的两个递归层次

| 层次 | 机制 | 成本 | 适用 |
| --- | --- | --- | --- |
| **L1 程序级递归信封**(bootloader 型) | 一个 Cairo 程序跑 N 个 hand_verify + **电路内重算承诺链**(prev_acc → new_acc),链式复用(layer k+1 输入 = layer k 证明输出) | ≈ 证明固定成本 + N×边际(EC_OP 步数线性) | 批聚合摊薄 + 递归链绑定;**本 spike 采用** |
| **L2 证明的递归验证**(§1.1 全栈) | cairo-verifier 电路验证 CairoProof → leaf → 树折叠 → Cairo 根 | leaf ≈ 数十倍 Cairo 步数 + 电路栈工程 | 第三方聚合服务/最终根证明 |

选型理由:L1 正是执行计划 P3.3(ADR-2026-09-06-1)的形态——
「hand_batch σ 折叠校验并进电路;`p_batch_commitment` 由电路内部重算
(批次词为电路输入),绝不作外部断言」。信封把该公式推广为多层:

```
digest_i = poseidon([payload_len] ++ payload_i)              (host payload_digest 同构)
claim_i  = poseidon([hand_binding_i, digest_i, n_own, n_reveal, n_leave, n_recon])
new_acc  = poseidon([prev_acc] ++ claim_1 … claim_N)
```

- EC 残差经 **EC_OP builtin 进 trace**(真验证,可转移健全性,形态② 同源);
- 承诺链在电路内重算(批次词是程序输入,链上/验证方只需验证明 + 读公开输出);
- 任一任务验证失败 → panic → **该批次无证明**(fail-closed,延续「未实现/
  未通过语义必须拒绝而非跳过」纪律);
- 链式:layer k+1 的 `prev_acc` = layer k 证明的公开输出 → proof-carrying
  data 链,最终一份证明锚定整条链的累计语句。

### 1.4 tagged proof 对照(Cairo 侧有无对应物)

本项目 stwo 侧的 tagged proof = `src/texas_tagged.rs` 的**规范异构转移批
AIR**:行由 method-kind tag 选择子(tagged selector)驱动,一行一个
(pre, post, action) 转移,批量异构转移共用一棵 FRI。

Cairo 侧**没有** AIR 选择子机制,功能对应物分两层:

1. **调度层**:程序内 tag dispatch——tag felt 驱动 while/match 分支
   (hand_verify.cairo 的 header counts 分派 ownership/reveal/leave/recon
   即此模式);Cairo VM 顺序执行,无需选择子/自由旋转技巧。
2. **绑定层**:stwo tagged proof 靠 Fiat–Shamir 混入 claim 绑定语义;
   Cairo 侧对应物 = **program hash + 公开输出**(fact-registry 路线)或
   **SNIP-36 proof_facts**(协议内路线)——即「哪个程序在什么输入下产出
   什么输出」由证明的公共段绑定,tag 语义退化为程序逻辑。

生态里无 "tagged proof" 术语(zksecurity 对 stwo-cairo 审计报告中的
"tagged relations" 指 LogUp 关系 ID,是另一回事)。

## 2. 本 spike 交付(Cairo 路线递归信封)

- `cairo/src/recursion.cairo`:递归信封 executable(独立 crate root,
  与 form-② 的 lib.cairo 并存,共享 `dual/` 验证器模块)。
- `src/recurse.rs`:host 驱动——任务铸造 → host 直验(form-① 同款)→
  期望承诺链 host 重算 → prove-hand 逐层出证 → **cairo acc == host acc
  对拍(公式 parity 门)** → 独立复验(--check-only)。
- 负例:篡改任务 → 程序 panic → 无证明;错误 prev_acc → 链对拍失败。
- CLI:`recurse`(功能往返 + 2 层链 + 负例)、`recurse-perf`(性能矩阵)。
- 测试:`tests/recurse_test.rs`(`#[ignore]` + release 门,同 compose_test)。

## 3. 生产升级路径(不在本 spike 范围)

1. **L2 全栈**:用 `leaf_prover` 把 proving-tool 的 proof.json 折成 leaf
   (需 circuit_params 生成覆盖我方 trace log size 的 registry JSON),
   `stwo_run_and_prove_recursive_tree` 折 N 个 leaf → 根 →
   `stwo_cairo_verifier` 消费。收益:O(1) 根证明;成本:电路栈集成 +
   每 leaf 一次 cairo-verifier 电路证明(约为原证明 10–100× 步数,
   参照主项目 PERFORMANCE_V2_PROTOCOL §4 的 admission STARK 量级)。
2. **SNIP-36 形态**:P3.1 `starknet_proveTransaction` 落地后,L1 信封
   程序即为 create_proof 入口的被证明对象;L2 即 SHARP 式聚合服务。
3. **GPU**:icicle 后端(vendored stwo 2.3 未带,评估 ~1–2 周)大批次
   唯一可行路径(参照 cairo-route-optimization.md 的相位分解)。

## 4. 性能实测(2026-09-06,M3 Pro 12 核,release)

生产参数(canonical_small + fast FRI pow16/q40),任务 = 2 人满手
(2 own + 18 reveal + 1 leave + 1 recon = 43 EC 方程),`recurse-perf`
实测:

| 任务数/层 | EC_OP | steps | compile | run/witness | prove | 总 wall | 复验 | 证明 |
|---|---|---|---|---|---|---|---|---|
| 1 | 128 | 24,699 | 1.5s | 0.4s | 2.6s | 4.6s | 39ms | 13.7 MiB |
| 2 | 256 | 49,239 | 1.5s | 0.4s | 3.5s | 5.5s | ~40ms | 13.8 MiB |
| 4 | 512 | 98,328 | 1.5s | 0.5s | 5.9s | 8.0s | ~40ms | 13.7 MiB |
| 8 | 1,024 | 196,506 | 1.5s | 0.6s | 10.4s | 12.6s | ~40ms | 13.9 MiB |

读数:

1. **证明尺寸与任务数基本无关**(13.7→13.9 MiB,+1.5%)——SNIP-36 成本
   结构基石(「批聚合摊薄单位成本」)在 Cairo 递归信封上成立;
2. **批摊销 2.9×**:8 任务合封 12.6s vs 8 份独立证明 ≈ 36.8s;
   prove 边际 ≈ 1.1s/任务,固定 ≈ 1.5s(compile 1.5s + FRI 固定层);
3. **递归链线性**:2 层 × 2 任务链总 11.7s(≈ 2× 单层),链承诺
   genesis → acc₀ → acc₁ 每层 host parity 对拍 ✓,独立复验 ~40ms/层;
4. **负例 fail-closed**:篡改任务 → Cairo panic 无证明;伪造 prev_acc
   (跨层拼接)→ parity 门拒绝,两种攻击路径均无证明产出;
5. 对照:同 2 人手 form-② 单独出证(基线参数)22.2s → 信封生产参数
   4.6s(含 compile),证明尺寸同为 ~14 MiB JSON(二进制格式可再减)。

**边界**:L1 信封聚合的是「验证义务」(同一信任域的批次合并 + 链式
绑定),不是证明压缩;跨信任域的 O(1) 根证明仍需 §3 的 L2 全栈
(cairo-verifier 电路 + recursive tree)。

## 5. 复现

```bash
cd proving-tool && cargo build --release   # 一次
cd ../hand-verify-native
cargo test --release --test recurse_test -- --ignored --nocapture
cargo run --release -- recurse            # 功能往返 + 负例
cargo run --release -- recurse-perf       # 性能矩阵
```


## 6. texas 集成（2026-09-06，form-③ → 结算路径）

递归信封已并入根 workspace（`hand-verify-native` 成为成员，运行时仍依赖
proving-tool 的 prove-hand 二进制），并接入 texas 结算路径：

- **挑战域 v3**：动作签名挑战升级为 felt 直通
  `poseidon([label, table_id, hand_id, seq, action_felt, amount, R_x, R_y])`
  （`poker-protocol-core::stark_curve::action_sig_challenge`），与
  ownership/reveal 挑战同构——Cairo 端 `hand_verify.cairo` 的 action 桶
  （kind=5，词条 10 词）原生复刻，无字节级操作。v2 字节域未上生产即被
  取代；跨 crate 对拍测试
  （`action_sig_challenge_matches_protocol_core`，dev-dep
  poker-protocol-core）钉死 raw ≡ core 标量（mod n）。
  教训：types-core 的 `Felt::from_raw` 是 Montgomery limbs 语义——
  常量 felt 必须走 `from_bytes_be`（对拍测试抓出）。
- **签名留存**：`ActionLogEntry.sig: Option<ActionSig>`——验签成功即落
  签名本体（此前验完即丢），是本批次的数据源；auto 代打为 None。
- **snip36 模式**（`STARKNET_SETTLEMENT_MODE=snip36`）：牌局结束 →
  每参与者首条已签名动作组 action-sig 批次（header 6 词尾槽 n_action）
  → 异步出证（`spawn_blocking` + prove-hand）→ host parity 门 →
  acc/proof 落盘 prover_work_dir → v3 双门入口提交（随 cairo ≥2.12
  合约上链后激活）；证明失败自动回退 legacy 结算，结算永不阻塞。
  非 snip36 模式（legacy/v2）不启动任何证明进程。
- **端到端**：`recurse` 全绿（主链 2 层 × 2 任务含 n_action=2、
  EC_OP 256、parity ✓、负例语料 tampered/wrong-prev 均拒）。
- ⚠️ **已知间歇问题**：cairo-lang executable 编译/运行存在偶发的
  `ASSERT_EQ failed: 0 != 1 @ pc=0:17`（同代码同输入时绿时挂，重跑即
  复绿）——疑似编译器或 runner 的非确定行为，与改动内容无关；正式
  环境需固定编译器版本并做双跑校验（记录待查）。
