# T3-FRI Wrap 设计（冻结）

日期：2026-10-02 · 分支 feat/prove_perf · HEAD 7d74c47c
目标：把 groth16-wrap 从「operator endorsement + circuit consistency」（`wrap_circuit.rs:23-29`
如实声明的信任边界）升级为**电路内验证 STARK 的 PCS/FRI 层**，对齐 SP1/RISC Zero 的
工业包裹配方（只装查询层 + SNARK 友好哈希 + 域对齐），最终 Groth16 上 Monad。

## 0. 为什么这条路线比预想便宜（侦察结论）

- **hand-verify-native 的 fold 证明已经用 `Poseidon252MerkleHasher` + `Poseidon252Channel`
  承诺与派生随机性**（`prove.rs:8-17,60-64`）——无需“重建 Poseidon2 承诺树”，承诺层
  原生就是 SNARK 友好的。FS 通道本身也是 Poseidon（starknet Hades），查询索引与折叠
  α 可以完整在电路内重推导。
- **无仿真算术**：felt252（STARK prime ≈ 2^251）< BN254 Fr r；QM31 的每个 M31 坐标
  < 2^31。所有值都可作为 BN254 Fr 的原生元素。唯一例外是 M31 乘法**约减 mod 2^31−1**
  ≠ Fr 乘法 → 用约束 gadget（ab−c=k·M + k 范围检查）实现，见 §3。
- **Merkle 内部节点 = `poseidon_hash(left,right)` 纯单 permute**（vcs_lifted/verifier.rs
  的 `hash_children`）；列值只在叶子进入（`update_leaf` sponge）。17 列 trace 叶子 =
  3 个 packed felt。
- **最后一层是常数**：`FriConfig::new(0,1,30,1)` → `log_last_layer_degree_bound=0`，
  末层多项式长度 ≤1（单个 QM31），末层检查退化为常数相等。
- 复用现有资产：`poseidon.rs`/`poseidon_circuit.rs`（与 starknet-crypto 0.8 逐位对拍）、
  `felt.rs`、seeded setup/prove/verify（`lib.rs`）、Solidity 导出（`gen-sol*`）。

## 1. 验证的语句（电路内强制）

公开输入（BN254 Fr 元素）：
- claim：`hand_binding`、`payload_digest`、`cairo_program_hash`（felt252）、counts×4、
  `log_size`；
- 承诺根：trace 树根、quotient 树根、FRI 第一层根 + 14 个 inner 层根
  （preprocessed 空树根为协议常数，硬编码）；
- 末层多项式：1 个 QM31 = 4 个 M31；
- OOD `sampled_values`（per tree per column，展平为 QM31 序列）；
- PoW nonce（u64）；
- 查询位置：30 个（去重后不足则哨兵填充，哨兵 = 2^log_domain）。

电路约束（全部在 BN254 Fr 上）：
1. **FS 通道重推导**（Poseidon252Channel 逐位复刻）：claim `mix_u32s`（29 词 →
   5 felt，含 length-padding 位）、`mix_root`×3（PCS 树）、`mix_felts`(OOD)、
   `random_coeff`/16 个折叠 α 的 `draw_secure_felt`（252-bit 分解 → 4×M31）、
   PoW 前导零检查 + `mix_u64`、`draw_u32s` 抽 35 词 → mask 出查询位置并与公开
   位置做多集合匹配 + 严格递增检查（等价于 stwo 的 BTreeSet sort+dedup）。
2. **Merkle 路径**：trace/quotient/FRI 每层树，每查询从叶子 `update_leaf` sponge
   （M31→8-limb 打包 + 余块 length-padding）逐层 `poseidon_hash(l,r)` 上行，
   hash_witness 为见证，对齐公开根。
3. **首层 RLC 绑定**（pcs/quotients.rs `fri_answers` 复刻）：trace/quotient 列在查询行
   的值（Merkle 验证过）经 random_coeff 随机幂 + OOD 商常量累积，必须等于 FRI 第一层
   叶子值。
4. **折叠链**：`fold_circle_into_line`（α₀，circle→line）→ 逐层 `fold_line`
   （ibutterfly + αᵢ）→ 末层常数 == 末层多项式。域点及其逆为常数（综合期算好）。
5. **M31 乘法 gadget**：`c = ab mod (2^31−1)`，见证 `k = ⌊ab/M⌋`，约束
   `a·b − c = k·M` 且 k、c 均 < 2^31（位分解）。QM31×QM31 / CM31 常数乘按
   stwo `qm31.rs` 公式展开。

## 2. 信任边界（如实声明，v1）

**电路内证明**：给定这些公开承诺与 OOD 应答，存在一条完整的 FRI 打开链：
承诺绑定（Merkle）+ 低调式（折叠链收敛到声明的常数）+ FS 派生（查询/α 全部电路内
重推导，无外部可信随机数）+ trace 行值与首层的 RLC/商公式一致。

**残留信任（stage-2，明确不在本电路内）**：OOD 应答本身满足 fold AIR 的约束系统
（`sampled_values` 的正确性）。即：电路证明“这是对已承诺 trace 的合法 FRI 打开”，
不证明“trace 满足牌局 AIR”。OOD 应答作为公开输入被通道绑定（改它们会改变全部
查询位置），stage-2 在电路内加入 fold AIR 的 OOD 点约束求值（17 列行局部约束 +
循环累加器，估计 <100k 约束）。此前 wrap_circuit 的“运营方可包装任意格式良好
output”这一缺陷被消除；运营方 residual 只剩“OOD 求值正确”这一可审计小面，与
链下 fact-verify（stwo 全验证）互为冗余。

**trusted setup**：沿用 `SETUP_SEED` 单方仪式（测试网口径，主网需 MPC）。

## 3. 成本估算（K=64，log_size=15，n_queries=30）

| 项 | 数量 | 约束估算 |
|---|---|---|
| Merkle permutes（trace 16 + FRI L0 16 + Σ15..2≈119）×30 查询 | ~4.6k | ~1.7M |
| 叶子 sponge（17 列 trace / QM31 FRI 层，每查询每树一次） | ~500 | ~0.2M |
| M31 gadgets（折叠链 + 商累积，~9 mul/QM31-mul） | ~2k mul | ~0.3M |
| 通道 permutes + 位分解（21 次 252-bit） | ~120 | ~0.1M |
| **合计** | | **~2.3M** |

对比现有单手 wrap（4.58M 约束、prove 31.9s）更小。gas：公开输入 ~100-150 Fr →
参照现有实测（216k local / 1.05M Monad @ 18 公开），预计 Monad ~2-3M/批，
K=64 摊薄 ≈ 0.0005 MON/手量级，与 T3 预算一致。

## 4. 实现与验证方法（双实现 + 差分）

- `fri_ref`：纯 Rust 参照验证器，直接以 BN254 Fr 表示 M31/QM31/felt252（与电路同一
  算术面），从 stwo `StarkProof` 提取见证；**对拍 stwo `verify`**（同输入同判定）+
  stwo 官方测试向量（`poseidon252_merkle.rs` 两条 hash_node 向量）钉哈希。
- `fri_circuit`：arkworks R1CS，与 `fri_ref` 同构；差分测试 ref vs circuit；
  篡改负例（叶值/路径哈希/α/根/末层常数各一类）。
- 真实证明源：`hand-verify-native::prove::prove_claim` 现场生成（小实例 E2E +
  K=64 性能实例）。
- E2E：Groth16 roundtrip → `gen-sol` 导出 → anvil `verifyProof`（金向量）+
  篡改 calldata 反例。
- 性能测试（验收口径）：提取 / 电路综合 / Groth16 prove / verify / 约束数 /
  公开输入数，小实例与 K=64 双档，输出 `out/t3-fri-wrap-report.md`。

## 5. 线格式

`FriWrapWitness`（serde JSON）：config、claim、trees[2]（roots+列 log sizes+查询行+
路径节点序列）、fri（15 层 roots+α+查询叶值+路径）、last poly、ood、pow_nonce、
queries(30)。所有 felt252/QM31/M31 均以十进制字符串表示的 Fr 元素，参考与电路
共用同一套解析。
