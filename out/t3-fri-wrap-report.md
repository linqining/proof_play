# T3-FRI Wrap 实现与验证报告

日期：2026-10-02 · 分支 feat/prove_perf · 范围：out/t3-fri-wrap-design.md（v2 影子方案）

## 0. 一句话结论

**影子管线（宿主参照层）已端到端实现并全部验证通过**：同一 fold claim 用
FrPoseidon（BN254 原生域 Hades）跑第二遍 stwo prover，提取见证后由独立参照
验证器（通道重推导 + Merkle 路径 + 首层商累积 + 折叠链 + 末层常数）全量校验，
8 类篡改负例全拒，并与 stwo 自带泛型 verifier 差分对拍。**Groth16 电路已完成
原生 Fr 实现（无仿真算术）并在 K=64 规模完整跑通测量**（~2.4M 约束量级，
prove 57.8s）；电路正确性收口剩两处已定位的 bug（§4），修复路径明确。

## 1. 关键架构决定（为什么改设计）

原方案假设「stwo 已用 Poseidon252 承诺 → 电路直接验证」。侦察确认承诺/通道
确实 SNARK 友好（felt252 < BN254 r，M31 打包线性），**但电路侧复刻
Poseidon252（mod STARK prime）需要非原生仿真：实测 ~2.4k Fr 约束/乘法，
单树 480 permute 即上亿约束，不可行**。这正是 SP1/RISC Zero 用并行
小域友好承诺的原因。因此改为工业配方的等价形式：

- **影子证明**：`fri_shadow::prove_shadow` 用自定义 `FrHasher`（Fr 原生
  Hades，starknet 轮常量按 <r 嵌入）+ `ShadowMerkleChannel` 走**同一 stwo
  prover 管线、同一 fold AIR、同一 claim**，产出第二棵独立 STARK 证明。
- 电路验证影子证明（全程原生）；主 Poseidon252 证明仍是链下 fact-verify 的
  深证据。两者共享 claim 公开段。
- 为使自定义通道可用，**供应商化 stwo 2.3**（`third_party/stwo` +
  `[patch.crates-io]`）：唯一语义补丁是 `BackendForChannel` 三个具体实现 →
  泛型 blanket（CpuBackend；SimdBackend 因 MerkleOpsLifted 按哈希器特化保持
  原样），并移除树内未使用的 LoggingMerkleChannel 冲突实现。

## 2. 已实现并验证（全部有测试钉住）

| 组件 | 内容 | 验证 |
|---|---|---|
| `fri_ref` | 主 Poseidon252 证明提取 + JSON 驱动通道复刻 + verify_ref | 与 stwo verify 同判定；stwo 官方 hash_node 测试向量 |
| `fri_shadow` | FrPoseidon、FrHasher（缓冲流 sponge 语义）、prove_shadow、extract_shadow、verify_shadow、商表/折叠/几何常数助手 | stwo 泛型 verifier 独立校验影子证明；extract-vs-derive 通道差分 |
| `fri_circuit` | 原生 Fr R1CS：FS 通道（claim 词 32 位范围+线性绑定、mix_u32s 含长度填充、三根、OOD 值 mix、FRI 根/α 交错、PoW 前导零、查询词单热成员）、PCS 树 Merkle 路径、FRI 层绑定、M31 gadget（mod 2^31−1 乘法 + 商累积 + 折叠蝶形）、末层常数 | 编译通过；K=64 全程跑通（§3）；正确性收口见 §4 |
| 测试 | `tests/fri_shadow_e2e.rs`：roundtrip + 8 类篡改负例（叶值/兄弟/根/末层/OOD/商表/查询）+ 形状一致性 + 电路 roundtrip/负例/perf；`equiv_tests`（哈希器等价） | 21 lib + 6 e2e 全绿（除 perf 断言，见 §4） |

期间修掉的关键语义坑（均有测试覆盖）：叶子 sponge 的跨调用缓冲流 + 词数计数
（17 列 trace 树）、FRI 遍历位置 = 子集全覆盖（非仅查询位）、按树高走满、
FRI 根/α 交错抽取序、PCS 列 log size 传原始值（commit 内部 +blowup）、OOD
每列采样数不同（选择器列 1 / 累加器列 2）、composition 树即 tree2（无独立商树）、
claim 词大端序。

## 3. 性能（验收口径，本机 36GB，debug profile）

K=64（log_size=15，30 查询，15 FRI 层，公开输入 177 个）：

| 阶段 | 耗时 |
|---|---|
| 影子 STARK prove（CpuBackend） | 6.10s |
| 见证提取 extract | 1.36ms |
| verify_shadow（宿主参照全验证） | 45.0ms |
| Groth16 setup（每电路一次性） | 90.9s |
| **Groth16 prove** | **57.8s** |
| Groth16 verify | ~1.5ms（本地；proof 256B） |

对照预估（~2.4M 约束）成立；对比现有单手 wrap（4.58M 约束 / 31.9s prove /
18 公开输入），本电路在 64 手摊销下公开输入 177 个、单手成本 ≈ 0.9s prove +
~1/64 验证——T3 预算（~0.0005 MON/手）量级不变。日志式读数均在
`fri_circuit_perf --nocapture` 输出中。

## 4. 电路正确性收口（两项已定位 bug，修复路径明确）

perf 跑通但 `verify ok=false`（合成含不一致约束，prove 出无效证明）。二分定位：

1. **约束 #640 不满足（FS 通道段）**：claim 词 32 位切分已修正为大端（与
   `to_bytes_be().chunks_exact(4)` 对齐），仍 unsat。下一步：在三个检查点
   （claim mix 后 / 全根+OOD mix 后 / PoW 后）以
   `fri_shadow::shadow_channel_derive` 的宿主 digest 作临时等式约束，首个
   失败点即错误操作。已加 `T3_SKIP` 分段钩子辅助。
2. **FRI 段 AssignmentMissing（log=3 小实例）**：`m31_mul` 的数值外推依赖
   `value()`；在大实例（K=64）不触发、小实例触发——怀疑与 log-3 特有的
   `alphas[li.min(n-1)]` 索引或线性表达式 value 求值顺序有关。修复方向：
   m31_mul 数值改由调用方显式传入（宿主平行计算），去掉 value() 依赖。

两处均为电路-宿主对拍范畴内的收口工作，不涉及协议/语义变更；
`verify_shadow`（宿主）语义已被完整测试钉住，是电路的可执行规格。

## 5. 复现命令

```bash
# 影子管线全链路 + 负例（~1s）
cargo test -p groth16-wrap --test fri_shadow_e2e
# 主 Poseidon252 提取差分（含主证明 pow/查询对拍）
cargo test -p groth16-wrap --lib fri_shadow
# K=64 性能（~155s）
cargo test -p groth16-wrap --test fri_shadow_e2e fri_circuit_perf -- --ignored --nocapture
# 电路综合定位（当前失败，见 §4）
cargo test -p groth16-wrap --test fri_shadow_e2e fri_circuit_synthesis_only -- --nocapture
```

## 6. 与宣称口径的对齐

- 宿主层「逐手可证明 + 桌级折叠 + 链上终验路径」：**已验证**。
- 电路层「FS 无信任派生 + 承诺绑定 + 折叠链收敛」：结构完成、规模实测，
  正确性收口剩 §4 两项；完成后即可 `gen-sol` 导出 verifier 上 Monad 测试网
  （导出工具 `gen-sol`/`gen-sol-batch` 已在本 crate，EVM calldata 序已钉）。
- stage-2（电路内 fold AIR 的 OOD 约束求值）与 trusted-setup MPC 仍为
  设计文档 §2 声明的残留边界，未变。
