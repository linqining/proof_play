# Cairo 路线性能优化报告（prove-hand 管线）

> 2026-09-06 实测，M3 Pro（12 核），release，96-bit 基线 = stwo-cairo 生产默认
> （pow_bits=26，n_queries=70，blowup=1）。基准程序：hand_verify_bench
> （148 EC ops ≈ 1 手；medium 740 ≈ 5 手；full 1,480 ≈ 10 手）。

## 成本模型（实测拟合）

```
prove(参数, n手) ≈ fixed(参数) + marginal(参数) × (n − 1)

baseline: fixed 13.63s, marginal 1.35s/手   （30.6 µs/step，9.1 ms/EC op）
fast:     fixed 12.08s, marginal 1.19s/手   （pow_bits 16，queries 40）
ultra:    fixed 10.04s, marginal ~1.0s/手   （pow_bits 10，queries 30）
```

fixed = stwo-cairo 的 preprocessed trace + 组件 setup + 小 trace 的 FRI 层；
marginal = 30.6 µs/step × ~44k steps/手。

## 杠杆 1：批摊销（最大杠杆，零代价）

固定成本 ~12–13.6s 与手数无关——**多手合入一个 Cairo 程序证明**即摊薄：

| 批大小 | 参数 | prove 总时 | **每手摊销** | 数据 |
|---|---|---|---|---|
| 1 | baseline | 13.63s | **13.6s** | 实测 |
| 5 | baseline | 17.15s | **3.4s** | 实测 |
| 10 | baseline | 25.75s | **2.6s** | 实测 |
| 10 | fast | 22.80s | **2.28s** | 实测 |
| 40 | fast | ~58.5s | **~1.5s** | 线性模型外推 |
| 64 | fast | ~87s | **~1.4s** | 外推 |

验证端不受批大小影响（9–10ms 恒定）。

## 杠杆 2：证明器参数调优（`--params` JSON）

| 参数档 | pow_bits | n_queries | 相对基线 | 适用 |
|---|---|---|---|---|
| baseline | 26 | 70 | — | 生产默认（~96-bit 安全惯例）|
| fast | 16 | 40 | **−11%**（13.63→12.08；full 25.75→22.80） | 安全评审后的生产下限 |
| ultra | 10 | 30 | **−26%**（13.63→10.04） | 仅内部审计件，需安全评审 |

verify 全部通过且恒定 9–10ms。**减参数 = 减 FRI 查询与 PoW 健全性预算**，
任何生产降档必须过安全评审并写明目标安全位数。

## 其他已排除/次要项

- witness 生成（0.076–0.6s）与 prove 流水线重叠后不可见；
- rayon 并行已预热（否则单线程慢 ~8×，prove-hand 已处理）；
- `store_polynomials_coefficients` / lifting_size_policy 变体：对 prove 无感；
- GPU（icicle/CUDA 后端）：Apple Silicon 不可用，x86 + NVIDIA 环境另测。

## FRI/承诺层相位分解与缓存可行性（prove 内部 span 实测）

10 手批（full，prove_cairo busy 25.0s）逐相位：

| 相位 | busy | 可跨证明缓存？ |
|---|---|---|
| cairo run + adapt | 0.52s | 否（每批不同输入）|
| Write Preprocessed trace | ~0s | 是（布局纯函数）|
| Precompute Twiddles | 0.077s | **是**（域大小纯函数）|
| **Compute preprocessed trace commitment** | **5.38s**（Extension 1.12 + Merkle 3.43） | **是（布局 × builtin 段大小决定）** |
| Write Base trace | 3.63s | 否（witness）|
| Compute base trace commitment | 2.56s | 否（witness）|
| Write interaction trace + commitment | 4.03s | 否（witness）|
| Prove STARKs（Composition 4.95 + OOD 1.05 + FRI quotients 0.42 + commit 0.13 + Grind 0.17） | 7.05s | 否（witness）|

**结论**：
1. FRI 的计算主体（折叠/查询，7.05s 内）依赖 witness 多项式——**不可缓存**；
2. 但 **preprocessed 承诺层 5.38s + twiddles 0.08s ≈ 5.46s 是布局纯函数，完全可缓存**——且实测它随 trace 大小增长温和（1 手 4.12s → 10 手 5.38s，+30%），缓存在任何批大小下都值 ~5.4s/证明；
3. 实现前提：需要给 stwo-cairo prover 加"外部注入 preprocessed provider"接口（当前 prove_cairo 每次内部重建），按 (program hash, trace log sizes, params) 做缓存键，序列化 Merkle 树——工程量 ~1–2 天（含序列化格式与失效逻辑），非科研风险；
4. 收益矩阵：1 手批 −40%（13.6→8.2s）、10 手批 −21%（25.75→20.4s，叠加 fast 参数 ≈ **1.74s/手**）、批越大绝对节省越恒定；
5. 替代方案（无需改 stwo-cairo）：**常驻证明服务**——注意仅缓存进程内 twiddles/rayon 池，preprocessed 承诺在 prove_cairo 内部仍会重建，故 daemon 只省 ~0.1s 级，**真正的 5.4s 必须走磁盘缓存或上游 API 改造**。

## 追加优化（2026-09-06 二轮）：preprocessed 瘦身 + 批甜点

**`preprocessed_trace` 瘦身**：程序 pedersen_builtin = 0，`Canonical` 变体
携带的 Pedersen 预计算表（固定尺寸）是死重。切换 `canonical_small`：

| 配置（+ fast FRI） | 1 手 | 10 手批 | 备注 |
|---|---|---|---|
| canonical（基线二轮） | 12.08s | 22.80s | preprocessed 承诺 4.12s |
| canonical_without_pedersen | **5.24s** | — | pedersen 表（固定尺寸）移除 |
| **canonical_small** | **3.02s** | **21.12s → 2.1s/手** | preprocessed 承诺 4.12s→**144ms（−97%）** |

1 手证明 **4.5×**（vs 13.63s 基线）。健全性：LogUp 表成员性 + 编译期
preprocessed ID 解析 + honest verify OK 共同保证（表更小只会让出界值无法
查找——sound by construction）。

**批大小悬崖（重要）**：30 手批（1.32M 步）出现超线性——interaction trace
Extension 22.9s（3× 步数 → 15× 时间，内存带宽悬崖）；per-step 成本 48µs →
131µs。**本机最优批 = 10 手（438k 步）**，更大批次按桌分片为多个 10 手证明
而非加大单证明。

## 建议生产配置

**生产配置（二轮定型）：canonical_small + fast FRI + 10 手批 → 2.1s/手
（相对 13.6s 基线 = 6.5×）**；1 手证明 3.02s（4.5×）。比形态①（0.1s）仍慢
~21×，但交易路径零影响，证明作为异步审计/锚定工件。原"磁盘缓存 preprocessed
承诺"路线图已被瘦身取代：canonical_small 下该层仅 144ms，缓存收益趋零；
仅当未来批次必须 >50 万步时才重新评估（届时先解决内存带宽悬崖）。

## 复现

```bash
cd proving-tool
./target/release/prove-hand --scale medium --out-dir /tmp/m \
  [--params /tmp/cairo-opt/params-fast.json]
```

参数档样例：`/tmp/cairo-opt/params-{fast,ultra}.json`
（schema 见 `proving-tool/src/main.rs::default_params`；注意枚举值为小写
`blake2s`/`canonical`/`auto`）。
