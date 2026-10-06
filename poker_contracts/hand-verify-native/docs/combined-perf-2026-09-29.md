# Combined 证明性能实测（2026-09-29）

> 合并信封（P 层递归 + settlement 语句，一次 FRI 统一采样）的真实出证性能矩阵。
> 方法：`tests/combined_perf.rs`（`#[ignore]`）直调 `prove_combined_layer`（与
> CLI/生产同代码路径），4 配置 × 冷+热 3 次，外部 `/usr/bin/time -l` 采
> 进程树 max RSS；每次运行断言 acc 确定性（同配置三次 acc 逐字一致 ✓）。
> prove-hand：proving-tool release（79M，2026-09-29 build）。本机：Apple
> Silicon，多线程 prover（user 167s / wall 33s，≈4-5 核并行）。

## 矩阵

| 配置 | 动作语句 | 参与者 | steps | prove_ms（3 次） | 全程 wall | ec_ops | 证明大小 | 峰值 RSS |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| s2p3（基线） | 2 | 3 | 7,204 | 10,736 / 8,402 / 10,850 | 11.3–11.7s | 16 | ~21.0 MB | **12.00 GB** |
| s8p3 | 8 | 3 | 11,452 | 9,581 / 9,179 / 8,575 | 9.3–10.4s | 16 | ~21.1 MB | 12.32 GB |
| s2p8 | 2 | 8 | 7,451 | 10,449 / 9,305 / 11,225 | 10.0–12.0s | 16 | ~21.0 MB | 11.32 GB |
| s32p8（压测） | 32 | 8 | 28,691 | 9,647 / 10,737 / 9,864 | 10.4–11.5s | 64 | ~21.0 MB | **12.57 GB** |

固定开销（可忽略）：cairo_run ≈0.5s、check-only 复验 ≈0.05s、程序编译 **0ms**
（prove-hand 全局缓存，编译一次后免费）。cairo_acc 跨运行确定性 ✓。

## 发现

1. **出证时间对 steps 不敏感（桶内常数）**：steps 4×（7.2k→28.7k）prove 时间
   仍 ~10s——证明时间由固定 trace 桶的 FRI 主导，实际 steps 只消耗桶内行数。
   含义：**桶上限内（canonical_small 2^20 ≈ K≤195 手）边际手近乎免费**——
   把多手装进一份合并证明的批量化，是时间维度上几乎白拿的优化。
2. **内存是硬约束：峰值 RSS 11.3–12.6 GB**——**超过 stark 服务器 7.3G**，
   也超本轮定的 6G 隔离预算。合并证明的出证宿主需要 ≥16G 内存专机（或
   prover 内存优化/分段）。这推翻了「合并证明 2.2–2.9s/轻量」的旧口径
   （那是分离路径 settlement_private 小电路的数字）。运维决策项，非代码缺陷。
3. **证明 ~21MB 且桶内恒定**：对链上锚定的含义——终证上链走的是 stark-recursion
   折叠链的 EVM 友好终证（keccak 通道），21MB 是叶级 Stwo 证明的离线形态，
   不直接上链；但存储/传输成本要计入 prover ↔ settlementd 链路。
4. ec_ops 随动作语句线性（16→64），对时间无感（同上，桶内）。

## 结论

- **时间**：~10s/手（桶内常数）→ K 手批量摊销后每手趋近 10s/K；加上
  stark-recursion 叶/折叠链（K=64 @ 3.69 GiB / keccak 通道）的内存安全形态，
  递归聚合的经济性成立。
- **内存**：合并证明出证必须落在大内存 prover 机（≥16G）。stark 服务器现状
  不可跑合并腿——与「递归聚合在 stark、叶子出证在大内存机」的分工冲突，
  需要运营决策：要么 prover 机升配，要么合并腿移出 stark。
- **确定性**：同输入三次出证 acc 逐字一致，生产可安全用作链锚。

## 内存优化实测（同日追加，canonical_small 通道）

根因修正：大内存不是单一 2^20 垫高点，而是 **Canonical 预处理迹**（543M cells /
161 列 / 域 2^26，preprocessed_trace.rs:20 `MAX_SEQUENCE_LOG_SIZE=25`）叠加
range_check_20 全值表（语义耦合，log_size=20 编译期常量，**不可收缩**）。
换用 CanonicalSmall pp 变体（域 2^21，`prove-hand --trace-log-size auto` 或
`--params params/canonical_small.json`）后：

| 端点 | 默认 Canonical | canonical_small | 加速 | acc |
| --- | ---: | ---: | ---: | --- |
| s2p3 | 10.76 GiB / ~10-18s | **2.01 GiB**（亲验 1.98）/ 1.8-7.9s | **5.4× 内存，3-5× 速度** | 逐字相同 |
| s32p8 | 11.04 GiB / ~11.6-13.3s | **2.41 GiB** / 2.7-3.5s | 4.6× 内存，4× 速度 | 逐字相同 |

- 安全度量不变（pow26+70q×blowup1 = 96 bits）；verify 从 proof 读 pp 变体与
  PcsConfig（verifier.rs:263,281），内部 verify + check-only 双验通过。
- 生产批腿（L1 终证）早已钉扎同一参数集——非新增安全假设。
- 注意：优化腿的 proof 字节与默认腿不同（pp 变体进 claim），消费方须钉扎同
  参数集；acc/公开输出/program_hash 不变。
- fork（third_party/proving）零改动（git diff 为空）——默认路径逐字节不变。
- 运营影响：合并证明出证 **2.0–2.4 GiB，stark 服务器（7.3G）与 6G 隔离预算
  现在都装得下**，§发现-2 的大内存专机决策不再必要。

复现：`prove-hand --trace-log-size auto`（等价 `--params canonical_small.json`）；
perf 端点 `perf_s2p3_csmall` / `perf_s32p8_csmall`。

## 复现

```bash
cd poker_contracts
cargo test --release -p hand-verify-native --test combined_perf perf_s2p3 -- --ignored --nocapture
# 每配置独立进程（外部 time 采 RSS）；4 个配置：perf_s2p3 / perf_s8p3 / perf_s2p8 / perf_s32p8
```

依赖：`cd proving-tool && cargo build --release`（prove-hand）。
