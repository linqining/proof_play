# Performance — current measured record

> **Authoritative performance record.** Supersedes and replaces the former
> `docs/plan_d_perf.md`, `docs/PERFORMANCE_FOLLOWUPS.md` and
> `docs/plan-d-p3-metrics.md` (removed; full history in git). English is
> authoritative; the Chinese section is a mirror for convenience.
>
> **性能权威记录**。取代并合并原 `docs/plan_d_perf.md`、
> `docs/PERFORMANCE_FOLLOWUPS.md`、`docs/plan-d-p3-metrics.md`（已删除，
> 历史见 git）。以英文为准，中文为对照。

## Headline

| Claim | Number | Nature |
|---|---|---|
| Total cryptographic work per hand (shuffle proof + deal encryption + reveals + folding) | **~0.1 s class** | measured, release |
| Visible latency per hand (bet → showdown) | **< 1 s** — Web2-class table feel | derived from the above |
| Production recursive proving pipeline | **~2.2 s/hand** local (exec compile cached, 2026-09-27; server was 15–17 s incl. per-prove compile), fully async, play never waits | measured, M3 Pro |
| Full-table (9p) on-chain P verification cost | **≈ 0.25 STRK** — same order as one ordinary invoke | measured + extrapolated |

## 1. Release baseline — Stark-curve hot path (2026-09-05)

Apple Silicon, `--release`, pinned nightly.
Reproduce: `cargo test -p poker-protocol-proofs --release --test plan_d_perf -- --ignored --nocapture`

| Item | Measured | Notes |
|---|---|---|
| Scalar mul (double-and-add, 251 bit) | **19 µs/op** | acceptance threshold < 20 ms/op (playability) |
| 52-term vartime MSM | **3.4 ms** | not a bottleneck — see non-goals |
| ZK shuffle proof 52 cards — prove / verify | **44 ms / 23 ms** (cycle ~67 ms) | direct-Sigma, three-layer Schnorr |
| 52-card batch ElGamal deal encryption | **6.2 ms** | includes 52 scalar muls |
| `hash_to_scalar` (Poseidon) | **8 µs/op** | challenge derivation |
| `hash_to_curve` (try-and-increment + sqrt) | **118 µs/op** | plaintext-card domain derivation |
| 1540-term host folding (9p full-residual batch) | **2.0 ms** | on-chain EC_OP is faster than this simulation |

**Reading:** the direct-Sigma hot path finishes in milliseconds at human betting
rhythm. STARK proving never enters the interaction path — architecture claim
confirmed by measurement.

## 2. Production proving pipeline (asynchronous, off the interaction path)

| Stage | Cost | Where |
|---|---|---|
| Recursive proving (per hand, exec compile cached) | **~2.2 s/hand** local (2p batch 2.22 s / 9p batch 2.13 s, M3 Pro, cache warm; server was 15–17 s incl. per-prove Cairo compile) | `texas/src/starknet/recursion_prover.rs` (`elapsed_ms`) |
| Settlement STWO prove (`settle_hand`) | ~2 s/hand, `spawn_blocking` | `texas/src/starknet/hooks.rs` |
| State-root recomputation component (Poseidon252 v2, AIR) | **2.91 s** e2e prove+verify (~237× vs v1) | `src/poseidon252_v2.rs` |

**Exec compile cache (2026-09-27):** prove-hand caches the compiled Cairo
`Executable` content-addressed by (program source bytes, corelib path/stat,
prove-hand binary stat) under `proving-tool/.cache/exec-cache` — override with
`PROVE_HAND_CACHE_DIR` (mount on a persistent volume in containers), disable
with `--no-exec-cache`. Compile phase: 1.5 s → ~0 ms on hit; cache publishes
are atomic renames so concurrent proves only race to a no-op. Proofs are
bit-identical (same program hash → same chain accumulator, verified against
the pre-cache run).

Envelope matrix (task = full 2p hand: 2 own + 18 reveal + 1 leave + 1 recon;
M3 Pro, canonical_small + fast FRI, cache warm; pre-cache totals in parens):

| tasks | steps | prove | total (was) |
|---|---|---|---|
| 1 | 26 196 | 2.3 s | **2.9 s** (4.6 s) |
| 2 | 52 233 | 3.2 s | **3.8 s** (5.6 s) |
| 4 | 104 316 | 5.8 s | **6.3 s** (7.9 s) |
| 8 | 208 482 | 11.8 s | **12.5 s** (14.0 s) |

Regression gate: `cargo test --release --test recurse_test -- --ignored
--nocapture recursion_prod_shape` (2-seat / 9-seat action-sig batches,
parity gate + standalone reverify asserted).

**Combined envelope (2026-09-29): one Stwo proof for BOTH the P layer and
the settlement statement.** `cairo/src/combined.cairo` proves the action-sig
batch (EC_OP in trace) *and* the settlement-private statement (digest /
zero-sum / claim-cms / action-log chain) in ONE Cairo VM run — public output
16 words `[chain_acc] ++ v2-segment]`, consumed on-chain by the new
`verify_and_settle_dapv_combined_private` entry with a **single fact**
(`combined_program_hash` slot; contract snforge 114/114 incl. 4 new tests).
In-circuit binding assert: every P task's `hand_binding` == the settle
section's — one proof semantically covers "this hand's signatures AND this
hand's settlement". Measured (M3 Pro, prod params, exec cache warm):

| shape | steps | prove | total (1 proof) | vs separate |
|---|---|---|---|---|
| 2p action-sig + 3-player settle | 7 204 | ~1.6–2.2 s | **2.2–2.9 s** | P-layer 2.2 s + settlement ~2 s ≈ 4.2 s |
| 9p action-sig + 3-player settle | 12 160 | ~2.2 s | **2.85 s** | idem, one bucket up |

Regression gate: `cargo test --release --test combined_test -- --ignored
--nocapture` (honest 2p/9p roundtrip with dual parity [acc + segment] and
standalone reverify; tampered-digest and cross-hand-binding negatives).

**Bug found & fixed en route (prefix digest fold):** the standalone
`proving-tool/src/settlement_private.cairo` circuit absorbs ALL 8 player
slots into the settlement digest, while the on-chain registered digest
(contract `compute_settlement_digest` / texas `submit.rs`) folds over the
**actual** participant count — for any non-full table (n<8, i.e. almost
every real table) the circuit's `DIGEST_MISMATCH` assert fires and **no
proof exists** (fail-closed → v2 private leg silently falls back to public
linear settlement). The shared `settlement_stmt.cairo` module fixes this:
it absorbs only the trailing-zero-canonical prefix of non-zero players,
matching the on-chain formula for every n ≤ 8 (pinned by the
`combined_digest_prefix_fold_semantics` test). The stale standalone circuit
is left untouched for the v2 path as-is; migrating v2 to the shared module
is the follow-up.

Prover parameters: production file = `canonical_small` trace + fast FRI
(pow16 / 40 queries, blake2s channel). The fast tier passes the full test gate;
a dedicated security review is still scheduled before it is used for
production proofs.

**Next levers:** the prove phase is now the whole budget — fixed ~1.5–1.7 s +
~30 µs/step with no single hotspot (spread across trace generation, three
trace commitments, composition and FRI; all rayon-parallel). In rough order:
texas wiring onto the combined driver (one spawn per hand instead of two),
container CPU-quota/toolchain parity (rayon pool sizing, pinned nightly with
SIMD), Cairo step reduction inside the recursion program, GPU offload (§5).

## 3. On-chain P verification — EC_OP gas, compressed (mainnet-calibrated)

Calibration: mainnet block 14056911, l2_gas_price ≈ 3.63×10¹⁰ fri/unit;
ordinary invoke observed at **0.17–0.40 STRK**.

| Table size N | l2_gas | Mainnet cost | Note |
|---|---|---|---|
| 2 | **1.60 M** | ~0.058 STRK | felt-passthrough transcripts |
| 4 | **3.12 M** | ~0.113 STRK | |
| 9 (extrapolated, linear model 0.08 M + 0.76 M×N) | **≈ 6.9 M** | **≈ 0.25 STRK** | same order as one ordinary invoke |

Pre-compression byte-stream transcripts cost 956 M–4.15×10⁹ l2_gas (35–150
STRK) — profiling showed ~95% was byte serialization and pure-Cairo keccak, not
cryptography. Switching challenges/ρ to felt lists straight into Poseidon
(shared three-way implementation: Rust core, texas, wasm, and
`hand_batch_stark.cairo`) gave a **~600× reduction**. Horner folding removed
the ρ power table and every mod-n multiplication. Regression:
`hand_batch_stark` snforge 12/12, host parity 5/5, e2e 2/2.

**Conclusion: no STARK and no sharding needed — full-table on-chain P
verification is affordable today.** Remaining headroom: `u256_mul_mod_n` λ
computation (~5.4 M gas at N=9) could roughly halve cost again; deferred until
live data demands it.

## 4. Decided non-goals (2026-09-05 dispositions)

| Candidate | Decision | Reason |
|---|---|---|
| Dedicated scalar-mul AIR | not implemented | host 19 µs/op; AIR cost exceeds benefit |
| MSM balanced tree | deferred | 3.4 ms is not a bottleneck |
| Limb backend re-selection | deferred | no current pressure |
| Streaming outer-aggregate encoding | deferred | decide after peak-memory measurement |

## 5. GPU acceleration — theoretical analysis only (no benchmarks)

The proving workload is dominated by data-parallel operations: circle-STARK
FRI field arithmetic, batched Poseidon hashing, AIR row evaluation, MSM-style
accumulations. These map naturally onto GPUs, and the design target is
second-level proofs for the recursive pipeline. **This is an engineering
estimate from the operation profile — no GPU implementation or test case
exists yet**, and no number in this document depends on it.

---

## 中文对照

**总览**：一手牌全部密码学开销 ~0.1 秒级（release 实测）→ 从下注到摊牌可见
时延 < 1 秒、Web2 手感；生产递归证明流水线本地 ~2.2 秒/手（exec 编译缓存
热态，2026-09-27；服务器旧值 15–17 秒含每次重复编译）、完全异步、对局零
等待；满桌（9 人）链上 P 层验证 ≈ 0.25 STRK，与一笔普通 invoke 同量级。

**§1 release 基线（2026-09-05，Stark 曲线热路径）**：标量乘 19 µs、52 项
MSM 3.4 ms、52 卡洗牌证明 prove/verify 44/23 ms（全周期 ~67 ms）、52 卡
ElGamal 发牌加密 6.2 ms、Poseidon hash_to_scalar 8 µs、hash_to_curve
118 µs、9 人桌 1540 项 host 折叠 2.0 ms。结论：direct-Sigma 热路径在人类
下注节奏下毫秒级完成，STARK 不进交互路径——架构主张实测成立。

**§2 生产证明流水线（异步）**：递归证明**本地 ~2.2 秒/手**（2 座位批次
2.22 s / 满桌 9 座位 2.13 s，M3 Pro、编译缓存热态；服务器旧值 15–17 秒
含每次重复 Cairo 编译，`texas/src/starknet/recursion_prover.rs`，生产
形状 steps 1656/2364、ec_ops=16）；结算 STWO 证明 ~2 秒/手
（`spawn_blocking`）；Poseidon252 v2 state-root 重算组件 e2e 2.91 秒
（~237×）。**exec 编译缓存（2026-09-27）**：prove-hand 按（程序源码 +
corelib + 工具链指纹）内容寻址缓存 Cairo Executable 于
`proving-tool/.cache/exec-cache`（容器用 `PROVE_HAND_CACHE_DIR` 指到
持久卷；`--no-exec-cache` 关闭），命中时编译相位 1.5 s → ~0 ms，证明
产物与缓存前逐位一致。回归门：`cargo test --release --test recurse_test
-- --ignored --nocapture recursion_prod_shape`。生产参数 = canonical_small +
fast FRI（pow16/q40、blake2s）；fast 档过全量门禁、投产前仍需专项安全
评审。**下一杠杆：prove 相位已是全部预算（固定 ~1.5–1.7 s + ~30 µs/步，
无单一热点）；候选按序为容器 CPU 配额/工具链对齐、递归程序 Cairo 步数
压缩、GPU（§5）。**

**§2b 合并信封（2026-09-29）：P 层 + 结算语句一份 Stwo 证明**。
`cairo/src/combined.cairo` 在**一次** Cairo VM 执行里同时证明 action-sig
批次（EC_OP 进 trace）与 settlement-private 语句（digest/零和/认领
承诺/动作日志链），公开输出 16 词 `[chain_acc] ++ v2 段]`，合约新入口
`verify_and_settle_dapv_combined_private` **单 fact** 消费
（`combined_program_hash` 槽；snforge 114/114 含 4 个新测试）；电路内
绑定断言：每条 P 任务 hand_binding == settle 段 binding——一份证明语义
上覆盖「这手的签名 + 这手的结算」。实测（M3 Pro、生产参数、缓存热）：
2p+3人结算 7 204 步 **2.2–2.9 s**、9p+3人结算 12 160 步 **2.85 s**——
对照分离路径（P 层 2.2 s + 结算 ~2 s ≈ 4.2 s）省近半，且链上一次
fact 登记、一次验证。回归门：`cargo test --release --test combined_test
-- --ignored --nocapture`（诚实 2p/9p 往返 + acc/segment 双 parity +
check-only；篡改 digest 与跨手绑定负例）。**顺手发现并修复（digest
前缀折叠）**：独立 `proving-tool/src/settlement_private.cairo` 电路把
全部 8 槽吸进 settlement digest，而链上注册 digest（合约
`compute_settlement_digest` / texas `submit.rs`）按**实际人数**折叠——
非满桌（n<8，即几乎所有真实桌）电路 `DIGEST_MISMATCH` 必然中止、
**出不了证明**（fail-closed → v2 私密腿静默回退公开结算）。共享
`settlement_stmt.cairo` 修复为只吸收「尾部全零规范」的非零玩家前缀，
对一切 n ≤ 8 与链上公式一致（`combined_digest_prefix_fold_semantics`
测试钉死）；独立电路原样保留（v2 路径不变），迁移为后续项。

**§3 链上 P 验证 EC_OP gas（主网校准）**：压缩后 N=2/4/9 ≈ 1.60M/3.12M/
6.9M l2_gas（≈ 0.058/0.113/0.25 STRK）；压缩前为 956M–4.15G（35–150
STRK），剖析显示 ~95% 花在字节序列化与纯 Cairo keccak 而非密码学本身；
challenge/ρ 改 felt 直通 Poseidon（Rust/texas/wasm/Cairo 四端共享实现）+
Horner 折叠（无 ρ 幂表、无 mod-n 乘法）合计 **~600×**。回归：snforge
12/12、parity 5/5、e2e 2/2。**结论：无需 STARK、无需分片，满桌规模链上
验证今天就可负担。**

**§4 已裁决的非目标**：标量乘专用 AIR（无净收益）、MSM 平衡树（3.4 ms 非
瓶颈）、limb 后端选型、流式 outer-aggregate（待内存实测）——均暂缓/不实施。

**§5 GPU 加速——仅理论分析、无实测**：证明负载由数据并行操作主导
（FRI 域运算、批量 Poseidon、AIR 行求值），天然适合 GPU 映射；设计目标为
递归流水线秒级证明。本文档任何数字均不依赖该目标。

**§6 canonical 一手牌 STARK 证明延迟 + 128 位安全档（2026-09-15 实测，
M4 Pro release 构建）**：整手控制行链（16 行 witness，log_size=8 域，
含翻前盲注完成 → 三街窗口完成 → 摊牌完成，`bench_full_hand_prove_latency_security`
出证验收）。两轮取稳定值：

| PCS 档位（stwo 猜想模型 pow + blowup×queries） | prove | verify | proof |
|---|---|---|---|
| 生产 40-bit（pow10 + 1×30） | ~1.0 s | ~174 ms | ~1.17 MB |
| **128-bit**（pow8 + 4×30） | **~1.9–2.2 s** | **~0.5 s** | ~1.23 MB |

- 计时口径：`prove_canonical_reveal_completion_batch_with_pcs` 全程 =
  host 校验（trace_for→validate_batch，单列 ~64–100 ms）+ canonical
  STARK prove + flock rules-hash；verify 为独立全验证（公共 scope 重建
  + STARK verify）。128 位档在 stwo 猜想安全模型下 `8 + 4×30 = 128`
  bits（`prover_context::security_128_pcs_config`，prover/verifier 必须
  同档原子切换——档位混入 Fiat–Shamir）。
- 结论：128 位安全的整手证明 ~2 s/手、验证 ~0.5 s，证明开销相对生产
  40-bit 档 ×2.1、验证 ×2.9、proof +5%——对异步结算流水线（§2 的
  `spawn_blocking` 语义）完全可接受；生产切档只需
  `protocol_pcs_config` 换指 `security_128_pcs_config` 并全量重跑
  门禁。
