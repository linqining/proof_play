# 双证明结算架构重构方案（poker_protocol direct-sigma + 牌局过程 STARK）

> **Summary (EN).** Live target architecture for dual-proof settlement:
> P-layer sigma proofs verified on-chain (EC_OP) + G-layer canonical STARK.
> The **v2.9 revision header below is the current truth** and supersedes the
> body where they conflict: curve world = Stark curve only; production P layer
> = `dual::hand_batch_stark` (EC_OP, Poseidon challenges/ρ, 32-byte points);
> settlement digest = `poseidon([hand_id] ++ Σ(player, sign, |delta|) ++
> [action_log_digest])`; the resident mirror is removed — a per-hand live VM
> mirror is the single state, consumed directly at settle (prove_log is the
> cross-check baseline only); legacy `PokerSettlement` is fallback only. The body is the Chinese
> working spec with the full derivation history.

状态：设计稿 v2.9（2026-09-05 修订）。本文档取代 admission-AIR（Path A
递归信封）作为「链上可验证结算」的目标架构。

**v2.9 修订（Plan D + #18 Phase B 后的现状对齐，正文旧措辞以本节为准）**：
- **曲线世界 = Stark 曲线唯一**（Plan D 2026-09-05：blst/BLS12-381 全量移除）。
  正文中的 secp256k1（D1/v2.2）、BN254（v2.1）、Bls12381Curve（§3.1）、
  "48 字节压缩点"（§3.2）等曲线叙事全部作废——生产 P 层走
  `dual::hand_batch_stark`（Cairo 原生 STARK 曲线 + EC_OP），挑战/ρ 用
  Poseidon，压缩点 32 字节；secp/BN254 仅作理论载体与保留代码。
- **结算 digest 公式**（§5.1/§6.3 "不动"作废）：
  `poseidon([hand_id] ++ Σ(player, sign, |delta|) ++ [action_log_digest])`——
  尾词为本手动作日志哈希（#18 Phase B，2026-09-05 接线：settlement_private
  电路第 37 入参、公开段 15 felt、合约 register_hand 第 4 参承诺、
  SETTLEMENT_SEGMENT_LEN=15）。
- **§5.2 "canonical 状态镜像"**：常驻 mirror 已删除；现为单一状态架构——
  实时 VM 镜像（`texas/src/starknet/shadow.rs`）在每个接受点同步 dispatch，
  结算直接取用其 ProveTask 链与 pre-payout 快照；游戏层 prove_log 仅作
  对账基准（`mirror::build_from_log` 重放路径已删除）。
- **§7.1 合约签名以代码为准**：`register_hand(hand_binding, settlement_digest,
  g_attestation, action_log_digest, exp_reveal, exp_leave, exp_recon)`；
  生产入口 `verify_and_settle_dapv_stark(hand_binding, hand_id_bytes, hand_id,
  action_log_digest, players, deltas, p_batch)`；legacy `PokerSettlement`
  仅 fallback。
- **§7.3/§12/§7.4 中 poker_l1 链上验证路线**（zk_verify/gas 表/ZkVerifierRegistry）：
  poker_l1 已收缩为合约库，该路线前提消失，仅存档；链上验证路线以
  `SETTLEMENT_PRIVACY_PLAN.md` 与 ../TODO.md 为准。

v2.8 变更（重构成果总结 + DAPV 方向）：**Path A admission STARK 全族移除后，
系统证明复杂度大幅简化**。前架构的 admission STARK 需要 log-16~21 的 FRI 域
（124–188 梯子 × 335 行 ≈ 41.5–63K 行，prove 38.4s，Merkle 承诺占 78%）；
移除后 **P 层不再有任何 STARK**（direct-sigma 链上直验或毫秒级 native prove），
**G 层保持 log-8**（canonical tagged batch 域下限 256 行，批内行数 1..=256
不影响证明成本；九人桌一手 = 2 个 log-8 批并行 prove 651ms）。正在研究的
**DAPV（Direct-Sigma Aggregate Pairing Verification）**将 P 层进一步聚合为
**一次配对**：ρ = H(hand-agg ‖ hand_binding)，L = Σ ρⁱ·Lᵢ（N ≈ 200–600 条
残差方程 MSM），接受 ⟺ e(L, H₂) = 1——终态为**一手牌提交一个配对 + 一个
STARK**。

v2.7 变更（Path A 递归工件退役执行）：按「direct-sigma 已全面替代」的决策，
**admission STARK 族整体移除**（非 archive，git 历史保留）：admission 主模块、
reconstruction 全族（V2 摊牌重建——其义务被统一 Σ 的 reveal 关系 + 合约公开
点算术/卡点比对分解吸收）、curve25519 域算术 AIR 族（fp_*/scalar_*/point_*/
msm/edwards）、aggregator PoC（descriptor-only，生产本就 fail-closed）、
ristretto_perf bin、相关 bench（slot-or-deep-batch / ristretto-timing）与
e2e 测试。共 39 文件 −31,331 行。`dual_proof.rs` 更名
`method_precompile_dual.rs`（消除与新双证明的撞名）。**保留** `outer_aggregate`
（G 层 MVP 的 O(N) host 验证聚合，settlement calldata 构造器，非递归压缩）与
`ristretto_shuffle_air`（V2 wire 类型内联自包含）。Rust 侧 release 回归
364/364 绿；Cairo 22/22 绿。编译时间：lib check 5.7s → 4.4s（−23%）；
运行时性能**零变化**（移除的全部是非生产路径代码）——九人桌 v3-dual
276.5ms prove / 28.0ms host verify 实测不变。"一手一证"的递归聚合
（跨证明折叠）确认为 M3 D 路线（gnark wrapper）的事，当前架构不做。

v2.6 变更（BG shuffle 链上验证落地）：**kind=2 (`PROOF_KIND_SHUFFLE_BG`) 从
fail-closed 变为直验**。`verify_bg_shuffle` 把 poker-protocol-bg 的
`BayerGrothShuffleProof::verify` 全量方程翻译到 Cairo（EC_OP 内建承载全部群
运算；标量域算术走新 `dual/fr.cairo`——`u256_mul_mod_n` + 比较守卫加法 + 
`fr_sub`，全程 mod-n）；transcript 重放含 `bg12_*` 全标签（逐字节对齐
poker-protocol-bg）、u64-LE deck size、`challenge_nonzero` 重试语义。
Payload 布局 (33+13n)×u256：语句（pk、in/out 密文、承诺点）+ 证明向量 +
**h 与 n 个生成器**（性能优先：生成器表随 calldata 传入而非链上 derive）。
确定性 RNG 的 n=4 向量经 Cairo↔Rust↔Python 三方交叉验证（honest/伪造
rerand/篡改密文/错域全拒绝）。调试中顺带修复了两处基础设施 bug：
`Span::slice(start, length)` 长度语义误用为 end（影响 fold/unified 的
dispatcher 切片）、`transcript_challenge` 不回传挑战后的链状态（BG 多挑战
链因此断裂——新增 `transcript_challenge_and_state`）。snforge 22/22 绿。

v2.5 变更（per-player 统一 Σ）：**PlayerHandSigma 落地两仓**。标准定义在
`zgame/poker-protocol-proofs/src/unified_sigma.rs`（zgame 为标准协议仓库，
同步引入 Secp256k1Curve/KeccakTranscript/ABI 枚举 Secp256k1=5、Keccak256=7，
编号与本仓一致）；本仓镜像同文件。协议形态：一玩家一证明——语句 = ownership
(G,pk) + fold leave (in_c1_i, d2_i) + reveal (c1_j, token_j) 的**同 witness
关系集**；证明 = 逐关系承诺 A_k=w·X_k + 单响应 s=w+c·sk；验证 = ∀k:
s·X_k == A_k + c·Y_k。**精确特判可靠性**（同 witness AND 组合，非计算性
批量化）。Transcript：`b"poker_unified_sigma_v1"`，Keccak-256，标签
unified_pk/n_fold/fold_*/n_reveal/reveal_*/commitment/challenge 逐字节两端
对齐。Cairo `verify_unified`（kind=5）经完整向量交叉验证（含伪造/篡改/错域
拒绝）；G 通道维持 Poseidon252MerkleChannel 不变（v2.5 决策）。注意：完整
向量测试需 `snforge test --max-n-steps 1000000000`（runner 默认步数上限
较低）。

v2.4 变更（P 验证器补全）：**CP（reveal token）与批量 DLEQ（fold）链上验证器
落地**——同一 EC_OP + Keccak transcript 载体，Rust↔Cairo 向量交叉验证
（honest/伪造/篡改全拒绝），snforge 11/11 绿。合约 `verify_and_settle` 升级为
**通用 kind+len+limbs 帧格式**（支持混合证明序列 + protocol_name 重放）。
BG shuffle 的链上验证仍 fail-closed（需 Fr 域 modmul，§11 SNARK 路径或 mod
builtin 方案待评估）。Sepolia 实际部署需 SNCAST_ACCOUNT 凭据（deploy 脚本已
支持 `USE_DUAL=1` 声明 PokerDualSettlement）。

v2.3 变更（transcript 切换）：secp256k1 路线的 Fiat–Shamir 挑战压缩函数从
SHA3-256 切换为 **Keccak-256**（`TranscriptId::Keccak256 = 7`，Rust
`KeccakTranscript`，secp256k1 曲线 `hash_to_scalar` 同步切换）。理由：Starknet
keccak builtin 接受 pad10*1 预填充块直接吸收（legacy Keccak 与 SHA3 仅差填充
首字节），**链上 transcript 重放近零成本**，无需软件 SHA3；挑战标量约定为
digest 的**小端整数 mod n**（与 builtin 的 LE-u256 输出直配，Rust 侧 digest
反序一次）。transcript 状态机（域分离标签/长度前缀/"challenge" 后缀）不变。
`PKOwnershipProof` 的挑战在 Cairo verifier 内**链上推导**
（`c = keccak256(G‖pk‖R) mod n`，不再进入 calldata，ownership payload
6→5 个 u256），消除挑战伪造面。

v2.2 变更（方向调整）：**协议群定为 secp256k1**（原 BN254）。决定性因素：
Starknet VM 对 secp256k1 有原生 EC_OP 内建（点加/标量乘/坐标解码），链上
P 验证零自定义算术；BN254 在链上只能走纯 Cairo 多 limb 算术（v2.1 已实现
Montgomery CIOS 参考实现并经向量交叉验证，验证了可行性但代码规模与 steps
成本高，且出现 Sierra Offset overflow 工具链问题）。secp256k1 与配对无关，
但 sigma 协议（BG/DLEQ/CP）本不需要配对；BN254 保留为 §11 SNARK 升级路径
（Rust 侧 Bn254Curve 后端已完成）。secp256k1 非 SNARK 友好，届时走 SNARK
聚合需换曲线或接受跨曲线绑定。

**实施记录（v2.2，M0–M2 已落地）**：

| 项 | 状态 | 位置 |
| --- | --- | --- |
| `Secp256k1Curve` 后端（k256） | ✅ 48/48 测试绿 | `poker-protocol-core/src/backend.rs` |
| ABI `CurveId::Secp256k1 = 5` + `(Secp256k1, BayerGrothV2, FiatShamirSha3)` 组合 | ✅ 9/9 绿 | `poker-protocol-abi/src/lib.rs` |
| 卡点常量派生（52 张，33B SEC1） | ✅ 3/3 绿 | `poker_protocol/src/secp256k1_sigma.rs` |
| sigma 套件 secp256k1 实例化（ownership/BG shuffle/fold DLEQ/reveal + 三人 e2e） | ✅ 5/5 绿（52 卡全量 ignored，release ~0.1s） | `poker-protocol-proofs/tests/secp256k1_sigma.rs` |
| `hand_binding`（§6 统一绑定） | ✅ 4/4 绿 | `src/hand_binding.rs` |
| bench `full-hand-v3-dual`（九人桌，Keccak transcript） | ✅ **整手 289.63ms**（client prove 237ms + host verify 29ms），calldata ≈65.9KiB | `hand-bench/src/main.rs` |
| Cairo `keccak.cairo`（builtin 封装 + pad10*1 + LE mod-n 挑战） | ✅ 3/3 绿（NIST 空串/abc + mod-n） | `poker_contracts/src/dual/keccak.cairo` |
| Cairo `secp256k1_verifier`（EC_OP builtin：ownership + reveal CP + fold DLEQ + **BG shuffle**，挑战/transcript 重放 + 调度） | ✅ 全 kind 直验（22/22 snforge 绿，含 BG 向量交叉验证） | `poker_contracts/src/dual/secp256k1_verifier.cairo` |
| Cairo `fr.cairo`（secp256k1 标量域 mod-n 算术：mul via `u256_mul_mod_n`、比较守卫 add/sub） | ✅ 5/5 绿 | `poker_contracts/src/dual/fr.cairo` |
| Cairo `keccak_transcript`（FiatShamir 状态机重放：new/append/challenge + 点压缩） | ✅ 状态机确定性测试绿 | `poker_contracts/src/dual/keccak_transcript.cairo` |
| Cairo `PokerDualSettlement`（u256 calldata，ownership 块 = 1 kind + 5×u256） | ✅ 编译绿 | `poker_contracts/src/poker_dual_settlement.cairo` |
| 部署清单/文档 | ✅ `strk20.json`（dual proof_policy + abi_notes）、`SEPOLIA.md`、本文档 v2.3 | 仓库根 / `poker_contracts` |
| Cairo `PokerDualSettlement`（注册绑定 + 链上验 P + 零和 + 防重放 + vault 结算） | ✅ 编译绿（u256 calldata） | `poker_contracts/src/poker_dual_settlement.cairo` |
| BN254 侧资产（Bn254Curve/向量生成器/纯 Cairo Montgomery 参考实现） | 保留为 §11 SNARK 升级路径参考 | core/proofs/bench、git 历史 |

注：`hash_to_scalar` 对 secp256k1 用 SHA3-256 → mod-n（n 距 2^128 于 2^256，
清顶位无意义）；`base_h`/卡点走 RFC 9380 SSWU（k256 `hash2curve`），dlog
对 G 不可知，保 Pedersen 绑定。Cairo 向量生成器：
`cargo test -p poker-protocol-core --test secp256k1_vectors -- --ignored --nocapture`；
合约测试：`cd poker_contracts && snforge test`（snforge 0.39 + USC 2.10，
需 PATH 含 `~/.local/usc/bin`）。

v2.1 变更：① §7.3 新增路线 D（stwo → gnark Groth16 wrapper，Herodotus
`stwo-gnark-verifier` 为参考实现）及决策门 spike；② G 层交付边界明确为
**MVP = Phase 1**（合约强制验证 P + G 注册制承诺绑定），Phase 2 上链验证
四路线为 M3 演进项、带实测数据择一，不阻塞 MVP。

版本演进：v1 的 P 层为 Groth16 SNARK（BN254 + 嵌入曲线电路）。v2 依评估结论
reversal：**sigma 协议的验证本身就是群方程 + Fiat–Shamir 挑战重放**，合约能做
椭圆曲线点运算和哈希即可直接验证，无需电路、无需 trusted setup、无需新证明栈。
SNARK 降级为规模化后的压缩升级路径（§11）。

## 0. 背景与决策演进

上一架构阶段（见 `PERFORMANCE_V2_PROTOCOL.md` §0、`HOST_ZERO_RISTRETTO_AIR.md`）的
结论是：

- **部署路径**（生产）：客户端 native sigma 证明 + 服务端 host native/AIR 验证，
  整手 ~2s 墙钟（九人桌 164.69ms 客户端 prove + 15.83ms 服务端准入）。
- **递归工件路径（Path A）**：`ristretto_admission_air.rs` 把服务端验证义务折叠为
  单份 admission STARK——九人桌实测 **>800s/手**，远不可用。

Path A 失败的根因：把 255-bit 曲线算术（Fp 域运算 + 标量乘梯子 + MSM）写进 M31
STARK，每条曲线运算要展开成几千条 M31 约束，成本随牌数×玩家数线性爆炸。**这不是
实现问题，是「非原生域算术进 STARK」的结构性成本。**

因此本方案：

1. 已回归 hostnative（commit `06ba936` 起部署路径逐证明 Flock admission 工件已移除）；
2. 新目标架构采用**双证明**：
   - **P 证明（poker_protocol 层）= sigma 协议直接验证**：密钥所有权、洗牌
     正确性、fold 掩码、reveal token——客户端照旧生成毫秒级 native sigma 证明，
     **合约用椭圆曲线内建直接验证原始群方程**（曲线迁至 BN254 G1，见 D1）；
   - **G 证明（牌局过程层）= STARK**（维持现有 stwo `texas_canonical_air` 体系），
     覆盖游戏状态机：行动合法性、底池记账、状态转移、结算计划；
   - **两者同时有效才允许结算**，合约支持双证明验证。

选择 direct-sigma 而非 SNARK 的决定性论据：

| 维度 | 直接链上验 sigma（v2，本方案） | Groth16 SNARK（v1） |
| --- | --- | --- |
| 客户端证明成本 | **~ms（现有 native 路径不动）** | 每洗牌 1–2s + 新电路栈 |
| trusted setup | **无** | 3 个电路仪式 |
| 链上成本/手 | ~3–6k EC ops + keccak（待 microbench 定价） | ~15–27 证明 × ~2M Cairo steps |
| 合约复杂度 | 全协议验证器在链上（审计面较大） | 3 个固定 verifier（审计面小） |
| calldata | ~60–80KB/手 | ~10KB/手 |
| 聚合上限 | **无**（每手永远付全额 EC 验证） | 有（递归聚合是天花板突破口） |
| 现有代码复用 | **极高**（曲线泛型套件 + 现成 transcript） | 中（witness 复用，电路新写） |

SNARK 的唯一结构性优势是后续可聚合压缩；在每手链上验证费用成为实际瓶颈之前，
它不值得电路栈 + 仪式 + 秒级客户端证明的代价。v2 把它放在 §11 升级路径。

## 0.5 重构成果总结（v2.2–v2.8）

| 指标 | 前架构（admission STARK） | 现架构（direct-sigma + G STARK） |
| --- | --- | --- |
| P 层证明形态 | 一个 admission STARK（Ristretto 曲线算术进 M31） | 每玩家一个统一 Σ（native prove 毫秒级，链上 EC_OP 直验） |
| P 层 FRI logsize | **log-16 ~ log-21**（124–188 梯子 × 335 行，41.5–63K 行） | **无 STARK**（链上群方程直验，或 DAPV 单配对） |
| P 层 prove 时间 | 38.4s（Merkle 承诺 30s = 78%） | **228ms**（九人桌全手 native） |
| G 层 FRI logsize | log-8 × 2 批（不变） | **log-8 × 2 批**（不变；域下限 256 行） |
| G 层 prove 时间 | ~0.6s/批 | **651ms**（2 批并行） |
| 链上验证 | 无（仅 digest 注册） | P 全 kind 直验（22/22 snforge 绿） |
| 代码量 | +31,331 行 admission 族 | **−31,331 行**（v2.7 移除，git 历史保留） |
| 编译时间 | 5.7s（lib check） | **4.4s**（−23%） |

**主要性能提升来源**（按贡献排序）：
1. **消除结构性成本**——"非原生曲线算术进 M31 STARK"是 admission 路线的
   根本瓶颈（每条 255-bit 曲线运算展开为 ~335 行 M31 约束，随牌数×玩家数
   线性爆炸）；direct-sigma 在 EC_OP 内建上直接执行群方程，该成本归零。
2. **P 层去 STARK 化**——sigma 协议本质是"证明廉价、验证廉价"的构造，
   链上直验消除了 FRI/Merkle 承诺/quotient 插值的全部开销。
3. **统一 Σ 合并**——一玩家一证明（共享 witness 的 AND 组合），证明数
   35→9，挑战/响应共享，calldata 缩小 ~3×。
4. **G 层不变**——canonical tagged batch 本来就在 log-8 域下限运行，
   与 admission 移除无关。

**DAPV 方向**（正在研究，另一会话）：将全部 P 层残差方程（ownership +
reveal + fold + BG shuffle ≈ 200–600 条仿射线性残差）经 Schwartz–Zippel
折叠为单个群元素 L = Σ ρⁱ·Lᵢ（一次 MSM），链上验证归约为**唯一一次配对**
e(L, H₂) = 1（H₂ ∈ G₂ 固定常数）。曲线需迁回 BN254（余因子 1，Starknet
有纯 Cairo 配对实现）。可靠性损失 ≤ (N−1)/r ≈ 2⁻²⁴⁶（Schwartz–Zippel）。
终态：**一手牌 = 一个配对（P 聚合） + 一个 STARK（G）**，两笔上链调用。

## 1. 目标架构总览

```
┌─────────── 玩家（客户端，秘密持有者） ───────────┐
│  sk_i、洗牌置换 π_i、掩码 r_i                      │
│                                                   │
│  每玩家每阶段一份 sigma 证明（native，毫秒级，    │
│  与现有 V2 部署路径同构，仅换曲线与 transcript）：│
│   P1: shuffle(BG) + ownership（开局各自回合）     │
│   P2: fold-mask（52 卡批量 leave DLEQ，弃牌时）   │
│   P3: reveal-tokens（批量 CP，摊牌时）            │
└──────────────┬────────────────────────────────────┘
               │ 公开输入：牌组密文链 / pk / hand_binding
               ▼
┌─────────── Operator/Host（游戏进行期） ──────────┐
│  · 游戏内准入：native sigma verify（现有         │
│    verify_* / admit_* 路径，毫秒级，不动）        │
│  · G 证明：stwo canonical tagged batch STARK      │
│    （现有 texas_canonical_air 体系，不改语义）    │
└──────────────┬────────────────────────────────────┘
               │ 结算时提交：{P_i} + G + 公开牌组密文 + 结算计划
               ▼
┌─────────── 合约（双证明验证后结算） ──────────────┐
│  · P：Cairo sigma 验证器（Garaga EC 内建做群运算 │
│    + keccak 重放 Fiat–Shamir，直接验原始方程）   │
│  · G：Phase 1 = 绑定注册（operator 已验证承诺）； │
│        Phase 2 = Cairo STARK verifier（见 §7.3）  │
│  · 交叉绑定：同一 hand_binding，否则拒绝          │
│  · 通过 → PokerVault.apply_settlement             │
└───────────────────────────────────────────────────┘
```

核心原则：

- **秘密分片 ⇒ 证明分片**。洗牌秘密分散在各玩家手中，任何单一 prover 无法产出
  「整手一份 P 证明」。P 是**每玩家每阶段的小 sigma 证明集合**。
- **sigma 证明一个工件从头用到尾**：游戏内 host native verify（准入，毫秒）与
  结算时合约直接验证**同一批证明**——链上验证是最强验证（合约亲自验原始方程，
  无 digest 中介），链下验证是其镜像。这与被 host-zero 政策封禁的「宿主 precompile
  出 digest 当证明」路径（`NativeBls12381V1`）本质不同：那里信任的是宿主断言，
  这里合约执行的是验证器本身。
- **G 无秘密**。牌局状态机的输入（行动序列、公开牌组密文、reveal tokens）全部
  公开，operator 可以独立证明 G——维持现有 orchestrator 职责不变。
- **两证明靠公开承诺衔接，不靠信任衔接**（§6）。

## 2. 关键决策

### D1：ElGamal 曲线 = secp256k1（v2.2 方向调整；BN254 为 SNARK 升级路径）

v2.1 曾定 BN254 G1 并完成 Rust 后端；v2.2 依「链上验证成本」方向调整为
**secp256k1**：

| 维度 | secp256k1（v2.2 定案） | BN254（v2.1，保留为升级路径） |
| --- | --- | --- |
| Starknet 链上验证 | ✅ **原生 EC_OP 内建**（点加/标量乘/取坐标），无自定义算术 | ❌ 纯 Cairo 多 limb Montgomery（已实现，代码 ~600 行 Cairo，steps 高） |
| 标量/坐标表示 | **u256 原生**（n < 2^256），calldata 直排 | 254-bit > felt252，需双 felt/limb 拆分 |
| 余因子 | 1（点校验仅曲线方程） | 1（同） |
| EVM | 无原生 precompile | ✅ EIP-196/197 |
| SNARK 嵌入曲线/Garaga Groth16 | ❌ 非 SNARK 友好 | ✅ ed-on-bn254 |

sigma 协议（BG/DLEQ/CP）与配对无关，secp256k1 功能上完全满足；`Curve`
trait 曲线泛型使两套实例化共存（Rust 侧 Bn254Curve 与 Secp256k1Curve 并行）。
安全边际 ~128-bit（优于 BN254 的 ~100-bit）。

### D2：P = sigma 协议直接链上验证（secp256k1 实例化）

sigma 验证器 = 群方程 + 挑战哈希重放。逐协议的链上验证成本（native 实测，见
`PERFORMANCE_V2_PROTOCOL.md` §1–§2）：

| 协议语句 | 验证内容 | 群运算量级 |
| --- | --- | --- |
| ownership（Schnorr） | s·G = R + c·pk | ~2 次标量乘/个 |
| reveal token（批量 CP） | pk=sk·G ∧ token_i=sk·c1_i，随机线性组合批量化 | 3 玩家 33 token 共 13.2ms ≈ 每人几十次 |
| fold（52 卡批量 DLEQ） | 挑战组合后的几条多重指数方程 | 8.8ms ≈ ~100–200 次 |
| 洗牌（Bayer–Groth） | MEA + Product Argument 折叠后终检 | 17ms ≈ ~300–600 次 |

九人桌一手合计约 **3–6k 次群运算 + transcript 哈希**。链上执行载体 = Garaga 的
Starknet 椭圆曲线内建（点加/标量乘/MSM）+ keccak 内建。唯一待实测的决策门：
**Garaga EC 内建每次标量乘的 Cairo steps 数**（M0 microbench，§9）。

### D3：transcript = Keccak-256（v2.3），Starknet 内建直配

- 合约必须逐字节重放 Fiat–Shamir 挑战。v2.2 曾沿用 SHA3-256（需纯 Cairo 软件
  实现，~24 轮 Keccak-f）；v2.3 切换为 **Keccak-256**：
  `TranscriptId::Keccak256 = 7`，Rust `KeccakTranscript`，曲线
  `hash_to_scalar` 同步——Starknet keccak builtin 接受 pad10*1 预填充块
  （legacy Keccak 与 SHA3 仅差填充首字节 0x01 vs 0x06），多块消息一次
  syscall 吸收完毕，链上重放近零成本。
- 挑战标量约定：digest 的**小端整数 mod n**。builtin 输出即 LE-u256，
  合约端一条 `u256 % n`；Rust 端 digest 字节反序一次后走
  `reduce_bytes`。两端等价已由向量测试锁定
  （`challenge_bytes_golden` / `challenge_matches_rust_vector`）。
- transcript 状态机不变：`state = Keccak256(state ‖ u32le(len) ‖ label ‖
  u32le(len) ‖ msg)`，挑战 = `hash_to_scalar(state ‖ "challenge")`，
  域分离标签逐字节保留——仅压缩函数替换，安全分析原样继承。
- Poseidon2-M31 链机制（`Poseidon2ChainSpec` 等）整体退役。

### D4：ElGamal 群 = secp256k1 本身（无配对依赖）

v1 的嵌入曲线（ed-on-bn254）是为「电路内原生域算术」；direct-sigma 没有电路，
合约直接在原生支持的 secp256k1 上做群运算（Starknet EC_OP 内建），ElGamal、
BG、DLEQ、CP 全部落同群。G2/配对是可选项：单条 DLEQ 可压成 e(pk, c1) =
e(G, token)，但一次配对比两次标量乘更贵，不划算；现有批量随机线性组合已把
每批压到常数条方程。G2 留给未来 Groth16 升级。**MVP 不用配对。**

### D5：卡点为合约对齐的确定性派生

52 个规范卡点 [card_i] = 确定性派生（域分离 `texas_poker_secp256k1/card/{i}`，
经 k256 RFC 9380 SSWU hash-to-curve），Rust 侧运行时派生、Cairo 侧由 EC_OP
直接以 (u256, u256) 坐标表示——链上无需 hash-to-curve，解密复核即坐标比对。

### D6：G 证明链上验证分两阶段

现状：Starknet 上**没有**验证任意自定义 AIR 的 stwo 证明验证器——stwo-cairo 与
Herodotus Integrity 验证的是「Cairo 程序执行」而非任意 AIR；Starknet v0.14.2 的
OS 级 S-two 验证不开放给应用。因此：

- **Phase 1（本方案 MVP）**：G 由 operator/host 验证（现有 orchestrator 的
  O(N) 逐手验证 + verified chain），但其公开输入承诺（state roots、deck/reveal
  承诺、结算摘要）**注册上链并被绑进 P 的公开输入**（§6）。合约强制 P 链上直接
  验证；G 的残差信任 = operator 可能伪造游戏记录（不能伪造密码学）。
  `proof_policy` 明示该残差。
- **Phase 2**：四条候选路线择一（§7.3；D. gnark wrapper 为重点候选）。
  **MVP 不依赖 Phase 2**——上链验证是 M3 演进项，不是交付门。

## 3. 协议层重构（poker_protocol 五 crate）

### 3.1 曲线注册（poker-protocol-core / abi）✅ 已实现

- `poker-protocol-core/src/backend.rs`：新增 `Secp256k1Curve` 实现 `Curve` trait
  （k256 0.13；33 字节 SEC1 压缩点、32 字节大端标量、`hash_to_scalar` =
  SHA3-256 → mod-n、`hash_to_curve` = RFC 9380 SSWU via `hash2curve` feature）；
  曲线算术只引入 k256，不违反 proofs 层「无证明后端依赖」纪律。`RistrettoCurve`
  （迁移窗口）、`Bls12381Curve`（Sui/poker_l1 轨道）、`Bn254Curve`（§11 SNARK
  升级路径）并存。
- `poker-protocol-abi/src/lib.rs`：
  - `CurveId::Secp256k1 = 5`（`point_size() = 33`）；`Bn254G1 = 4` 并存；
  - `validate()` 放行 `(Secp256k1, BayerGrothV2, FiatShamirSha3)`——
    `ShuffleProofSystem::BayerGrothV2 = 2` 与 `TranscriptId::FiatShamirSha3 = 2`
    **复用现有枚举**，ABI 改动最小化；
  - 52 卡 / readable=2 的既有校验不变；
  - 迁移窗口后旧组合 fail-closed（复用信封版本硬切换纪律，V2→V3 同理）。

### 3.2 序列化与哈希约定（三端逐字节对齐）

| 项 | 约定 |
| --- | --- |
| 点编码 | BN254 G1 压缩（32 字节 x + 符号位），大端 |
| 标量 | 32 字节大端 |
| 挑战派生 | Keccak256(transcript state) → 清高 2 位 → Fr |
| 卡点 | 合约 immutable 常量表；Rust 侧同源常量（测试向量锁定） |
| 域分离 | 每协议语句 label（`pk_ownership_v4`、`bg_shuffle_v4` 等）版本号 +1 |

### 3.3 sigma 套件地位：恢复为生产路径

`poker-protocol-proofs` / `poker-protocol-bg` 的 curve-generic sigma 套件（BG
洗牌、CP reveal、批量 DLEQ、reconstruction v3）**继续是生产证明栈**，在 BN254
上实例化。同时承担第二职责：若未来走 §11 的 SNARK 升级，它成为电路语义 oracle
（「sigma verify == 电路 verify」交叉验证）。reconstruction v3 摊牌解密在链上
由合约以纯点算术复核（c2 − Σ tokens 是公开点运算，无需专门证明）。

### 3.4 信封与 wire（poker_protocol）

- submission 类型（`ristretto_air.rs` 系）曲线泛型化，新增 V3 信封：
  `(CurveId::Bn254G1, BayerGrothV2, FiatShamirSha3)`，版本判别式 +3，未知组合
  fail-closed；
- 洗牌 BG wire ~5.5KB/份、fold/reveal wire 更小，borsh/bcs 序列化与现有 ABI
  工具链对齐；
- `precompile.rs` 的 legacy BLS builder/verifier 不动（已被 host-zero 政策封禁，
  仅审计）。

## 4. 链上验证层：Cairo secp256k1 验证器（✅ 已实现）

合约内验证 P 的全部方程。载体为 **Starknet 原生 EC_OP 内建**（`Secp256Trait`
/ `Secp256PointTrait`，坐标与标量均为 `u256` 原生表示）——无自定义域算术、
无 Montgomery、无 limb 拆分。

### 4.1 计算载体

- **EC 运算**：`Secp256Impl::secp256_ec_new_syscall`（on-curve 解码校验）、
  `Secp256PointTrait::{mul, add, get_coordinates}`（EC_OP 内建）；
- **哈希**：Starknet keccak 内建（transcript 重放 + 承诺）；
- **点校验**：secp256k1 余因子为 1，`secp256_ec_new_syscall` 的解码失败即
  拒绝（不 on-curve / 无效编码）。

### 4.2 验证器与交叉验证（`poker_contracts/src/dual/secp256k1_verifier.cairo`）

| 验证器 | 状态 | 内容 |
| --- | --- | --- |
| `verify_ownership` | ✅ 已实现 + 2/2 测试绿 | `s·G == R + c·pk`：EC_OP 标量乘/点加 + 坐标比对；on-curve 解码失败/恒等点拒绝 |
| `verify_p_proof` 调度 | ✅ | **全部 kind 直验**：ownership / reveal CP / fold DLEQ / unified Σ / BG shuffle |
| 交叉验证 | ✅ | 向量由 `k256`（Rust）生成（`secp256k1_vectors.rs`），Cairo 侧 honest 验证 / 伪造 s 拒绝 / 错钥拒绝 / off-curve 拒绝 全绿 |

验收纪律沿用：Rust↔Cairo 测试向量交叉验证（合法/非法/篡改各态），BG 挑战
调度逐轮对齐。

### 4.3 与 G 的计算分工

合约持有**原始公开密文列表**（calldata），直接在其上验证 P 方程；G 侧承诺由
合约用同一列表重算（§6.2）。

## 5. G-STARK 层调整（根 crate）

G 层按 **MVP 实现**重构：本方案交付的是 Phase 1 形态——G 由 host/orchestrator
生成并验证（§5.1 现状不动），其公开输入承诺经 `hand_binding` 注册上链并被 P
证明绑定（§7.1）。Phase 2 的四条上链验证路线（§7.3）为 M3 演进项，不阻塞 MVP。

### 5.1 保持不变

`texas_canonical_air` 批次证明、19 个方法 AIR、`canonical_rake_opening` /
settlement AIR、orchestrator 的 O(N) 验证链、`starknet_settlement.rs` 的
Poseidon252 结算摘要双端对齐——**牌局过程语义零改动**。

### 5.2 新增：G 公开输入信封

定义 `hand_binding`（§6）并纳入 G 的公开输入集合（canonical 状态镜像已携带
deck_commitment/reveal_commitment/proof_commitment 承诺字段，补齐与 P 相同的
`hand_binding` 摘要即可）。`deck_commitment.rs` 增加对 BN254 G1 点的承诺路径
（felt 域哈希，Cairo 可重算）。

### 5.3 服务端准入：维持现有 sigma native verify

游戏内准入继续走现有 `verify_*` / `admit_*` native 路径（毫秒级）——与 v1
方案不同，这里**不需要**换成 Groth16 验证，host 与合约验证的是同一批 sigma
证明。迁移期内 host 同步双曲线（Ristretto V2 收尾中的手牌 + BN254 V3 新手牌），
cutover 后 Ristretto fail-closed。

### 5.4 退役清单（标记 archive，不删除）

| 模块 | 处置 |
| --- | --- |
| `ristretto_admission_air.rs`（161KB） | archive：Path A 递归信封关闭，文档标注 superseded by 本方案 |
| `ristretto_fp_*_air.rs` 族（~239KB）、`ristretto_scalar_*`、`ristretto_msm/edwards/point_decode/encode` | archive：其存在意义（非原生曲线算术进 M31 STARK）被 D2 消除 |
| `ristretto_poseidon2_air.rs` / `ristretto_poseidon2_transcript.rs` | 退役：direct-sigma 路线无 transcript STARK 需求（D3） |
| `ristretto_shuffle_air.rs` / `ristretto_player_proofs_air.rs` | 改造：submission/wire 类型泛型化后服务新曲线；Flock 路由代码退役 |
| `blake3_flock.rs` 等 flock 残余 | 退役（部署路径已无 Flock） |
| `src/dual_proof.rs` | **更名**：其现有含义（stwo + native precompile）与本方案「双证明」撞名，重命名为 `method_precompile_dual.rs` 或并入 `precompile_binding.rs` |

## 6. 绑定与防混合攻击（soundness 核心）

双证明最大的风险是**拼装攻击**：用 A 手的 P 配 B 手的 G。防御：

1. **统一 hand_binding**：
   `hand_binding = Poseidon(table_id, hand_id, num_players, players[], deck_commit_0..9, reveal_commitment, state_root_pre, state_root_post, settlement_digest)`
   - P 各 sigma 证明的公开输入必须引用同一 `hand_binding`（及其声明的密文子集）；
   - G 的公开输入包含同一 `hand_binding`；
   - 合约注册时存储，结算时两证明的 binding 必须相等且未结算过。
2. **deck 承诺桥接（单向重算，比 v1 简单）**：P1 洗牌证明链式连接
   deck_0（聚合公钥下规范牌组，确定性派生）→ deck_9；合约从 calldata 的**原始
   密文列表**直接验证 P 方程（无需中间承诺），再用同一列表以 felt 域哈希
   （`deck_commitment` 现有函数路线，Poseidon252 风格、Cairo 可重算）重算 G 侧
   承诺并与 G 注册值比对。v1 的「BN254 Fr-Poseidon 双承诺桥」不再需要——没有
   电路就没有跨域承诺问题。
3. **结算摘要强制**：`settlement_digest`（现有 `settlement_hash.cairo` /
   `compute_settlement_digest` 双端 Poseidon252，不动）同时出现在
   hand_binding 与合约重算路径中，任何证明无法为一个不同的支付方案背书。
4. **fail-closed 纪律沿用**：未知曲线/系统/transcript 组合、信封版本不匹配、
   缺证明、点不在曲线上 → 合约与宿主一律拒绝（复用 ABI `validate()` 与信封
   版本硬切换经验）。

## 7. 合约层

### 7.1 Starknet：`PokerDualSettlement`（新合约，MVP）

在 `poker_contracts` 新增，逐步接管 `PokerSettlement`：

```cairo
#[external(v0)]
fn register_hand(ctx, hand_binding: felt252, settlement_digest: felt252,
                 g_attestation: felt252);            // Phase 1: G 为注册制
fn verify_and_settle(ctx, hand_binding: felt252, hand_id: u64,
                     players: Span<ContractAddress>, deltas: Span<i128>,
                     p_proof_kinds: Span<felt252>,   // 每玩家一个 kind（ownership=1）
                     p_proof_limbs: Span<u256>)      // 每玩家 6 个 u256：pk_x,pk_y,r_x,r_y,c,s
```

- 内部调用 **Starknet 原生 secp256k1 EC_OP 内建**（`Secp256Trait` /
  `Secp256PointTrait`，无自定义算术）+ keccak + §4 的验证器；
- secp256k1 标量/坐标 = u256 原生 calldata 类型（< 2^256），无 limb 拆分——
  这正是 v2.2 选 secp256k1 的直接收益；
- 保留：provers 白名单（Phase 1 仅控制 G 注册权）、零和校验、`settled_hands`
  防重放、`settlement_hash.cairo` 不动；
- `PokerVault` 不动（`apply_settlement` 接口不变）。

### 7.2 `strk20.json` / 文档同步

`proof_policy.on_chain_verification` 从
`aggregate_digest_and_settlement_state_only` 改为：

```json
{
  "on_chain_verification": "sigma_p_equations_on_chain__g_registered_attestation_phase1",
  "residual_trust": "operator attests G-STARK validity until Phase 2",
  "dual_proof": { "p": "bn254-g1 sigma, verified on-chain via garaga ec builtin", "g": "stwo circle-stark, host-verified" }
}
```

`SEPOLIA.md`、`TRUST_MODEL_NO_TRANSACTION_REPLAY.md` 信任模型章节同步改写。

### 7.3 Phase 2：G 上链验证的候选路线（M3 择一；MVP 不阻塞）

| 路线 | 内容 | 链上每手成本 | 关键代价 |
| --- | --- | --- | --- |
| A. 自研 Cairo AIR verifier | 把 texas_canonical AIR 的约束求值 + FRI(M31) + Poseidon252 Merkle 验证写成 Cairo（Herodotus Integrity 证明可行性） | 高（全额 FRI in Cairo） | 周月级自研 + 审计 |
| B. 迁移 stwo-cairo | 牌局逻辑改写为 Cairo 程序，G = Cairo 执行证明，用 Integrity/SHARP 验证 | 中 | 放弃手写 AIR 资产；边际成本比手写 AIR 退化约 50–100×/动作（§8 注） |
| C. poker_l1 原生验证 | 自有链 `zk_verify` syscall 原生实现两个后端（§7.4） | 自有链 gas 定价 | 纯工程，无密码学研究；但只在自有链生效 |
| **D. gnark wrapper（STARK→Groth16 包装）** | gnark 电路内验证 stwo 证明，再以 Groth16 上链（Garaga 或 EVM） | **常数；递归聚合后每手边际趋零** | Go/gnark 引入 + wrapper 电路自研 + 一次 ceremony |

#### 7.3.1 路线 D：stwo → gnark Groth16 wrapper（重点候选）

参考实现：Herodotus **`stwo-gnark-verifier`**（Apache-2.0）——gnark Groth16
电路内实现 M31/qm31 四次扩域算术 + Circle FRI + Merkle 验证，消费 stwo 证明并
产出 Groth16 证明；同类先例为 SP1 的 `gnark-plonky2-verifier`（Plonky2 FRI 进
gnark）。STARK→SNARK 包装是业界成熟上链模式（Polygon/SP1/ZKM 同款）。

两种用法：

- **B+D 组合**：游戏逻辑迁 Cairo（路线 B）→ stwo-cairo 出证明 → 适配
  `stwo-gnark-verifier` 包成 Groth16。链路每段都有现成代码，且消除路线 B
  「每手付全额链上验证」的弱点。
- **D 独立（保留 canonical AIR 资产）**：自写 wrapper 验证
  `texas_canonical_air` 证明——FRI/qm31 机器参考 `stwo-gnark-verifier`，
  替换约束部分为 texas canonical 的 AIR 求值。**通道注意**：现用
  `Poseidon252MerkleChannel`（felt252 域）在 BN254 Fr 电路内是非原生大数
  算术；选 D 独立路线应把 G 承诺通道切到 **M31 原生哈希**（当初保留
  Poseidon252 的理由是 Starknet OS 兼容，走 wrapper 后该理由消失）。

成本/风险量化（估算，spike 实测替换）：

| 项 | 估算 |
| --- | --- |
| wrapper 电路规模 | ~5–30M 约束（n_queries=70 的 FRI + Merkle 路径 + 约束求值主导；plonky2-verifier 先例同量级） |
| wrapper prove | ~30s–数分钟 CPU 多核（gnark GPU 路线可降）；跨 K 手聚合摊销 |
| 链上验证 | 常数：Garaga Groth16 ~2M Cairo steps / EVM ~230k gas，证明 ~0.5KB |
| 额外义务 | Groth16 trusted setup（固定 wrapper 电路，一次仪式；可与 §11 P 层 SNARK 升级的仪式合并规划） |

已知风险：`stwo-gnark-verifier` 未审计、社区规模小、pin 死 stwo/stwo-cairo
特定 commit、测试 fixture 仅 1-query——**只能作参考实现，不作依赖**；自研
部分需 Rust↔gnark 测试向量交叉验证 + 审计；wrapper 电路与 stwo 证明格式版本
强耦合（stwo 2.3 升级需重编译电路并重跑 setup）。

**决策门 spike（并入 M3 前置）**：fork `stwo-gnark-verifier`，用最小 canonical
组件的真实 stwo 证明（全 query 数）跑通电路，实测约束规模与 prove 时间——
1–2 周出可信数字后，再在 A / B+D / D 独立 / C 之间做最终选择。

### 7.4 poker_l1：原生双验证后端（与 Starknet 轨道并行）

`poker_l1` 已有 `zk_verify(scheme_id, ...)` syscall、gas 表（Stwo=300000 /
Groth16=20000）与 `ZkVerifierRegistry` 热插拔槽位，补齐生产后端：

- **P 侧**：在 rBPF 合约内直接调 BN254 G1 syscall（现有 BLS12-381 G1/G2/
  pairing syscall 旁新增 BN254 变体——曲线算术用 ark-bn254，实现量小），sigma
  方程在合约里展开；或注册 `SCHEME_SIGMA_BN254 = 5` 的新 scheme 后端（含 BG
  verify 的 native 实现，即 poker-protocol-bg 的直接复用）；
- **G 侧**：`StwoVerifier` 直接调 workspace 内 stwo 验证 `texas_canonical_air`
  证明，注册 `SCHEME_STWO = 1`；
- `contracts/texas_poker` 结算 dispatch：连续两次 `zk_verify`（G + 全部 P）
  通过才走 `SettlementPlan` 应用——「两者有效才结算」在自有链上是完整原生语义。

## 8. 性能预算（估算，M0/M1 以实测替换）

| 项 | 现值（hostnative） | 双证明方案预估 |
| --- | --- | --- |
| 玩家 shuffle 证明 | ~13ms（sigma native，Ristretto） | **secp256k1 实测 24ms/次**（九人桌 9 次共 218ms） |
| reveal / fold 证明 | ~ms | **不变** |
| 游戏内准入（host） | 8–16ms/洗牌 | secp256k1 实测并行验证 ~2.3ms/洗牌 |
| G 证明（operator） | canonical batch 现有耗时 | 不变 |
| 链上 P 验证 | 无（仅 digest 注册） | ~3–6k EC ops + keccak/手；**Garaga microbench 定价是 M0 决策门** |
| 链上 G 验证 | 无（仅 digest 注册） | MVP = 注册制承诺绑定（≈0 额外链上计算）；Phase 2 路线 D 为常数 ~2M Cairo steps/聚合批，跨手摊销后边际趋零 |
| 链上 calldata | — | ~60–80KB/手（9×BG wire ~5.5KB + 玩家证明） |

**v3-dual 九人桌实测**（`full-hand-v3-dual`，secp256k1，release）：整手墙钟
**282.95ms**（client prove 233.98ms + host verify 27.12ms），fold DLEQ 5.2ms，
56 张 reveal 8.5ms，decrypt+settlement 10.3ms，hand_binding 0.6ms；链上 P
calldata ≈65.9KiB。对照 BN254 同流程 586.79ms——secp256k1 快约 2×。

对照 Path A 的 >800s：direct-sigma 没有任何「非原生算术进 STARK」成本，客户端
证明维持毫秒级，新增成本全部落在链上验证（按次付费、随吞吐线性）。

## 9. 里程碑

| 阶段 | 内容 | 完成判据 |
| --- | --- | --- |
| **M0** 骨架 + 决策门（~1 周） | `Bn254Curve` backend + ABI 组合 + 卡点常量 + transcript 约定；**Garaga microbench：BN254 G1 标量乘/点加/keccak 的 Cairo steps，乘上 3–6k 量级得每手真实费用**；若费用超预算 → 回到 §11 SNARK 路线决策点 | workspace 编译绿；microbench 报告；曲线/编码单测 |
| **M1** Cairo 验证器（2–3 周） | §4.2 移植清单（Schnorr → 批量 CP/DLEQ → BG）+ hand_binding + Rust↔Cairo 测试向量交叉验证；hand-bench 新模式 `full-hand-v3-dual`（九人桌端到端） | 测试向量全绿（合法/非法/篡改）；bench 全绿；性能表实测化 |
| **M2** 合约双证明（1–2 周） | `PokerDualSettlement` + Garaga 集成 + Sepolia 部署 + `strk20.json`/文档更新 | Sepolia 上九人桌双证明结算 e2e |
| **M3** G 上链 / 自有链（2–4 周） | §7.3 四路线择一推进——路线 D 先做决策门 spike（fork stwo-gnark-verifier，最小 canonical 组件真实证明实测电路规模/prove 时间）；poker_l1 两个 zk_verify 后端 + texas_poker dispatch | 残差信任消除或自有链原生双验证；spike 实测报告 |
| **M4** 优化（按需） | 每手链上费用实测量化后的降本：批量多手结算、争议手全验证/常规手抽查模式、§11 SNARK 压缩升级 | 单手链上验证成本达标 |

## 10. 风险与开放问题

| 风险 | 缓解 |
| --- | --- |
| Garaga EC 内建单价未知，链上费用可能超预算 | M0 microbench 为硬决策门；超标则触发 §11 SNARK 路线（v1 方案即其蓝本） |
| BG verify 的 Cairo 移植正确性（挑战调度逐轮对齐） | 1:1 移植 + Rust↔Cairo 全态测试向量；团队已有双路由 transcript 精确性经验 |
| calldata ~60–80KB/手 | Starknet calldata 相对便宜；必要时仅提交承诺 + 争议时提交全量 |
| 每手链上成本随玩家数线性、无聚合上限 | §11 SNARK 升级路径（保留 v1 设计为蓝本）；或 M4 的批量/抽查结算模式 |
| BN254 ~100-bit 安全边际 | 扑克注码量级业界普遍接受；架构分层使整栈换 BLS12-381 局部化（代价：点子群检查 +30–50% 链上成本） |
| 迁移期双栈复杂度 | cutover 用信封版本硬切换（V2→V3），Ristretto 组合届时 fail-closed，复用既有纪律 |
| 混合攻击面（binding 设计缺陷） | §6 的四层绑定 + 负向测试（拼装不同手的 P/G 必须被合约拒绝）进 CI |
| reveal token 上链的隐私边界 | 沿用现有 V2 协议摊牌即公开 token 的暴露模型，写入威胁模型文档复核 |
| 路线 D 参考实现不可依赖（未审计 / pin commit / 1-query fixture） | 只作参考代码不作依赖；自研 wrapper 需 Rust↔gnark 测试向量交叉验证 + 审计；电路与 stwo 2.3 版本锁定的升级流程写入 M3 计划 |
| 通道切换（Poseidon252MerkleChannel → M31 原生哈希）牵动 G 证明参数与双端对齐 | 仅在选 D 独立路线时触发；通道切换与 §5.2 信封一并在 M3 设计评审，felt252 侧 settlement_hash 路径不动 |

开放问题：

1. M3 的 G 上链路线选择（A 自研 Cairo verifier vs B stwo-cairo 迁移 vs
   D gnark wrapper vs C 只走 poker_l1）——建议 M2 结束后带 §7.3 决策门
   spike 的实测数据决策；
2. Phase 1 operator 对 G 的残差信任是否需要多签/欺诈挑战窗口兜底；
3. 常规手是否可走「operator 批量结算 + 抽查/争议触发链上全验证」的混合模式
   以摊薄每手链上费用（需与信任模型文档联动设计）。

## 11. 远期升级路径（非本方案范围，保留 v1 设计为蓝本）

**SNARK 压缩升级（v1 方案）**：当手牌吞吐使每手 ~3–6k EC ops 的链上费用成为
实际瓶颈时，把 P 层升级为 Groth16/BN254——ElGamal 迁至嵌入曲线
`ark-ed-on-bn254`（基域 = BN254 Fr，电路内群运算原生），每玩家每阶段子证明
~0.1–0.5M 约束、可递归聚合为 1–3 个证明/手，链上成本降至 ~2M steps/证明；
代价是 trusted setup 仪式 + 电路栈 + 客户端证明秒级化。本方案的 sigma 套件届时
成为电路语义 oracle（「sigma verify == 电路 verify」交叉验证）。Garaga 届时
提供 Groth16 verifier 生成（snarkjs/gnark JSON 导入）。

**PRF-native 协议重设计**：ElGamal 重加密 → Fr 域 PRF 掩码
（card' = card + Σ PRF(sk_j, idx)），全部原生域算术、电路内无椭圆曲线，单洗牌
电路 ~50–100k 约束。代价是协议语义重写。仅在 SNARK 升级之后再评估。

## 12. 代码影响清单（摘要）

| 层 | 新增 | 修改 | 退役/archive |
| --- | --- | --- | --- |
| core/abi | `Secp256k1Curve`（k256）、`Bn254Curve`（升级路径）、`CurveId::Secp256k1 = 5` / `Bn254G1 = 4` | `validate()` 组合（复用 `BayerGrothV2`/`FiatShamirSha3`）、point_size 33/32 | — |
| poker_protocol | `secp256k1_sigma.rs` / `bn254_sigma.rs` 卡点派生 | — | legacy BLS 路径维持封禁 |
| proofs/bg | BN254 实例化 + Keccak transcript 对齐 | 序列化/哈希约定 | — |
| 根 crate | `hand_binding`、G 公开输入信封 | `deck_commitment.rs` BN254 路径；准入维持 sigma native | admission air、ristretto_fp 族、poseidon2 transcript、flock 残余；`dual_proof.rs` 更名 |
| poker_contracts | `PokerDualSettlement` + `dual/secp256k1_verifier`（EC_OP builtin，✅ 2/2） | `strk20.json`、`SEPOLIA.md`、信任模型文档 | BN254 纯 Cairo Montgomery 参考实现随 v2.2 退役（git 历史保留） |
| poker_l1 | BN254 G1 syscall + `SCHEME_SIGMA_BN254`/`StwoVerifier` 后端 | texas_poker 结算 dispatch | — |
| gnark-wrapper（新，Go） | 路线 D 专用：FRI/qm31 电路参考 stwo-gnark-verifier + canonical AIR 约束移植；vk→Garaga/EVM 导出 | — | — |
| hand-bench | `full-hand-v3-dual` 模式 | 现有模式保留作迁移对照 | — |

---

参考（外部依赖现状，2026-08 调研）：

- Garaga：Starknet 链上椭圆曲线运算（EC 内建）与 SNARK 验证库，支持
  BN254/BLS12-381 G1/G2 与 Groth16/Noir Honk——https://github.com/keep-starknet-strange/garaga
- stwo-gnark-verifier（Herodotus，stwo 证明的 gnark Groth16 wrapper 参考实现，
  未审计）——https://github.com/HerodotusDev/stwo-gnark-verifier
- gnark-plonky2-verifier（SP1，同类 STARK→Groth16 包装先例）——
  https://github.com/succinctlabs/gnark-plonky2-verifier
- gnark std/recursion（电路内 Groth16 验证器，递归聚合）——
  https://pkg.go.dev/github.com/consensys/gnark/std/recursion/groth16
- stwo-cairo（Cairo 程序的 Circle STARK prover/verifier，Cairo 内验证器可递归）：
  https://github.com/starkware-libs/stwo-cairo
- Herodotus Integrity（Cairo 实现的 STARK 验证器，验证 Cairo 程序执行）：
  https://github.com/HerodotusDev/integrity
- S-two 上线 Starknet 主网（2025-11，OS 级验证）：
  https://www.starknet.io/blog/s-two-is-live-on-starknet-mainnet-the-fastest-prover-for-a-more-private-future/
