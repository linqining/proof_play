# Soundness — final status

> **Authoritative soundness record** for the three verification pillars of
> this project, in their final state. Supersedes and replaces the former
> `docs/design/DAPV_SOUNDNESS.md` and `docs/archive/SOUNDNESS_FIXES.md`
> (removed; full derivations remain in git history, and
> `docs/archive/PO5_PO6_DESIGN_NOTES.md` keeps the VM architecture snapshot).
> Current AIR coverage/gap authority: [docs/STATUS.md](STATUS.md).
> English is authoritative; Chinese is a mirror.
>
> **健全性最终状态记录**。取代并合并原 `docs/design/DAPV_SOUNDNESS.md` 与
> `docs/archive/SOUNDNESS_FIXES.md`（已删除，推导全文在 git 历史；
> `docs/archive/PO5_PO6_DESIGN_NOTES.md` 保留 VM 架构快照）。
> AIR 覆盖/缺口权威见 [docs/STATUS.md](STATUS.md)。以英文为准，中文对照。

The system verifies fairness in three independent pillars. Their assumption
sets are disjoint, so guarantees compose additively (combined bound below).

## Pillar 1 — Protocol level: Lean 4 + Mathlib (reconstruction)

The reconstruction protocol is fully formalized. A machine-checked
counterexample proved reconstruction **V2 unsound** (removed/folded seats
leaked card slots to anyone replaying the reconstruction) — found by Lean, not
by fuzzing. The repaired **V3** ships with machine-checked completeness and
soundness theorems; the Lean development contains zero `sorry`/`admit`.

Details: [`poker_protocol_lean/SECURITY_RECONSTRUCTION.md`](../poker_protocol_lean/SECURITY_RECONSTRUCTION.md)

## Pillar 2 — P layer: DAPV sigma-proof aggregation (on-chain)

Production instantiation: **Stark-curve direct-sigma proofs, Poseidon
challenges/ρ, verified on-chain** by `PokerDualSettlement` via the EC_OP
builtin (`dual::hand_batch_stark`). (Earlier secp256k1/BN254 instantiations in
the literature-facing derivation are theoretical carriers only.)

**Theorems (final):**

- **Aggregate soundness.** If any equation in the submitted transcript has a
  non-zero residual under honestly derived inner challenges, acceptance
  probability ≤ (N−1)/2²⁵³ + q_H·2⁻²⁵⁶. At N = 253 (9-player hand): ≈ **2⁻²⁴⁵**.
- **Aggregation ⟺ individual verification.** The pairing check and the free
  `L == O` point check accept exactly the same transcript set; production uses
  the `L == O` form.
- **Composition.** DAPV is an *aggregator of verification, not an amplifier of
  soundness*: acceptance requires all residuals zero, so inner-protocol
  assumptions (DLP + ROM per sigma protocol; Pedersen binding for the
  Bayer–Groth V2 shuffle) are inherited unchanged. **BG V2 is mandatory** — the
  legacy V1 shuffle proof has a documented mixed-witness attack that aggregation
  would inherit.

**Replay/splice protection — four-layer binding** (hand_id on-chain registry →
hand-binding prefix inside every inner Fiat–Shamir transcript → ρ/hand_binding
cross-layer reconciliation with the STARK public inputs → on-chain freshness
state machine). Every replay/splice/mixing/double-spend/epoch/stale-key attack
in the threat model fails at a mapped layer; the former ownership-challenge
binding gap is **closed**. Experimentally validated: honest transcripts
accepted; single-point tampering and cross-hand replays rejected.

## Pillar 3 — G layer: canonical AIR (Stwo circle-STARK)

- The AIR constraint set was **audited by a Lean formalization**: of 21 method
  AIRs, 20 had machine-checked counterexamples (state-root, version increments,
  missing guards, unchecked fund conservation). All were fixed within the
  degree-2 constraint frame (version `+1` ripple-carry constraints, round-state
  gating, 4-limb pot/pool conservation, global bound range checks), each with
  prove-fails regression tests.
- Current coverage and the **fail-closed gap list** are maintained in
  [docs/STATUS.md](STATUS.md) (authoritative). Highlights now covered:
  mid-round betting relations, showdown settlement algebra, reveal ledger,
  timeout cascades, state-root **binding and recomputation** (Poseidon252 v2
  component, e2e 2.91 s).
- Deliberately still **out of AIR** (each with an acceptance criterion in
  STATUS): curve-crypto equalities (verified natively + on-chain EC_OP instead,
  per the Plan D split), the RevealComplete phase switch, recursive aggregation
  of batches, and an in-AIR settlement algorithm (settlement runs as canonical
  native `SettlementPlan` replay with digest binding into the AIR).
- Consequence: a witness-free Stwo verification alone must not advance a
  production table; the **host is an availability dependency, not a
  correctness dependency** — anyone can re-verify proof bundles in the browser,
  and the P layer settles on-chain regardless.

## Combined claim

Under (i) inner sigma FS soundness (DLP+ROM), (ii) BG V2 soundness, (iii) STARK
soundness, (iv) hash collision resistance, (v) an unrollbackable on-chain state
machine, the advantage of any PPT adversary settling a transcript that is not
the honest execution of the hand is

```
≤ Σᵢ ε_inner,i + ε_STARK + (N−1)/2²⁵³ + q_H·2⁻²⁵⁶
```

**What we do not claim:** the G-layer chain contract does not yet verify STARK
proofs directly (Phase 2); open source is not correctness (hence fail-closed
coverage + mutation tests); browser verification depends on the served wasm
bundle until the verification key becomes a chain fact.

## Verify

```bash
lake build                                    # poker_protocol_lean — zero sorry
cd poker_contracts && snforge test            # 91 contract tests
cargo test --workspace                        # Rust stack incl. soundness regressions
cargo test -p poker-protocol-proofs --release --test plan_d_perf -- --ignored
```

---

## 中文对照

系统在三个相互独立的支柱上验证公平性，假设集不相交，保证按组合界相加。

**支柱一 · 协议层（Lean 4 + Mathlib）**：重建协议完全形式化；机器检查的
反例证明重建 **V2 不健全**（被移除/弃牌座位向重放者泄露牌槽——Lean 发现，
不是 fuzz）。修复后的 **V3** 携带机器检查的完备性与健全性定理，Lean 开发
零 `sorry`/`admit`。详见
[`poker_protocol_lean/SECURITY_RECONSTRUCTION.md`](../poker_protocol_lean/SECURITY_RECONSTRUCTION.md)。

**支柱二 · P 层（DAPV sigma 聚合，链上）**：生产实例化 = **Stark 曲线
direct-sigma、Poseidon 挑战/ρ、`PokerDualSettlement` 经 EC_OP builtin 链上
验证**（`dual::hand_batch_stark`）。定理：聚合可靠性 ≤ (N−1)/2²⁵³ +
q_H·2⁻²⁵⁶（N=253 九人桌 ≈ **2⁻²⁴⁵**）；配对判定与 `L == O` 自由点检查接受
完全相同的 transcript 集合（生产用后者）；DAPV 是**验证的聚合器而非可靠性
放大器**，内层假设（DLP+ROM；BG V2 的 Pedersen 绑定）原样继承——**BG V2
强制**，legacy V1 有已记录的混合见证攻击。防重放/拼接 = 四层绑定
（链上 hand_id 注册 → 每个内层 FS transcript 前缀 hand-binding → ρ 与 STARK
公共输入跨层对账 → 链上新鲜性状态机），威胁模型 A–F 逐项有失败点映射，
早期 ownership 挑战绑定缺口**已闭合**；实验验证：诚实接受、单点篡改与跨手
重放全拒。

**支柱三 · G 层（canonical AIR，Stwo circle-STARK）**：AIR 约束集经 **Lean
形式化审计**（21 个方法 AIR 中 20 个有机器反例），全部在 degree-2 框架内
修复（version 递增、round_state 门控、4-limb 资金守恒、全局上界 range
check），均有 prove 失败回归测试。现行覆盖与 **fail-closed 缺口清单**以
[docs/STATUS.md](STATUS.md) 为权威：中期下注关系、摊牌结算代数、reveal
台账、超时级联、state-root **绑定与重算**（Poseidon252 v2，e2e 2.91 秒）
均已组合。刻意留在 AIR 之外（各有准入条件）：曲线密码学等式（走 native +
链上 EC_OP 通道）、RevealComplete 阶段切换、批次递归聚合、AIR 内结算算法
（结算 = canonical native `SettlementPlan` 重放 + digest 绑定）。推论：仅凭
无见证的 Stwo 验证结果不得推进生产牌桌；**host 是可用性依赖而非正确性
依赖**——任何人都可浏览器重验 proof bundle，P 层照常链上结算。

**组合主张**：在内层 FS 可靠性、BG V2、STARK、抗碰撞、链上状态机不可回滚
之下，敌手让"非本局诚实执行"的 transcript 结算成功的优势 ≤
Σε_inner + ε_STARK + (N−1)/2²⁵³ + q_H·2⁻²⁵⁶。

**不做的主张**：G 层合约尚未直接链上验 STARK（Phase 2）；开源 ≠ 正确
（故有 fail-closed 覆盖 + mutation 测试）；验证密钥上链前，浏览器验证依赖
所服务的 wasm 包。
