//! # poker_texas_air — Texas Poker method AIR + host verification
//!
//! VM 与 AIR 当前统一保留 19 个 active MethodKind；退休 discriminant 5/10/15/16 均 fail-closed。
//!
//! ## 架构分层（生产路径）
//!
//! - **Layer 0**: Method AIRs（19 个 active stable discriminant，`airs::`）
//! - **Layer 1**: [`prove_task::ProveTask`] → [`orchestrator::Orchestrator`]：完整 VM
//!   dispatch replay + 逐方法 method AIR 证明；批内连续性由
//!   [`tagged_method`] 与 [`verified_chain`] 维护
//! - **Layer 2**: [`method_precompile_dual`] 把 method proof 与 canonical
//!   precompile request/receipt 打包为可转移 dual-proof；[`outer_aggregate`]
//!   做 O(N) host-verified 聚合（descriptor-only Aggregator AIR 不作为递归压缩
//!   证明使用），[`starknet_settlement`] 消费其 settlement 语句
//! - **Canonical direct AIR**: [`texas_canonical_air`] 为完整 canonical Texas
//!   transition 的 direct-AIR 路径（hand-bench 端到端基准与 settlement/rake
//!   opening 消费）
//! - Texas 自有递归协议尚未实现，生产验证入口保持关闭
//!
//! ## 设计文档
//!
//! 详见 `docs/STATUS.md`（canonical-AIR 覆盖与信任边界）与
//! `docs/design/DUAL_PROOF_PROTOCOL.md`（结算双证明架构）。
//!
//! ## 复用率 ~85%
//!
//! - state root 在可信 host 端从 canonical Borsh preimage 重算，并与完整公开输入一起
//!   混入 Fiat–Shamir；当前 method AIR 内没有嵌入 Poseidon verifier 组件
//! - 直接复用 `poker_l1::contracts::texas_poker::types::TexasPokerTable`（业务类型）

#![cfg_attr(texas_release_tests, allow(unexpected_cfgs))]
#![deny(unsafe_code)]
#![deny(missing_docs)]

// Integration tests use this feature to exercise deliberately untrusted PoC
// entry points. Refuse release artifacts that accidentally enable it through
// `--all-features`; checked production APIs remain available without it.
// `cfg(test)` exempts the release *test harness* (`cargo test --release --lib`),
// and the custom `texas_release_tests` cfg — set explicitly via
// `RUSTFLAGS='--cfg=texas_release_tests'` — exempts deliberate release
// integration-test runs. Both are test artifacts, not shippable builds.
#[cfg(all(feature = "test-helpers", not(debug_assertions), not(test)))]
#[cfg(not(texas_release_tests))]
compile_error!("poker_texas_air/test-helpers must not be enabled in release builds");

// ===== Layer 0: Method AIRs =====
pub mod airs;
pub mod trace_gen;

// ===== 公共基础设施 =====
pub mod deck_commitment;
pub mod method_precompile_dual;
pub mod error;
pub mod hand_binding;
pub mod method_kind;
pub mod outer_aggregate;
pub mod precompile_binding;
pub mod proof_archive;
pub mod prove_timing;
mod prover_context;
pub mod public_inputs;
/// Poseidon252 (Starknet Hades-3) chain statement — native layer and honest
/// witness builder for the in-AIR state-root recomputation (#22⑤).
pub mod poseidon252_air;
/// Poseidon252 chain AIR component: constraints, range tables, interaction
/// traces, and the prove/verify drivers.
/// Poseidon252 v2: cairo-air-style component decomposition (chain linker +
/// mul/reduce coprocessors + range tables).
pub mod poseidon252_v2;
/// Raw Starknet Poseidon round keys (pathfinder parameter set) backing the
/// Poseidon252 AIR constants.
pub mod poseidon252_round_keys;
pub mod settlement_binding;
/// Strict Cairo ABI calldata builder for the verified outer aggregate
/// settlement path on Starknet Sepolia.
pub mod starknet_settlement;
/// 宿主（EVM 族）结算绑定：Monad 优先，EVM 等价链通用。与 starknet_settlement
/// 同层——per-chain calldata/事件编码唯一落点，AIR/证明器保持链无关。
pub mod host_evm_settlement;
pub mod state_root;
/// Flock-proven state-root binding replacing host hash recomputation.
pub mod state_root_binding;
pub mod tagged_method;
/// Fixed-width canonical state and selector ABI for the complete Texas VM surface.
pub mod texas_canonical;
/// Direct AIR and archive format for complete canonical Texas transitions.
pub mod texas_canonical_air;
pub mod verified_chain;

// ===== Post-commit Prover =====
// 证明任务（数据契约）+ Orchestrator（异步消费任务生成/聚合 proof）。
// 详见 orchestrator.rs 的架构说明。
pub mod orchestrator;
pub mod prove_task;

// ===== Layer 2: Aggregation =====
// 阶段 4：outer_aggregate 做 O(N) host-verified 聚合；descriptor-only
// Aggregator AIR 的 prove/verify 生产入口默认拒绝，只保留显式测试入口。
pub mod authorization_binding;
/// Lookup-backed Blake2b compression scheduler and fixed-value SMT path proof.
pub mod blake2b_lookup_compression;
/// Lookup-backed Blake2b G component for the host-zero compression path.
pub mod blake2b_lookup_g;
/// Fixed-width Blake2b SMT compression witness ABI for the host-zero route.
pub mod blake2b_smt_witness;
/// Binary-field BLAKE3 (flock) hash-proving backend.
pub mod blake3_flock;
/// Blake2b authentication of the canonical table-rules preimage and the
/// fixed-width rake opening consumed by raked settlement terminals.
pub mod canonical_dispatch_trace;
pub mod canonical_rake_opening;
/// Shuffle/deal proof-chain stage-0 producer + native two-sided BG/DLEq/V3
/// verification (`shuffle-chain stage0`; docs/shuffle-deal-proof-design.md §4
/// milestone 0, route A upstream half).
pub mod canonical_shuffle_chain;
pub mod canonical_reveal_opening;
/// Lookup-backed authentication of canonical state-image byte preimages.
pub mod canonical_state_hash;
pub mod state_image_admission;
/// Backend-agnostic hash-statement proving seam ([`hash_prover::HashStatement`])
/// shared by the M31 lookup stack and the binary-field flock backend (the
/// process-wide default backend is the BLAKE3 flock chain digest).
pub mod hash_prover;
/// Unified admission STARK skeleton: the Path A recursive-aggregator
/// RistrettoAirV2 player sigma proofs: ownership, reveal tokens, deck
/// remasking, and fold/leave transitions.
pub mod ristretto_player_proofs_air;
/// Composed host-zero Ristretto255 point-decode proofs.
/// Poseidon2 over M31: transcript-chain segment for the unified admission
/// STARK (Path A Flock-elimination).
pub mod ristretto_poseidon2_air;
/// Poseidon2-M31 native Fiat--Shamir transcript (the CryptoTranscript
/// implementation whose chain statements fold into the admission STARK).
pub mod ristretto_poseidon2_transcript;
/// Dedicated fixed-window Ristretto255 scalar-multiplication ladder AIR (the
/// point-side Path A prerequisite).
/// Single-STARK Ristretto255 scalar-field (`mod l`) program AIR: the Path A
/// constraints for the Bayer--Groth scalar-side schedule.
/// Canonical Ristretto255 scalar 4-bit window AIR.
/// RistrettoAirV2 complete 52-card shuffle: Bayer--Groth argument with a
/// Flock-BLAKE3 Fiat--Shamir transcript.
pub mod ristretto_shuffle_air;
/// Statement-level projection of L1 sparse-Merkle openings onto the shared
/// hash-prover seam.
pub mod smt_statements;
/// P2-M1 结算隐私电路骨架（Stwo）：公开语句展开 scope + witness trace 绑定，
/// digest/claim_cms 参考实现与链上逐字段对齐；§8.2 动作签名域预留列强制零化。
pub mod settlement_private_circuit;

/// Canonical tagged-seat fixture operations, available only to tests and debug test helpers.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_support;

// ===== Prover / Verifier 入口 =====
pub mod prover;
pub mod verifier;
