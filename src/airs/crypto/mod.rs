//! C 档 — Mental Poker 协议方法 AIRs（4 个）。
//!
//! - [`fold_with_proof`] — 局中 fold 并剥离玩家加密层
//! - [`submit_shuffle_v2`] — 玩家提交洗牌结果（V2）
//! - [`submit_player_reveal_tokens`] — 提交揭牌令牌
//! - [`submit_reconstruct_deck`] — 提交重构牌组
//!
//! ## 简化策略
//!
//! Mental Poker 协议涉及复杂密码学：
//! - ElGamal 加密牌组
//! - DLEq 零知识证明（每张牌一个）
//! - Reconstruct 多方重构
//! - Reveal Token 揭示
//!
//! 四条 crypto route 都采用同一 legacy precompile 调用绑定：verifier 从 canonical dispatch 重建
//! request，执行一次 host-native 密码学验证并签发不可伪造 binding，再将完整
//! request/receipt digest 和 replay scope 绑定进 AIR statement。AIR verifier 会检查该
//! binding 的 canonical bytes、ABI/backend/digest，但不会重复同一昂贵 BLS 验证。
//!
//! 当前 STARK proof 仍不能脱离 native verifier binding 单独作为密码学 proof 已验证的
//! 可转移证据。当前生产 receipt 路径的信任边界是
//! [`crate::orchestrator::Orchestrator`]：它先重放完整原生 VM dispatch，再验证
//! shuffle/fold/reveal/reconstruction precompile 与 method AIR。`poker_l1` 在非 crate 内单元测试构建中已禁止运行时
//! `zk_skip_*` 绕过，所以该 host replay 会执行真实密码学验证。
//! 阶段 4 的 [`crate::outer_aggregate`] 会把这些 dual-proof child 与完整 VM task
//! 包装为可转移的最终聚合（O(N) host-verified，不属于 succinct recursion）。
//!
//! This module is explicitly **not** the Ristretto255 host-zero route. A
//! request/receipt digest only authenticates that a native host emitted a
//! receipt; it does not place Bayer--Groth, DLEQ or Chaum--Pedersen equations
//! in the STARK. The replacement must use versioned Ristretto crypto AIR
//! components with state-opening/public-statement binding, as specified in
//! `docs/archive/HOST_ZERO_RISTRETTO_AIR.md`（历史路线）.
//!
//! ## AIR 列布局
//!
//! 所有 crypto AIR 共享通用 37 列 + 业务列（每个方法自定义）。

pub mod fold_with_proof;
pub mod redeal_hole_card;
pub mod submit_player_reveal_tokens;
pub mod submit_reconstruct_deck;
pub mod submit_shuffle_v2;
pub(crate) mod validation;
