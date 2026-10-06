//! Texas Poker 原生 Precompile 合约（移植自 `/Users/mac/projects/zgame/texas_poker_move`）。
//!
//! 本模块将 Sui Move 德州扑克合约（~8000 行，含完整 Mental Poker 协议）
//! 移植为 zchain 原生预编译合约。合约字节码内嵌于 zchain 节点二进制，
//! 通过 `PrecompileRegistry` 注册，ObjectID = `reserved::texas_poker_contract_id()`
//! （`0xFF..02`）。
//!
//! # 分层结构（2026-09-09 划界，依赖方向恒为 runtime → core）
//!
//! - [`core`]：**纯核心状态机**——状态类型、状态转移、下注规则、边池、
//!   结算派生、牌力评估、交易载荷密码学验证。时钟参数注入、无 IO、
//!   无随机数（cfg(test) 除外）。可独立嵌入合约移植 / bot / 模拟器 /
//!   属性测试 / 形式化对齐。
//! - [`runtime`]：**链运行时**——selector 路由与 borsh 解码、caller 认证、
//!   `DispatchContext` 时钟供给、事务原子性、call_seq/hand_id 记账、
//!   canonical 编解码与状态根（state_codec）、ProveTask 产出（→ 链下证明编排层
//!   Orchestrator 消费）。
//!
//! 扁平路径兼容：下列 `pub use` 保持全部旧导入路径不变
//! （`texas_poker::types::TexasPokerTable` 等），新代码请使用
//! `texas_poker::core::*` / `texas_poker::runtime::*`。
//! 核心纯度由 `poker_l1/tests/arch_core_purity.rs` 强制。
//!
//! # Mental Poker 协议
//!
//! 1. 玩家轮流 shuffle 加密牌组并提交 shuffle proof
//! 2. 每个玩家为非自己手牌提交 reveal token（部分解密）
//! 3. 牌主用自己 sk 完成解密（showdown 阶段）
//! 4. 公共牌由所有玩家 reveal token 聚合解密
//!
//! 链上仅做 verify，链下做 prove（`#[cfg(feature = "client")]` 门控）。
//!
//! # ZK 跳过回退（仅 crate 内单元测试）
//!
//! 单元测试的密码学跳过是编译期 `cfg(test)` 行为，不属于桌台状态。生产、普通库和
//! 集成测试构建始终执行真实密码学验证，状态/preimage 无法携带运行时绕过开关。

// ===== 纯核心状态机（core/）=====
pub mod core;

// ===== 链运行时（runtime/）=====
pub mod runtime;

// ===== 扁平路径兼容 re-exports（旧导入路径保持不变）=====
pub use core::{betting, card, constants, events, hand_evaluator, settlement, settlement_fixture};
pub use core::{side_pot, state_machine, types, utils};
pub use runtime::{dispatch, prove_task, state_codec};

/// Canonical Object type tag for persisted Texas Poker table state.
///
/// Keep this separate from the reserved precompile contract ID: reconciliation, snapshots and
/// proof anchors identify table escrow by this stable type tag, while the current MVP happens to
/// store its single table at the precompile ID.
pub const TEXAS_POKER_TABLE_OBJECT_TYPE: &str = "TexasPokerTable";

/// Object type tag for immutable table display metadata.
pub const TEXAS_POKER_METADATA_OBJECT_TYPE: &str = "TexasPokerTableMetadata";

/// Object type tag for immutable poker rules.
pub const TEXAS_POKER_RULES_OBJECT_TYPE: &str = "TexasPokerTableRules";

/// Object type tag for immutable creator/admin policy.
pub const TEXAS_POKER_GOVERNANCE_OBJECT_TYPE: &str = "TexasPokerGovernancePolicy";

/// Persisted Borsh schema version for [`types::TexasPokerTable`].
///
/// Version 3 removed persisted derived/transient fields while preserving the complete game state.
/// Version 4 replaces redundant seat lifecycle booleans with one status enum and packs orthogonal
/// booleans into flags. Version 5 moves all seat-set state to canonical u16 masks and replaces
/// persisted optional seat indices with `NO_SEAT`. Version 16 replaces the variable-length
/// encrypted deck with an absent-or-fixed-52 tagged union. Version 17 removes the duplicate
/// table-local command version. Version 18 removes `addon_pool`, which is uniquely derived from
/// the checked sum of every occupied seat's `pending_addon`. Version 19 removes
/// `ante_collected`; the start-hand transition derives it from checked per-seat debits and the pot
/// delta. Version 23 physically groups immutable/low-frequency poker parameters into
/// one canonical `TableRules` value, preparing it to move behind a rules hash without keeping
/// duplicate flat fields in the hot table state. Version 25 makes the tagged `Seat` enum the
/// physical runtime and resolved-snapshot representation; version 27 replaces the redundant
/// numeric reveal phase with a typed purpose whose exact board street comes from `HandPhase`.
/// Version 28 replaces the byte-wide `0xff` missing-seat marker with the canonical four-bit
/// sentinel `0x0f`. Version 29 replaces the variable-length reveal ledger with a fixed
/// `(seat, hole_slot)` owner-readable partial-ciphertext ledger.
/// Incompatible older layouts are deliberately unsupported.
/// Version 30 adds the per-seat registered session tx public key
/// (`OccupiedSeat.tx_pk`，P1-2 会话委托：座位级签名验证锚).
/// Version 32（2026-09-10）定宽化布局：座位槽位恒 9（`[Seat; 9]`，
/// `max_players` 之外 Vacant 填充）、会话交易公钥为定宽 `StarkTxPubkey`
/// （tag + `[u8; 32]`，去 Vec 长度前缀）。Incompatible older layouts are
/// deliberately unsupported.
/// Version 34（2026-09-11）桌台名出共识：`TexasPokerTable` 不再携带 `name`，
/// 展示名只存于非共识 metadata 对象（`TexasPokerTableMetadata`）。Incompatible
/// older layouts are deliberately unsupported.
/// Version 36（2026-09-13）dead button 盲注轨道：`TexasPokerTable` 新增
/// `last_bb_seat`（上一手大盲座位，`NO_SEAT` 表示无历史），完整实现
/// Robert's Rules of Poker §4.2b。Incompatible older layouts are
/// deliberately unsupported.
pub const TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION: u8 = 36;

/// ObjectDb-only hot-state schema.
///
/// Runtime/proof snapshots use resolved schema v36（v34 定宽布局 + dead
/// button 盲注轨道 `last_bb_seat`，无桌台名）. The v37 ObjectDb encoding
/// combines immutable rules/governance context commitments with the same
/// physical tagged-seat and typed-reveal representation；metadata 对象不再
/// 被热状态 digest 绑定（展示名非共识）.
pub const TEXAS_POKER_HOT_STATE_SCHEMA_VERSION: u8 = 37;

// Phase 3.3: TexasPokerPrecompile impl（待 state_machine/dispatch 完成后补）
// pub struct TexasPokerPrecompile { ... }
// impl
