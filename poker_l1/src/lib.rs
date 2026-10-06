//! poker_l1 — Texas Poker 合约库（Phase 1 收缩版，2026-09-05）
//!
//! 本 crate 原为完整 L1 链节点库（consensus/network/rpc/storage 等 ~99k 行）。
//! 仓库模型已定为 **Starknet 链下 stwo 证明程序**（根 crate `poker_texas_air`
//! 的 19 个方法 AIR + orchestrator + outer aggregate），不存在"链交易重放"
//! 概念；L1 链本体从未完成也不再是目标。链机制模块已整体移除（git 历史可
//! 恢复，见 docs/TODO.md #20 Phase 1）。
//!
//! 保留范围 = 证明与结算路径的实际闭包：
//! - [`error`]：PokerL1Error / PokerL1Result
//! - [`object_model`]：ObjectID / Object / Ownership / Sparse Merkle Tree
//! - [`signature`]：tagged pubkey / secp256k1 / ed25519
//! - [`contracts`]：`DispatchContext` / `DispatchResult` + [`contracts::texas_poker`]
//!   合约库（TexasPokerTable 状态机 / mental-poker 验证 / 确定性结算计划）——
//!   AIR trace 生成对其命令流重放（MethodBatchV2 语义），是证明本体，非链机制
//!
//! # 安全说明
//!
//! 全库 `deny(unsafe_code)`。原 rBPF VM（唯一 unsafe 例外）随链机制一并移除。

#![deny(unsafe_code)]
#![deny(rust_2021_compatibility)]
#![warn(missing_docs)]
#![warn(clippy::all, clippy::nursery)]

pub mod contracts;
pub mod error;
pub mod object_model;
pub mod signature;

/// 网络标识（chain_id）类型。保留：DispatchContext 的组成部分（hand_binding /
/// trace 派生输入）。
pub type ChainId = u64;

/// 区块高度类型。保留：DispatchContext 的组成部分。
pub type BlockHeight = u64;

/// 毫秒级时间戳。
pub type TimestampMs = u64;

/// 玩家地址（20 字节，由 blake2b_256(tagged_pubkey)[0..20] 派生）。
pub type Address = [u8; 20];

/// 32 字节哈希（blake2b_256 输出）。
pub type Hash = [u8; 32];

/// 历史默认 chain_id（"pok1"）。保留：镜像 DispatchContext 构造的兼容值。
pub const DEFAULT_CHAIN_ID: ChainId = 0x706F_6B31;
