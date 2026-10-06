//! 链运行时（分层架构 L2-runtime）。
//!
//! 所有"区块链性"收敛于此：selector 路由与 borsh 解码、caller 认证
//! （座位解析 + `signature/` 交易签名验证）、`DispatchContext` 时钟供给、
//! pre/post clone 事务原子性、call_seq/hand_id 记账、canonical 编解码与
//! 状态根（`state_codec`）、ProveTask 产出（→ 链下证明编排层 Orchestrator
//! `poker_texas_air` 消费生成证明）。
//!
//! 依赖方向：runtime → core（单向）。核心状态机（`super::core`）不得反向
//! 引用本目录任何模块（由 `poker_l1/tests/arch_core_purity.rs` 强制）。

pub mod caller_id;
pub mod dispatch;
pub mod pending;
pub mod prove_task;
pub mod state_codec;
pub mod table_runtime;

// ==== 兼容 re-exports ====
// runtime 三文件划界前与 core 文件是扁平兄弟，代码内大量 `super::types` /
// `super::utils` 等路径。这里保持这些路径继续有效；runtime 新代码请直接
// 写 `crate::contracts::texas_poker::core::...`。
pub use crate::contracts::texas_poker::core::{
    betting, card, constants, events, state_machine, types, utils,
};
pub use crate::contracts::texas_poker::{
    TEXAS_POKER_GOVERNANCE_OBJECT_TYPE, TEXAS_POKER_HOT_STATE_SCHEMA_VERSION,
    TEXAS_POKER_METADATA_OBJECT_TYPE, TEXAS_POKER_RULES_OBJECT_TYPE, TEXAS_POKER_TABLE_OBJECT_TYPE,
    TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
};
