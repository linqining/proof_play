//! 合约模块（Phase 1 收缩版）。
//!
//! - [`dispatch`]：`DispatchContext` / `DispatchResult` 调用边界类型
//! - [`texas_poker`]：Texas Poker 合约库（状态机 / mental-poker 验证 / 结算计划）
//!   —— AIR trace 生成对其命令流重放，是证明本体
//!
//! 原 GameContract（Phase 2 旧合约族：settle / force_* / checkpoint_* / ack /
//! revert / DA / 审查检测等）属 L1 链机制，已随 2026-09-05 模型收缩移除。

pub mod dispatch;
pub mod texas_poker;

pub use dispatch::{DispatchContext, DispatchResult};
