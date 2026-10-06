//! 纯核心状态机（分层架构 L2-core）。
//!
//! 本目录是德州扑克的**全部权威游戏语义**：状态类型、状态转移、下注规则、
//! 边池、结算派生、牌力评估、交易载荷密码学验证。它是纯函数式的：
//!
//! - 时钟由调用方注入（`now_ms: u64` / `DispatchContext.block_timestamp`），
//!   本目录**不读** `SystemTime` / `Instant`；
//! - 无 IO、无 tokio、无全局状态；随机数只允许出现在 `#[cfg(test)]` 内；
//! - 不依赖任何 runtime 模块（`dispatch` / `prove_task` / `state_codec`）——
//!   依赖方向恒为 runtime → core，由
//!   `poker_l1/tests/arch_core_purity.rs` 编译期外扫描强制。
//!
//! 可独立嵌入的目标：链上合约（Cairo 移植的唯一参照物）、bot、模拟器、
//! 属性测试、`airs_lean` 形式化对齐。

pub mod betting;
pub mod card;
pub mod constants;
pub mod events;
pub mod hand_evaluator;
pub mod settlement;
pub mod settlement_fixture;
pub mod side_pot;
pub mod state_machine;
pub mod types;
pub mod utils;
