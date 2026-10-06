//! relayer 子系统（Starknet-only）。
//!
//! Sui 时代的 PTB 构建 / 事件同步 / 提交与重试逻辑已随 Sui 链路一并移除。
//! 仅保留与链无关的工具模块：
//! - [`proof_bytes`]：证明/密文序列化辅助（Starknet 提交路径与 socket 层共用）
//! - [`util`]：时间戳等共享工具函数

pub mod proof_bytes; // Task 2: proof 序列化辅助
pub mod util; // 共享工具函数
