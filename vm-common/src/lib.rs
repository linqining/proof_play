//! vm-common — 证明任务输入的共享定义。
//!
//! **现状（2026-09-10 收缩）**：早期多 VM 计划（poker_l1 vm + poker_zkvm）
//! 的 gas / syscall_id / precompile / crypto / gas_strategy / catalog 六个
//! 模块已随 rBPF/ZKVM 路线移除（全 workspace 零消费者，含
//! `poker_zkvm` 本身——该 crate 已不存在）。仅存 `prove_task`：
//! `MethodInput` 是 poker_l1 与根 crate 证明栈的公共输入类型。
//!
//! # 安全保证
//!
//! 本 crate 严格 `#![deny(unsafe_code)]`，不引入任何 unsafe 代码。

#![deny(unsafe_code)]
#![forbid(unsafe_code)]

pub mod prove_task;
