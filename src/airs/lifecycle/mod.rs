//! A 档 — 表台生命周期 Method AIRs（5 个稳定 discriminant）。
//!
//! - [`create_table`] — 创建新桌台
//! - [`join_table`] — 简单入座
//! - [`leave_table`] — 简单离座
//! - [`start_hand`] — 开始新一局
//! - [`advance_deadline`] — permissionless 超时驱动

pub mod advance_deadline;
pub mod create_table;
pub mod join_table;
pub mod leave_table;
pub mod start_hand;
pub(crate) mod validation;
