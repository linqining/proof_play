//! B+ 档 — 资金动作方法 AIRs（2 个）。
//!
//! - [`addon`] — 玩家追加筹码（下一手生效）
//! - [`rebuy`] — 玩家重购（立即生效）
//!
//! ## 业务差异（关键）
//!
//! | 方法 | 生效时机 | 状态字段 | 是否影响当前 pot |
//! |------|---------|---------|---------------|
//! | `addon` | 下一手 `reset_for_next_hand` | `pending_addon` | ❌ 不影响 |
//! | `rebuy` | 立即 | `stack` | ⚠️ 影响下一动作可用筹码 |
//!
//! ## 约束模板
//!
//! 每个 funds AIR 验证：
//! 1. 通用约束（[`crate::airs::common::CommonConstraints`]）
//! 2. `seat_index == input.seat_index`（输入一致性）
//! 3. `amount` 完整 4×16-bit u64 一致性
//! 4. 业务约束：
//!    - `addon`: `pending_addon_post == pending_addon_pre + amount`
//!    - `rebuy`: `stack_post == stack_pre + amount`

pub mod addon;
pub mod rebuy;
pub(crate) mod validation;
