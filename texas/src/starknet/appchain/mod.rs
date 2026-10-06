//! B6/B7：嵌入式 appchain 结算出口与出入金桥。
//!
//! 模块地图：
//! - [`runtime`]：运行时装配（WAL sequencer + ProofPipeline + CustodyLedger
//!   + provider 单例）、`SOFT_CONFIRM` 软确认事件发射；
//! - [`prover`]：进程内 `SettlementProver`（canonical AIR 完整 STARK 验证 +
//!   attestation v2.1；与 poker-appchain-texasair 同语义的本地实例）；
//! - [`exit`]：`SettlementExit` 出口路由（Appchain/遗留 Starknet）与
//!   镜像 → SettlementRecord 的完整落地；
//! - [`bridge`]：出入金链上侧——`VaultProvider`（存款事件桥/打款执行/
//!   储备快照）+ 自动对账（M7-ACC-4 形态）；
//! - [`keys`]：嵌入式托管密钥派生（v1 信任模型，见模块文档）。
//!
//! 配置：`STARKNET_SETTLEMENT_EXIT`（appchain 默认 / starknet 遗留）、
//! `TEXAS_APPCHAIN*`（运行时；见 [`runtime::AppchainConfig::from_env`]）。

pub mod bridge;
pub mod exit;
pub mod keys;
pub mod monad_bridge;
pub mod prover;
pub mod runtime;

#[cfg(test)]
mod scenario_tests;

pub use exit::SettlementExit;
pub use runtime::AppchainConfig;
// init 经 starknet::appchain::runtime::init 显式路径调用（与 starknet::init
// 同名避免误导）；runtime()/emit_soft_confirm 由模块内部使用。
