//! # starknet-txmgr —— Starknet 交易管理层
//!
//! 2026-10-01 立项（todo 第 2 项「批量上链 rollup 程序」）。参照物：
//! op-service/txmgr（SendState 多 gas 变体追踪、TxpoolState 卡死 nonce
//! 清位）+ zkSync `eth_tx_manager`（nonce 链上推断、每轮只推进第一笔
//! 保序、失败即停的 safety-over-liveness 哲学）+ Arbitrum dataposter 的
//! RBF 加价梯度——survey §9.3 的结论是「交易管理层不要裸写」，本 crate
//! 就是这一层。
//!
//! ## 自定义注入接缝 [`StarknetSend`]
//!
//! 全仓现状无此 seam（唯一既有 trait 是 `BatchProver`，
//! `texas/src/starknet/dual_settle.rs:228`，属证明面）：本层定义
//! `broadcast / get_nonce / estimate_fee / get_transaction_receipt /
//! call_contract` 五方法的注入接缝——生产实现 [`provider::ProviderSend`]
//! 包 texas 已依赖的 starknet 0.17 Provider/账户层，测试用内存 mock
//! （feature `test-mocks`，不触网）。
//!
//! ## 职责边界
//!
//! - **nonce 租约与链上推断**：基线 nonce 从链上 `get_nonce` 推断
//!   （zkSync 式，不信本地自增），租约只增不减；重启/对账可重推。
//! - **每轮只推进第一笔（保序）**：在途队列队首未决时，后续交易不领
//!   nonce 不广播——宁可停住也不乱序上链（safety over liveness）。
//! - **v3 资源上限与加价重发**：[`ResourceLimits`] 为 v3 上限基线，重试按
//!   [`TxManagerConfig::bump_factor_pct`] 加价（RBF 梯度；同 nonce 重发
//!   替换 mempool 旧变体）。
//! - **在途交易表 + 回执轮询**：[`SendState`] 记录每笔的全部 gas 变体
//!   （op-service/txmgr SendState 语义）。
//! - **[`visible::wait_call_visible`]**：view 调用轮询直至链上可见——吸收
//!   texas submit.rs 旧 `wait_register_visible` 的语义（该实现 2026-10-01
//!   随 txmgr 切换删除；RegisterVisible 相位归属本层，poster 只记录相位）。
//! - **幂等重放分类**：[`replay`] 吸收 texas submit.rs 旧
//!   `is_register_replay` / `is_settle_replay` 的合约错误文案匹配（同上
//!   删除，语义归本层）。
//! - **有界重试 + 失败熔断**：[`TxManagerConfig`] 携带上限；连续失败达阈
//!   值即熔断停发（fail-closed——对账分歧绝不上链），人工
//!   [`TxManager::resume_after_halt`] 恢复。
//!
//! ## 接线状态（骨架）
//!
//! 生产 [`provider::ProviderSend`] 编译通过即可；texas 现有调用点
//! （submit_settlement / submit_dual_settlement 的发送面）**未切换**——
//! 后续把发送面换走本层，calldata 构建不动（见 docs/TODO.md #50）。

pub mod provider;
pub mod replay;
pub mod send;
pub mod txmgr;
pub mod visible;

pub use replay::{ReplayVerdict, classify_execution_error};
pub use send::{
    BoxFuture, BroadcastIntent, Call, FeeEstimate, ReceiptStatus, ResourceLimits, SendFailure,
    StarknetSend, TxReceipt,
};
pub use txmgr::{InFlightSnapshot, SendOutcome, SendState, TxError, TxManager, TxManagerConfig};
pub use visible::{VisiblePolicy, wait_call_visible};

#[cfg(feature = "test-mocks")]
pub mod mock;
