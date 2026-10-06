//! # settle-queue —— 结算任务持久化投递队列（正式状态表）
//!
//! 2026-10-01 立项（todo 第 2 项「批量上链 rollup 程序」，调研结论见
//! out/rollup-batch-submitter-survey.md §9）。参照物：zkSync `eth_sender` 的
//! Postgres 落库队列（aggregated_operations，先落库再发交易）与 Arbitrum
//! dataposter 的 DB/Redis 队列持久化——本仓 survey §9.2 的结论是
//! `texas/src/starknet/prove_log.rs` 只是结算输入雏形，应升级成正式状态表；
//! 本 crate 就是那张状态表（文件形态：JSONL WAL + sidecar）。
//!
//! ## 三层分工（与既有代码的边界，勿越界）
//!
//! 1. **prove_log 仍是对账事实源**：`take_settle_input`
//!    （`texas/src/starknet/prove_log.rs:434`）提取结算输入，队列只管投递；
//! 2. **本队列只管投递进度**：状态机的 `Receipted` 是「投递拿到回执」，
//!    **不是业务终态**；
//! 3. **业务终态权威仍是 settle_receipt**：`SettleStatus`
//!    （`texas/src/starknet/settle_receipt.rs:36`）的 Settled/Refused/Failed
//!    词汇不在这里重复定义（纯投递词汇见 [`state::TaskState`]）。
//!
//! ## 单写者文件归属协议（终审修订，双文件互不交叉）
//!
//! - **queue WAL（`queue.jsonl`）唯一写者 = texas**：append 入队
//!   （[`wal::QueueWal::enqueue`]）、构建期死信标记
//!   （[`wal::QueueWal::build_dead_letter`]）、Dual→Legacy 降级迁移
//!   （[`wal::QueueWal::downgrade`]，仅由 texas 依据 poster sidecar 回读
//!   触发写入）。poster 只读 WAL（游标扫描尾部，[`wal::scan_from`]）。
//! - **poster 独占 sidecar**（[`sidecar::PosterSidecar`]）：拾取游标/在途
//!   快照写 `poster-state.json`，回执写 `receipts/<key>.json`，投递期死信
//!   写 `dead/<key>.json`，fold 批记录写 `batches/<batch_key>.json`——全部
//!   经临时文件 + rename 原子写。texas 扫 sidecar 观察停发与对账，**只读**。
//!
//! **DeadLetter 双源归属**：构建期死信（对账拒绝/构建失败，发生在入队前后）
//! 由 texas 写 WAL；投递期死信（dual 腿重试耗尽，含降级后仍耗尽）由 poster
//! 写 `dead/<key>.json`。texas 扫 sidecar 发现 Dual 路投递期死信 → 执行
//! Dual→Legacy 降级（写 WAL）→ poster 下轮观察到 WAL 路由已变 Legacy →
//! 清死信、按 Legacy 重投（降级后仍耗尽 = 终态死信，停发观察）。
//!
//! ## 键域（单手键做队列去重，批键做批幂等，键域闭合）
//!
//! - 单手键 [`task::SettleKey`] = `(table_id, hand_id)`，仅做队列去重；
//! - fold 批不进队列键域：批级状态在 poster sidecar，批键
//!   `batch_key = keccak_root`（对齐 `stark-recursion/src/chain.rs` 的
//!   keccak 批根，同时是 zchain 侧幂等键与 MonadProofEnvelope 主键），
//!   `members: Vec<SettleKey>` 引用单手键（见 batch-poster crate）。
//!
//! ## 纪律复用声明
//!
//! payout-sidecar（Node 运行时，代码不可共用）的「队列 → 随机延迟抖动 →
//! 有界重试 → 投递 → DeadLetter 终态」纪律在本层以 Rust 语义复刻：有界
//! 重试上限由 poster 运营配置携带（batch-poster），死信终态词沿用
//! DeadLetter。

pub mod sidecar;
pub mod state;
pub mod task;
pub mod wal;

pub use sidecar::{
    BatchRecord, BatchState, DeadRecord, PosterSidecar, PosterStateFile, ReceiptRecord,
    atomic_write_json,
};
pub use state::{DeadLetterSource, SubmitPhase, TaskRecord, TaskState};
pub use task::{
    FoldStatement, LegCalldata, SettleKey, SettlePayload, SettleRoute, SettleTask, route_for_exit,
};
pub use wal::{EnqueueError, QueueState, QueueWal, WalError, WalEvent, scan_from};
