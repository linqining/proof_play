//! [`StarknetSend`] 注入接缝：交易管理层的全部链上触点收敛为五个方法。
//!
//! 沿 `texas/src/starknet/dual_settle.rs:228` `BatchProver` 的既有先例用手写
//! `Pin<Box<dyn Future>>`（不引 async-trait 依赖）。Felt 载体 =
//! `starknet_types_core::felt::Felt`（与 starknet 0.17 / poker-protocol-core /
//! texas 同一类型实例，根 Cargo.toml 全仓统一注释）。

use starknet_types_core::felt::Felt;

/// 手写 boxed future（沿 BatchProver 先例）。
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// 一笔合约调用（selector 语义与 starknet `Call` 同构）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub to: Felt,
    pub selector: Felt,
    pub calldata: Vec<Felt>,
}

impl Call {
    pub fn new(to: Felt, selector: Felt, calldata: Vec<Felt>) -> Self {
        Self {
            to,
            selector,
            calldata,
        }
    }
}

/// v3 资源上限（STRK 计价 fri）：本层的加价重发按此基线放大。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub l1_gas: u64,
    pub l1_gas_price_fri: u128,
    pub l2_gas: u64,
    pub l2_gas_price_fri: u128,
}

impl ResourceLimits {
    /// 按百分比加价（RBF 梯度；Arbitrum dataposter 式逐次放大）。
    pub fn bumped_by_pct(&self, pct: u64) -> Self {
        let f64mul = |v: u64| v.saturating_mul(100 + pct) / 100;
        let f128 = |v: u128| v.saturating_mul(100 + pct as u128) / 100;
        Self {
            l1_gas: f64mul(self.l1_gas),
            l1_gas_price_fri: f128(self.l1_gas_price_fri),
            l2_gas: f64mul(self.l2_gas),
            l2_gas_price_fri: f128(self.l2_gas_price_fri),
        }
    }
}

/// 广播意图：nonce + 调用集 + 资源上限（签名由实现侧账户层完成）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastIntent {
    pub nonce: Felt,
    pub calls: Vec<Call>,
    pub limits: ResourceLimits,
}

/// 广播失败（错误文案保留原文——重放分类的输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFailure {
    pub message: String,
}

impl SendFailure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// 费率估计（v3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeEstimate {
    pub l1_gas: u64,
    pub l2_gas: u64,
    pub overall_fee_fri: u128,
}

/// 回执执行状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptStatus {
    Succeeded,
    /// Reverted（携带合约 revert 文案——重放分类输入）。
    Reverted(String),
}

/// 交易回执（本层归一化形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceipt {
    pub tx_hash: Felt,
    pub status: ReceiptStatus,
    pub block_number: Option<u64>,
    pub actual_fee_fri: u128,
}

/// Starknet 发送/读取接缝——交易管理层的唯一链上触点。
///
/// 生产实现 [`crate::provider::ProviderSend`]；测试用 mock
/// （feature `test-mocks`）。
pub trait StarknetSend: Send + Sync {
    /// 广播一笔已定价交易（实现侧负责签名；nonce 已由 txmgr 分配）。
    fn broadcast<'a>(
        &'a self,
        intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<Felt, SendFailure>>;

    /// 账户当前链上 nonce（nonce 推断基线）。
    fn get_nonce<'a>(&'a self, account: Felt) -> BoxFuture<'a, Result<Felt, String>>;

    /// 费率估计（v3 资源画像）。
    fn estimate_fee<'a>(
        &'a self,
        intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<FeeEstimate, String>>;

    /// 回执轮询；`None` = 尚不可见（未入块/被丢弃）。
    fn get_transaction_receipt<'a>(
        &'a self,
        tx: Felt,
    ) -> BoxFuture<'a, Result<Option<TxReceipt>, String>>;

    /// view 调用（wait_call_visible 的探测通道）。
    fn call_contract<'a>(
        &'a self,
        contract: Felt,
        selector: Felt,
        calldata: Vec<Felt>,
    ) -> BoxFuture<'a, Result<Vec<Felt>, String>>;
}
