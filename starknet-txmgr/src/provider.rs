//! 生产实现 [`ProviderSend`]：包 texas 已依赖的 starknet 0.17
//! Provider/账户层（本层骨架只要求编译通过，不动 texas 现有调用点）。
//!
//! 读面直接走 `starknet::providers::Provider`（texas/src/starknet/chain.rs:87
//! 的 call 先例同源）；广播面走账户层 `execute_v3`（v3 资源上限 +
//! txmgr 分配的 nonce，签名/编码留在账户层——本层不重建 calldata）。

use std::sync::Arc;

use starknet::accounts::{Account as _, ConnectedAccount};
use starknet::core::types::{
    BlockId, ExecutionResult, FeeEstimate as SgFeeEstimate, Felt, FunctionCall,
    InvokeTransactionResult, ReceiptBlock, TransactionReceipt as SgReceipt,
    TransactionReceiptWithBlockInfo,
};
use starknet::providers::Provider as StarknetProvider;

use crate::send::{
    BoxFuture, BroadcastIntent, Call, FeeEstimate, ReceiptStatus, ResourceLimits, SendFailure,
    StarknetSend, TxReceipt,
};

/// 生产 [`StarknetSend`]：泛型于任意已连接账户（texas 用
/// `SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>`，见
/// texas/src/starknet/chain.rs:7-10 的既有装配）。
///
/// **nonce/view 块位随账户**（2026-10-01 修正）：读面（get_nonce /
/// call_contract）用 `account.block_id()` 而非本层自选——两个宿主（texas
/// chain.rs:68、batch-poster bin）的账户都钉在 PreConfirmed：结算账户连续
/// 发交易，Latest 块位读 nonce 看不见在途交易，连续两腿会撞 nonce。
pub struct ProviderSend<A>
where
    A: ConnectedAccount + Send + Sync + 'static,
{
    account: Arc<A>,
}

impl<A> ProviderSend<A>
where
    A: ConnectedAccount + Send + Sync + 'static,
    A::Provider: StarknetProvider + Send + Sync,
{
    pub fn new(account: Arc<A>) -> Self {
        Self { account }
    }

    fn provider(&self) -> &A::Provider {
        self.account.provider()
    }

    fn block_id(&self) -> BlockId {
        self.account.block_id()
    }
}

/// 本层 [`Call`] → starknet `Call`。
fn sg_call(call: &Call) -> starknet::core::types::Call {
    starknet::core::types::Call {
        to: call.to,
        selector: call.selector,
        calldata: call.calldata.clone(),
    }
}

impl<A> StarknetSend for ProviderSend<A>
where
    A: ConnectedAccount + Send + Sync + 'static,
    A::Provider: StarknetProvider + Send + Sync,
{
    fn broadcast<'a>(
        &'a self,
        intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<Felt, SendFailure>> {
        Box::pin(async move {
            let calls: Vec<starknet::core::types::Call> =
                intent.calls.iter().map(sg_call).collect();
            // v3 资源上限 + txmgr 分配的 nonce；签名由账户层完成。
            let result: Result<InvokeTransactionResult, _> = self
                .account
                .execute_v3(calls)
                .nonce(intent.nonce)
                .l1_gas(intent.limits.l1_gas)
                .l1_gas_price(intent.limits.l1_gas_price_fri)
                .l2_gas(intent.limits.l2_gas)
                .l2_gas_price(intent.limits.l2_gas_price_fri)
                .send()
                .await;
            result
                .map(|r| r.transaction_hash)
                .map_err(|e| SendFailure::new(e.to_string()))
        })
    }

    fn get_nonce<'a>(&'a self, account: Felt) -> BoxFuture<'a, Result<Felt, String>> {
        Box::pin(async move {
            self.provider()
                .get_nonce(self.block_id(), account)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn estimate_fee<'a>(
        &'a self,
        intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<FeeEstimate, String>> {
        Box::pin(async move {
            let calls: Vec<starknet::core::types::Call> =
                intent.calls.iter().map(sg_call).collect();
            let est: SgFeeEstimate = self
                .account
                .execute_v3(calls)
                .nonce(intent.nonce)
                .l1_gas(intent.limits.l1_gas)
                .l1_gas_price(intent.limits.l1_gas_price_fri)
                .l2_gas(intent.limits.l2_gas)
                .l2_gas_price(intent.limits.l2_gas_price_fri)
                .estimate_fee()
                .await
                .map_err(|e| e.to_string())?;
            Ok(FeeEstimate {
                l1_gas: est.l1_gas_consumed,
                l2_gas: est.l2_gas_consumed,
                overall_fee_fri: est.overall_fee,
            })
        })
    }

    fn get_transaction_receipt<'a>(
        &'a self,
        tx: Felt,
    ) -> BoxFuture<'a, Result<Option<TxReceipt>, String>> {
        Box::pin(async move {
            let r: TransactionReceiptWithBlockInfo = self
                .provider()
                .get_transaction_receipt(tx)
                .await
                .map_err(|e| e.to_string())?;
            let (tx_hash, execution, actual_fee) = match &r.receipt {
                SgReceipt::Invoke(t) => (t.transaction_hash, &t.execution_result, &t.actual_fee),
                SgReceipt::L1Handler(t) => (t.transaction_hash, &t.execution_result, &t.actual_fee),
                SgReceipt::Declare(t) => (t.transaction_hash, &t.execution_result, &t.actual_fee),
                SgReceipt::Deploy(t) => (t.transaction_hash, &t.execution_result, &t.actual_fee),
                SgReceipt::DeployAccount(t) => {
                    (t.transaction_hash, &t.execution_result, &t.actual_fee)
                }
            };
            Ok(Some(TxReceipt {
                tx_hash,
                status: match execution {
                    ExecutionResult::Succeeded => ReceiptStatus::Succeeded,
                    ExecutionResult::Reverted { reason } => ReceiptStatus::Reverted(reason.clone()),
                },
                block_number: Some(match &r.block {
                    ReceiptBlock::PreConfirmed { block_number } => *block_number,
                    ReceiptBlock::Block { block_number, .. } => *block_number,
                }),
                actual_fee_fri: felt_to_u128(actual_fee.amount),
            }))
        })
    }

    fn call_contract<'a>(
        &'a self,
        contract: Felt,
        selector: Felt,
        calldata: Vec<Felt>,
    ) -> BoxFuture<'a, Result<Vec<Felt>, String>> {
        Box::pin(async move {
            self.provider()
                .call(
                    FunctionCall {
                        contract_address: contract,
                        entry_point_selector: selector,
                        calldata,
                    },
                    self.block_id(),
                )
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// Felt → u128（费用金额饱和截断——观测值，不参与资金判定）。
fn felt_to_u128(f: Felt) -> u128 {
    let bytes = f.to_bytes_be();
    u128::from_be_bytes(bytes[16..32].try_into().expect("16 bytes"))
}

// ResourceLimits 由 BroadcastIntent 携带进生产路径（类型对齐说明：生产实现
// 不单独消费该类型——上限随 intent 传入 execute_v3 builder）。
const _: Option<ResourceLimits> = None;
