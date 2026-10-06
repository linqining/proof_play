//! 内存 mock [`StarknetSend`]（feature `test-mocks`，不触网）。
//!
//! 脚本化语义：`broadcast_results` 按广播顺序消费（耗尽后重复末条），
//! 交易哈希自动分配（`0x1000 + 广播序`）；`receipts_by_broadcast` 按广播
//! 序给出每笔交易的回执轮询序列（每次轮询弹出一个，耗尽后重复末条）；
//! `view_results` 按调用顺序消费。全部意图/视图调用留痕供断言。

use std::collections::VecDeque;
use std::sync::Mutex;

use starknet_types_core::felt::Felt;

use crate::send::{
    BoxFuture, BroadcastIntent, FeeEstimate, ReceiptStatus, SendFailure, StarknetSend, TxReceipt,
};

/// 回执脚本形态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptKind {
    Succeeded,
    Reverted(String),
}

/// mock 脚本。
#[derive(Debug, Clone, Default)]
pub struct MockSendScript {
    /// 链上 nonce 基线（get_nonce 返回值）。
    pub chain_nonce: u64,
    /// 广播结果序列（Ok(()) = 广播成功，哈希自动分配；Err 文案原样返回）。
    pub broadcast_results: Vec<Result<(), String>>,
    /// 每笔（按广播序）的回执轮询序列：None = 未入块；耗尽后重复末条；
    /// 空序列 = 永远 None（回执轮询耗尽路径）。
    pub receipts_by_broadcast: Vec<Vec<Option<ReceiptKind>>>,
    /// view 调用结果序列（耗尽后重复末条；空 = 永远空数组）。
    pub view_results: Vec<Result<Vec<Felt>, String>>,
}

#[derive(Debug, Default)]
struct Inner {
    broadcast_results: VecDeque<Result<(), String>>,
    receipts_by_broadcast: Vec<VecDeque<Option<ReceiptKind>>>,
    view_results: VecDeque<Result<Vec<Felt>, String>>,
    intents: Vec<BroadcastIntent>,
    nonce_queries: usize,
    views: usize,
}

/// 内存 mock。
pub struct MockSend {
    chain_nonce: Felt,
    inner: Mutex<Inner>,
}

impl MockSend {
    pub fn new(script: MockSendScript) -> Self {
        Self {
            chain_nonce: Felt::from(script.chain_nonce),
            inner: Mutex::new(Inner {
                broadcast_results: script.broadcast_results.into(),
                receipts_by_broadcast: script
                    .receipts_by_broadcast
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                view_results: script.view_results.into(),
                intents: Vec::new(),
                nonce_queries: 0,
                views: 0,
            }),
        }
    }

    /// 广播意图留痕（顺序 = 广播顺序）。
    pub fn intents(&self) -> Vec<BroadcastIntent> {
        self.inner
            .lock()
            .map(|g| g.intents.clone())
            .unwrap_or_default()
    }

    /// 广播 nonce 序列（保序断言用）。
    pub fn broadcast_nonces(&self) -> Vec<Felt> {
        self.intents().iter().map(|i| i.nonce).collect()
    }

    /// 广播次数。
    pub fn broadcast_count(&self) -> usize {
        self.intents().len()
    }

    /// get_nonce 查询次数。
    pub fn nonce_queries(&self) -> usize {
        self.inner.lock().map(|g| g.nonce_queries).unwrap_or(0)
    }

    /// view 调用次数。
    pub fn view_calls(&self) -> usize {
        self.inner.lock().map(|g| g.views).unwrap_or(0)
    }
}

impl MockSend {
    fn tx_hash_for(index: usize) -> Felt {
        Felt::from(0x1000u64 + index as u64)
    }
}

impl StarknetSend for MockSend {
    fn broadcast<'a>(
        &'a self,
        intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<Felt, SendFailure>> {
        Box::pin(async move {
            let (idx, result) = {
                let mut g = self.inner.lock().expect("mock lock");
                let idx = g.intents.len();
                g.intents.push(intent.clone());
                (idx, pop_or_last(&mut g.broadcast_results).unwrap_or(Ok(())))
            };
            result
                .map(|_| Self::tx_hash_for(idx))
                .map_err(SendFailure::new)
        })
    }

    fn get_nonce<'a>(&'a self, _account: Felt) -> BoxFuture<'a, Result<Felt, String>> {
        Box::pin(async move {
            self.inner
                .lock()
                .map(|mut g| {
                    g.nonce_queries += 1;
                    self.chain_nonce
                })
                .map_err(|_| "mock lock poisoned".to_string())
        })
    }

    fn estimate_fee<'a>(
        &'a self,
        _intent: &'a BroadcastIntent,
    ) -> BoxFuture<'a, Result<FeeEstimate, String>> {
        Box::pin(async move {
            Ok(FeeEstimate {
                l1_gas: 0,
                l2_gas: 0,
                overall_fee_fri: 0,
            })
        })
    }

    fn get_transaction_receipt<'a>(
        &'a self,
        tx: Felt,
    ) -> BoxFuture<'a, Result<Option<TxReceipt>, String>> {
        Box::pin(async move {
            let bytes = tx.to_bytes_be();
            let be = u64::from_be_bytes(bytes[24..32].try_into().expect("32B felt"));
            if be < 0x1000 {
                return Ok(None);
            }
            let idx = (be - 0x1000) as usize;
            let mut g = self.inner.lock().expect("mock lock");
            let script = g
                .receipts_by_broadcast
                .get_mut(idx)
                .ok_or_else(|| format!("mock: no receipt script for tx {tx}"))?;
            Ok(pop_or_last(script).flatten().map(|kind| TxReceipt {
                tx_hash: tx,
                status: match kind {
                    ReceiptKind::Succeeded => ReceiptStatus::Succeeded,
                    ReceiptKind::Reverted(msg) => ReceiptStatus::Reverted(msg),
                },
                block_number: Some(123),
                actual_fee_fri: 1000,
            }))
        })
    }

    fn call_contract<'a>(
        &'a self,
        _contract: Felt,
        _selector: Felt,
        _calldata: Vec<Felt>,
    ) -> BoxFuture<'a, Result<Vec<Felt>, String>> {
        Box::pin(async move {
            let mut g = self.inner.lock().expect("mock lock");
            g.views += 1;
            Ok(pop_or_last(&mut g.view_results)
                .unwrap_or(Ok(Vec::new()))
                .unwrap_or_default())
        })
    }
}

/// 弹出队首；耗尽后重复末条（None 当完全空）。
fn pop_or_last<T>(queue: &mut VecDeque<T>) -> Option<T>
where
    T: Clone,
{
    if queue.len() > 1 {
        queue.pop_front()
    } else {
        queue.front().cloned()
    }
}
