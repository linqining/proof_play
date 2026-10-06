//! 合约调用边界类型（Phase 1 收缩版）。
//!
//! 原 rBPF 合约 dispatch 路由（hand_started / force_advance / settle 等
//! GameContract 方法表）属 L1 链机制，已随 2026-09-05 模型收缩移除。
//! Texas Poker 的方法路由在 [`super::texas_poker::dispatch`]（19 个 active
//! selector），与本模块仅共享本文件定义的上下文/结果类型。

use borsh::{BorshDeserialize, BorshSerialize};

use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::{Address, BlockHeight, ChainId};

/// 合约调用上下文（传递给 dispatch 的执行环境）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DispatchContext {
    /// 调用者地址。
    pub caller: Address,
    /// 调用者 tagged_pubkey。
    pub caller_pubkey: TaggedPubkey,
    /// 链 ID。
    pub chain_id: ChainId,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: u64,
}

/// Dispatch 执行结果。
///
/// 包含状态变更信息，调用方据此跟踪对象变更并解析返回值
/// （texas_poker 的 `return_value` = borsh(DispatchOutput)，含 ProveTask）。
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// 新创建的对象 ID 列表。
    pub created_objects: Vec<ObjectID>,
    /// 修改的对象 ID 列表。
    pub modified_objects: Vec<ObjectID>,
    /// 返回值（borsh 编码，可被调用者解析）。
    pub return_value: Vec<u8>,
}

impl DispatchResult {
    /// 创建空结果（无状态变更）。
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![],
            return_value: vec![],
        }
    }
}
