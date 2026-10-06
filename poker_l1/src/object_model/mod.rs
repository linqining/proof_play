//! 对象模型（Object-Centric State）— Task 2 实现。
//!
//! 模块组成：
//! - [`id`]：ObjectID（NEW-L4 修复）
//! - [`ownership`]：Ownership 枚举（AddressOwned / Shared / Immutable）
//! - [`object`]：Object 结构（id / version / owner / type / data）+ BCS + content-hash
//! - [`smt`]：Sparse Merkle Tree（IMPL-SEC-3 修复）
//!
//! 历史留档（2026-09 死代码清理）：`store`（ObjectStore 内存版 + SMT backing）
//! 在 Phase 2b 前无任何生产消费者，整体移除；状态持久化由 runtime `state_codec`
//! 的专用 schema 承担。

pub mod id;
pub mod object;
pub mod ownership;
pub mod smt;

pub use id::ObjectID;
pub use object::{Object, ObjectData, ObjectType, Version};
pub use ownership::Ownership;
pub use smt::{
    MerklePath, SparseMerkleTree, TREE_DEPTH, empty_hashes, empty_leaf_hash, internal_hash,
    leaf_hash,
};
