//! Proof serialization helpers for the `texas_poker_move` contract.
//!
//! These functions convert Rust crypto proof types to the byte format expected
//! by the Move contract's `zk_verifier` / `table_serialization` modules.
//!
//! Extracted from `move_verify_tests.rs` so they can be reused by socket
//! handlers when building on-chain PTBs for shuffle / reconstruct / reveal /
//! join_and_shuffle actions.

use poker_protocol::crypto::{EcPoint, Scalar};
use poker_protocol::crypto::curve::{CurvePoint, CurveScalar};
use poker_protocol::z_poker::key_manager::PKOwnershipProof;

// ============================================================================
// Constants
// ============================================================================

// ============================================================================
// Serialization helpers
// ============================================================================

/// 将 G1 点序列化为 48 字节压缩格式
pub fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    p.compress().as_ref().to_vec()
}

/// 将标量序列化为 32 字节
pub fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.as_bytes()
}

/// 序列化 PKOwnershipProof 为 Move 合约期望的字节格式
/// 格式: commitment(48) + response(32) = 80 bytes
pub fn serialize_pk_ownership_proof(proof: &PKOwnershipProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf
}
