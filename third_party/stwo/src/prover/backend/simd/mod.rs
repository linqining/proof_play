use serde::{Deserialize, Serialize};

use super::{Backend, BackendForChannel};
use crate::core::channel::MerkleChannel;
#[allow(unused_imports)]
use crate::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
#[cfg(not(target_arch = "wasm32"))]
use crate::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;

pub mod accumulation;
pub mod bit_reverse;
pub mod blake2s;
pub mod blake2s_lifted;
#[cfg(test)]
pub mod blake2s_ref;
pub mod circle;
pub mod cm31;
pub mod column;
pub mod conversion;
pub mod domain;
pub mod fft;
pub mod fri;
mod grind;
pub mod lookups;
pub mod m31;
#[cfg(not(target_arch = "wasm32"))]
pub mod poseidon252;
#[cfg(not(target_arch = "wasm32"))]
pub mod poseidon252_lifted;
pub mod prefix_sum;
pub mod qm31;
pub mod quotients;
mod utils;
pub mod very_packed_m31;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct SimdBackend;

impl Backend for SimdBackend {}
#[cfg(not(target_arch = "wasm32"))]
// [T3-FRI patch] simd 后端 MerkleOpsLifted 按哈希器特化，保持具体实现
// （影子证明走 CpuBackend，见 fri_shadow.rs）。
impl BackendForChannel<Blake2sMerkleChannel> for SimdBackend {}
impl BackendForChannel<Blake2sM31MerkleChannel> for SimdBackend {}
impl BackendForChannel<Poseidon252MerkleChannel> for SimdBackend {}

// Optimal chunk sizes were determined empirically on an intel 155u machine.
pub(super) const PACKED_M31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 9;
pub(super) const PACKED_CM31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 10;
pub(super) const PACKED_QM31_BATCH_INVERSE_CHUNK_SIZE: usize = 1 << 11;
