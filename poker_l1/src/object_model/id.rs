//! ObjectID（NEW-L4 修复实现）
//!
//! spec NEW-L4：`ObjectID = (creator_address: [u8;20], creation_nonce: u64)` 二元组。
//! 全局唯一性保证：
//! - 同一 creator 的 creation_nonce 单调递增不复用
//! - 不同 creator address 不碰撞（address 由 tagged_pubkey 派生，不同曲线不碰撞）
//!
//! （历史：ObjectStore 创建时校验 ObjectID 不存在；ObjectStore 已随死代码清理移除。）

use crate::Address;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// 对象创建 nonce（每账户单调递增）。
pub type CreationNonce = u64;

/// ObjectID = (creator_address, creation_nonce)（NEW-L4 修复）。
///
/// 28 字节定长：20 字节 creator_address + 8 字节 creation_nonce（little-endian）。
/// 全局唯一性由「creator nonce 单调递增 + 不同 creator address 不碰撞」保证。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct ObjectID {
    /// 创建者地址（blake2b_256(tagged_pubkey)[0..20]）。
    pub creator_address: Address,
    /// 创建者账户的 creation_nonce（单调递增）。
    pub creation_nonce: CreationNonce,
}

impl ObjectID {
    /// 构造新 ObjectID。
    pub const fn new(creator_address: Address, creation_nonce: CreationNonce) -> Self {
        Self {
            creator_address,
            creation_nonce,
        }
    }

    /// 序列化为 28 字节定长（creator_address || creation_nonce_le）。
    pub fn to_bytes(&self) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[..20].copy_from_slice(&self.creator_address);
        out[20..].copy_from_slice(&self.creation_nonce.to_le_bytes());
        out
    }

    /// 从 28 字节反序列化。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 28 {
            return None;
        }
        let mut creator_address = [0u8; 20];
        creator_address.copy_from_slice(&bytes[..20]);
        let mut nonce_bytes = [0u8; 8];
        nonce_bytes.copy_from_slice(&bytes[20..]);
        Some(Self {
            creator_address,
            creation_nonce: u64::from_le_bytes(nonce_bytes),
        })
    }

    /// 计算 ObjectID 的 blake2b_256，用作 Sparse Merkle Tree 的 256-bit key（IMPL-SEC-3）。
    pub fn merkle_key(&self) -> crate::Hash {
        let bytes = self.to_bytes();
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&bytes);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

impl std::fmt::Display for ObjectID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "0x{}{}",
            hex::encode(self.creator_address),
            hex::encode(self.creation_nonce.to_le_bytes())
        )
    }
}

impl Default for ObjectID {
    fn default() -> Self {
        Self::new([0u8; 20], 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objectid_roundtrip_bytes() {
        let id = ObjectID::new([0xab; 20], 123_456);
        let bytes = id.to_bytes();
        assert_eq!(bytes.len(), 28);
        let recovered = ObjectID::from_bytes(&bytes).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn objectid_rejects_wrong_length() {
        assert!(ObjectID::from_bytes(&[0u8; 27]).is_none());
        assert!(ObjectID::from_bytes(&[0u8; 29]).is_none());
        assert!(ObjectID::from_bytes(&[]).is_none());
    }

    #[test]
    fn objectid_merkle_key_deterministic() {
        let id = ObjectID::new([0x01; 20], 42);
        let k1 = id.merkle_key();
        let k2 = id.merkle_key();
        assert_eq!(k1, k2, "merkle_key 必须确定性");
    }

    #[test]
    fn objectid_different_creators_dont_collide() {
        let id1 = ObjectID::new([0x01; 20], 1);
        let id2 = ObjectID::new([0x02; 20], 1);
        assert_ne!(id1, id2);
        assert_ne!(id1.merkle_key(), id2.merkle_key());
    }

    #[test]
    fn objectid_same_creator_different_nonce_dont_collide() {
        let id1 = ObjectID::new([0x01; 20], 1);
        let id2 = ObjectID::new([0x01; 20], 2);
        assert_ne!(id1, id2);
        assert_ne!(id1.merkle_key(), id2.merkle_key());
    }

    #[test]
    fn objectid_bcs_roundtrip() {
        let id = ObjectID::new([0xcd; 20], 999);
        let bytes = borsh::to_vec(&id).unwrap();
        let recovered: ObjectID = borsh::from_slice(&bytes).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn objectid_json_roundtrip() {
        let id = ObjectID::new([0xee; 20], 7777);
        let json = serde_json::to_string(&id).unwrap();
        let recovered: ObjectID = serde_json::from_str(&json).unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn objectid_ordering_total() {
        // BTreeMap / BTreeSet 依赖全序关系
        let a = ObjectID::new([0; 20], 1);
        let b = ObjectID::new([0; 20], 2);
        let c = ObjectID::new([1; 20], 0);
        assert!(a < b);
        assert!(b < c);
    }
}
