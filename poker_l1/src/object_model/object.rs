//! Object 结构（SubTask 2.1 + 2.4）。
//!
//! spec：`Object { id, version, owner, type, data }`。
//! - `version`：每次修改 tx 执行成功后 += 1，旧版本保留为不可变历史。
//! - 结算后 `owner` 变为 `Immutable`，后续仅可读不可写。
//! - content-hash = blake2b_256(BCS(Object))，用于对象完整性校验。
//!
//! 历史留档（2026-09 死代码清理）：`assigned_validator`（GameTurn 通道路由目标）
//! 全 workspace 恒 None 且无持久化 schema 写入（state_codec 只序列化 typed table
//! schema，不序列化 Object 壳），字段已删除。

use super::id::ObjectID;
use super::ownership::Ownership;
use crate::Address;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// 对象类型标签（字符串形式，如 "Game" / "Account" / "Contract" / "UpgradeCap"）。
pub type ObjectType = String;

/// 对象版本号。
pub type Version = u64;

/// 对象数据（BCS 序列化的 typed bytes）。
pub type ObjectData = Vec<u8>;

/// 对象（spec：id / version / owner / type / data）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Object {
    /// 对象唯一 ID（NEW-L4：creator_address + creation_nonce）。
    pub id: ObjectID,
    /// 版本号（每次修改 += 1）。
    pub version: Version,
    /// 所有权语义。
    pub owner: Ownership,
    /// 类型标签。
    pub object_type: ObjectType,
    /// 序列化的 typed 数据。
    pub data: ObjectData,
}

impl Object {
    /// 创建新对象（version = 0）。
    pub fn new(
        id: ObjectID,
        owner: Ownership,
        object_type: impl Into<ObjectType>,
        data: ObjectData,
    ) -> Self {
        Self {
            id,
            version: 0,
            owner,
            object_type: object_type.into(),
            data,
        }
    }

    /// 递增版本号（修改 tx 执行成功后调用）。
    pub const fn bump_version(&mut self) {
        self.version = self.version.saturating_add(1);
    }

    /// 冻结对象（结算后调用，owner → Immutable）。
    pub const fn freeze(&mut self) {
        self.owner = Ownership::Immutable;
    }

    /// 校验 `actor` 是否可写。
    pub fn can_write(&self, actor: &Address) -> bool {
        if self.owner.is_immutable() {
            return false;
        }
        self.owner.can_write(actor)
    }

    /// 计算 content-hash = blake2b_256(BCS(self))。
    pub fn content_hash(&self) -> crate::Hash {
        let bytes = borsh::to_vec(self).expect("Object BCS 序列化不会失败");
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&bytes);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_object() -> Object {
        Object::new(
            ObjectID::new([1u8; 20], 1),
            Ownership::AddressOwned { owner: [1u8; 20] },
            "Game",
            b"sample data".to_vec(),
        )
    }

    #[test]
    fn new_object_version_zero() {
        let o = sample_object();
        assert_eq!(o.version, 0);
        assert_eq!(o.object_type, "Game");
    }

    #[test]
    fn bump_version_increments() {
        let mut o = sample_object();
        o.bump_version();
        assert_eq!(o.version, 1);
        o.bump_version();
        assert_eq!(o.version, 2);
    }

    #[test]
    fn freeze_sets_immutable() {
        let mut o = sample_object();
        assert!(o.can_write(&[1u8; 20]));
        o.freeze();
        assert!(!o.can_write(&[1u8; 20]));
        assert!(o.owner.is_immutable());
    }

    #[test]
    fn content_hash_deterministic() {
        let o1 = sample_object();
        let o2 = sample_object();
        assert_eq!(o1.content_hash(), o2.content_hash());

        let mut o3 = sample_object();
        o3.bump_version();
        assert_ne!(o1.content_hash(), o3.content_hash());
    }

    #[test]
    fn object_bcs_roundtrip() {
        let o = sample_object();
        let bytes = borsh::to_vec(&o).unwrap();
        let recovered: Object = borsh::from_slice(&bytes).unwrap();
        assert_eq!(o, recovered);
        assert_eq!(o.content_hash(), recovered.content_hash());
    }

    #[test]
    fn object_json_roundtrip() {
        let o = sample_object();
        let json = serde_json::to_string(&o).unwrap();
        let recovered: Object = serde_json::from_str(&json).unwrap();
        assert_eq!(o, recovered);
    }

    #[test]
    fn can_write_respects_ownership() {
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let o = Object::new(
            ObjectID::new(owner, 0),
            Ownership::AddressOwned { owner },
            "X",
            vec![],
        );
        assert!(o.can_write(&owner));
        assert!(!o.can_write(&other));
    }
}
