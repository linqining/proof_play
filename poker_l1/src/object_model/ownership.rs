//! Ownership 枚举（SubTask 2.2）。
//!
//! 定义对象所有权的三种语义：
//! - `AddressOwned`：单一地址拥有（可转移）
//! - `Shared`：所有 validator 共享（如 Game 对象）
//! - `Immutable`：不可变（结算后冻结，仅可读）
//!
//! 历史留档（2026-09 死代码清理）：`ChannelOwner`（assigned_validator 独占写权，
//! GameTurn 通道语义）从未在生产构造，且随 `ObjectStore` / `Object.assigned_validator`
//! 一并移除；GameTurn 通道接线恢复时应连同构造点一起恢复。

use crate::Address;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// 对象所有权语义。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Default,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum Ownership {
    /// 单一地址拥有，可转移。
    AddressOwned {
        /// 持有者地址。
        owner: Address,
    },
    /// 共享对象（所有 validator 可见，写入需共识）。
    #[default]
    Shared,
    /// 不可变对象（结算后冻结，仅可读不可写）。
    Immutable,
}

impl Ownership {
    /// 是否可被 `actor` 写入。
    pub fn can_write(&self, actor: &Address) -> bool {
        match self {
            Self::AddressOwned { owner } => owner == actor,
            Self::Shared => true, // 共享对象写入由共识层校验，这里允许
            Self::Immutable => false,
        }
    }

    /// 是否可转移（AddressOwned 可转移；Shared/Immutable 不可）。
    pub const fn is_transferable(&self) -> bool {
        matches!(self, Self::AddressOwned { .. })
    }

    /// 是否为不可变。
    pub const fn is_immutable(&self) -> bool {
        matches!(self, Self::Immutable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_owned_can_write_only_by_owner() {
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let o = Ownership::AddressOwned { owner };
        assert!(o.can_write(&owner));
        assert!(!o.can_write(&other));
        assert!(o.is_transferable());
        assert!(!o.is_immutable());
    }

    #[test]
    fn shared_allows_write() {
        let o = Ownership::Shared;
        assert!(o.can_write(&[0u8; 20]));
        assert!(!o.is_transferable());
    }

    #[test]
    fn immutable_blocks_all_writes() {
        let o = Ownership::Immutable;
        assert!(!o.can_write(&[1u8; 20]));
        assert!(!o.can_write(&[2u8; 20]));
        assert!(o.is_immutable());
        assert!(!o.is_transferable());
    }

    #[test]
    fn ownership_bcs_roundtrip() {
        let cases = vec![
            Ownership::AddressOwned { owner: [1u8; 20] },
            Ownership::Shared,
            Ownership::Immutable,
        ];
        for o in cases {
            let bytes = borsh::to_vec(&o).unwrap();
            let recovered: Ownership = borsh::from_slice(&bytes).unwrap();
            assert_eq!(o, recovered);
        }
    }
}
