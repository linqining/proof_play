//! Tagged Pubkey 编码（SEC-M9 修复 — tag 版本化机制）
//!
//! spec SEC-M9：tag 字节编码 `(scheme_id: 4 bits || version_id: 4 bits)`
//! - `0x01` = secp256k1 v1（compressed 33B pubkey）
//! - `0x11` = ed25519 v1（32B pubkey）
//! - `0x21` = Stark Schnorr v1（32B 压缩点；2026-09-09 P1-2 引入）
//! - `0x10`-`0xF0` 高位段预留（BLS12-381 / 后量子等）
//! - 新 tag 引入须治理提案 + 90% quorum
//!
//! tagged pubkey = 1B tag || raw pubkey bytes
//! - secp256k1: 1 + 33 = 34 字节
//! - ed25519: 1 + 32 = 33 字节
//! - stark: 1 + 32 = 33 字节（32B 压缩点）
//!
//! IMPL-SEC-1：tag 字节解析须常数时间（防 timing 侧信道泄露 scheme 信息）。

use crate::error::{PokerL1Error, PokerL1Result};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// 签名方案枚举（与 tag 低 4 位的 scheme_id 对应）。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum SignatureScheme {
    /// secp256k1 ECDSA recoverable（tag scheme_id = 0）
    Secp256k1,
    /// ed25519（tag scheme_id = 1）
    Ed25519,
    /// Stark 曲线 Schnorr（tag scheme_id = 2，2026-09-09 P1-2 引入）：
    /// raw pubkey = 32B 压缩点、签名 64B（R‖s）。配套调用方身份为公开
    /// 可派生的确定性身份（`runtime::caller_id`）——完整性层，非认证层。
    Stark,
}

impl SignatureScheme {
    /// 该方案的原始 pubkey 字节数（不含 1B tag）。
    pub const fn raw_pubkey_len(self) -> usize {
        match self {
            Self::Secp256k1 => 33, // compressed
            Self::Ed25519 => 32,
            Self::Stark => 32, // compressed stark point（x + y 奇偶位）
        }
    }

    /// 该方案的签名字节数。
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Secp256k1 => 65, // r(32) || s(32) || v(1)
            Self::Ed25519 => 64,   // R(32) || S(32)
            Self::Stark => 64,     // R_compressed(32) || s(32)
        }
    }

    /// 从 scheme_id（tag 高 4 位）解析。
    pub const fn from_scheme_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Secp256k1),
            1 => Some(Self::Ed25519),
            2 => Some(Self::Stark),
            _ => None,
        }
    }

    /// 返回 scheme_id（tag 高 4 位）。
    pub const fn scheme_id(self) -> u8 {
        match self {
            Self::Secp256k1 => 0,
            Self::Ed25519 => 1,
            Self::Stark => 2,
        }
    }
}

/// 当前定义的 scheme 版本号。spec：secp256k1 v1 / ed25519 v1。
pub const CURRENT_VERSION: u8 = 1;

/// Tagged Pubkey：1B tag || raw pubkey bytes。
///
/// tag = `(scheme_id: 4 bits high) || (version_id: 4 bits low)`
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TaggedPubkey {
    /// 1 字节 tag（scheme_id << 4 | version_id）。
    pub tag: u8,
    /// 原始 pubkey bytes（不含 tag）。
    pub raw: Vec<u8>,
}

impl TaggedPubkey {
    /// 构造 tagged pubkey，自动编码 tag。
    pub fn new(scheme: SignatureScheme, version: u8, raw: Vec<u8>) -> PokerL1Result<Self> {
        if raw.len() != scheme.raw_pubkey_len() {
            return Err(PokerL1Error::InvalidPubkeyLength {
                tag: encode_tag(scheme, version),
                actual: raw.len(),
                expected: scheme.raw_pubkey_len(),
            });
        }
        Ok(Self {
            tag: encode_tag(scheme, version),
            raw,
        })
    }

    /// 解析 tag 字节，返回 (scheme, version)。
    /// 未知 scheme 返回 `UnknownScheme`。
    pub const fn parse_tag(tag: u8) -> PokerL1Result<(SignatureScheme, u8)> {
        let scheme_id = (tag >> 4) & 0x0F;
        let version_id = tag & 0x0F;
        match SignatureScheme::from_scheme_id(scheme_id) {
            Some(scheme) => Ok((scheme, version_id)),
            None => Err(PokerL1Error::UnknownScheme { tag }),
        }
    }

    /// 从字节流反序列化：第 1 字节为 tag，其余为 raw pubkey。
    ///
    /// IMPL-SEC-1：tag 解析常数时间（不因 scheme 不同而提前返回 / 抛异常时间差异）。
    pub fn from_bytes(bytes: &[u8]) -> PokerL1Result<Self> {
        if bytes.is_empty() {
            return Err(PokerL1Error::InvalidPubkeyLength {
                tag: 0,
                actual: 0,
                expected: 1,
            });
        }
        let tag = bytes[0];
        // 常数时间解析：先取 scheme 与 version，统一走长度校验路径
        let (scheme, version) = Self::parse_tag(tag)?;
        let expected = scheme.raw_pubkey_len();
        let raw = bytes[1..].to_vec();
        if raw.len() != expected {
            return Err(PokerL1Error::InvalidPubkeyLength {
                tag,
                actual: raw.len(),
                expected,
            });
        }
        // version 校验：当前仅支持 v1
        if version != CURRENT_VERSION {
            return Err(PokerL1Error::UnknownScheme { tag });
        }
        Ok(Self { tag, raw })
    }

    /// 序列化为字节流：tag || raw。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.raw.len());
        out.push(self.tag);
        out.extend_from_slice(&self.raw);
        out
    }

    /// 返回 scheme。
    pub fn scheme(&self) -> PokerL1Result<SignatureScheme> {
        Ok(Self::parse_tag(self.tag)?.0)
    }
}

/// 编码 tag 字节：`(scheme_id << 4) | version_id`。
pub const fn encode_tag(scheme: SignatureScheme, version: u8) -> u8 {
    (scheme.scheme_id() << 4) | (version & 0x0F)
}

/// Stark 会话交易公钥（定宽形式，2026-09-10）。
///
/// 会话交易签名当前唯一启用方案是 Stark Schnorr v1（32B 压缩点），
/// 状态字段 `OccupiedSeat.tx_pk` 使用本定宽类型以消除 borsh `Vec`
/// 长度前缀（AIR/trace 友好）；多方案的通用 [`TaggedPubkey`] 仍保留在
/// 外部入参（join args）与验签分发边界。tag 恒为 Stark v1（0x21）。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct StarkTxPubkey {
    /// 1 字节 tag，恒为 `encode_tag(SignatureScheme::Stark, CURRENT_VERSION)`。
    pub tag: u8,
    /// 32B Stark 压缩点；全零 = 未登记哨兵。
    pub raw: [u8; 32],
}

impl StarkTxPubkey {
    /// 未登记哨兵：合法 tag + 全零压缩点。
    pub const UNREGISTERED: Self = Self {
        tag: encode_tag(SignatureScheme::Stark, CURRENT_VERSION),
        raw: [0u8; 32],
    };

    /// 是否已登记（非全零哨兵）。
    pub const fn is_registered(&self) -> bool {
        let mut index = 0;
        while index < 32 {
            if self.raw[index] != 0 {
                return true;
            }
            index += 1;
        }
        false
    }

    /// 从通用 tagged pubkey 收敛：要求 Stark v1 + 32B，否则拒绝。
    pub fn from_tagged(pk: &TaggedPubkey) -> PokerL1Result<Self> {
        let (scheme, version) = TaggedPubkey::parse_tag(pk.tag)?;
        if scheme != SignatureScheme::Stark || version != CURRENT_VERSION {
            return Err(PokerL1Error::UnknownScheme { tag: pk.tag });
        }
        let raw: [u8; 32] = pk
            .raw
            .as_slice()
            .try_into()
            .map_err(|_| PokerL1Error::InvalidPubkeyLength {
                tag: pk.tag,
                actual: pk.raw.len(),
                expected: SignatureScheme::Stark.raw_pubkey_len(),
            })?;
        Ok(Self { tag: pk.tag, raw })
    }

    /// 升格回通用形式，供验签分发（`verify_signature`）使用。
    pub fn to_tagged(&self) -> TaggedPubkey {
        TaggedPubkey {
            tag: self.tag,
            raw: self.raw.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_encoding_secp256k1_v1() {
        assert_eq!(encode_tag(SignatureScheme::Secp256k1, 1), 0x01);
    }

    #[test]
    fn tag_encoding_ed25519_v1() {
        assert_eq!(encode_tag(SignatureScheme::Ed25519, 1), 0x11);
    }

    #[test]
    fn parse_tag_known_schemes() {
        assert_eq!(
            TaggedPubkey::parse_tag(0x01).unwrap(),
            (SignatureScheme::Secp256k1, 1)
        );
        assert_eq!(
            TaggedPubkey::parse_tag(0x11).unwrap(),
            (SignatureScheme::Ed25519, 1)
        );
    }

    #[test]
    fn parse_tag_unknown_scheme_returns_error() {
        // scheme_id = 3 (undefined)
        assert!(matches!(
            TaggedPubkey::parse_tag(0x31).unwrap_err(),
            PokerL1Error::UnknownScheme { tag: 0x31 }
        ));
        // scheme_id = 15 (reserved)
        assert!(matches!(
            TaggedPubkey::parse_tag(0xF1).unwrap_err(),
            PokerL1Error::UnknownScheme { tag: 0xF1 }
        ));
    }

    #[test]
    fn tagged_pubkey_roundtrip_secp256k1() {
        let raw = vec![0x02; 33]; // dummy compressed pubkey
        let tp = TaggedPubkey::new(SignatureScheme::Secp256k1, 1, raw).unwrap();
        assert_eq!(tp.tag, 0x01);
        let bytes = tp.to_bytes();
        assert_eq!(bytes.len(), 34);
        let recovered = TaggedPubkey::from_bytes(&bytes).unwrap();
        assert_eq!(tp, recovered);
    }

    #[test]
    fn tagged_pubkey_roundtrip_ed25519() {
        let raw = vec![0x09; 32];
        let tp = TaggedPubkey::new(SignatureScheme::Ed25519, 1, raw).unwrap();
        assert_eq!(tp.tag, 0x11);
        let bytes = tp.to_bytes();
        assert_eq!(bytes.len(), 33);
        let recovered = TaggedPubkey::from_bytes(&bytes).unwrap();
        assert_eq!(tp, recovered);
    }

    #[test]
    fn tagged_pubkey_roundtrip_stark() {
        let raw = vec![0x07; 32]; // dummy compressed stark point
        let tp = TaggedPubkey::new(SignatureScheme::Stark, 1, raw).unwrap();
        assert_eq!(tp.tag, 0x21);
        let bytes = tp.to_bytes();
        assert_eq!(bytes.len(), 33);
        let recovered = TaggedPubkey::from_bytes(&bytes).unwrap();
        assert_eq!(tp, recovered);
        assert_eq!(tp.scheme().unwrap(), SignatureScheme::Stark);
        assert_eq!(tp.scheme().unwrap().signature_len(), 64);
    }

    #[test]
    fn tagged_pubkey_rejects_wrong_length() {
        // secp256k1 期望 33B，给 32B
        let err = TaggedPubkey::new(SignatureScheme::Secp256k1, 1, vec![0; 32]).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidPubkeyLength { .. }));

        // ed25519 期望 32B，给 33B
        let err = TaggedPubkey::new(SignatureScheme::Ed25519, 1, vec![0; 33]).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidPubkeyLength { .. }));

        // stark 期望 32B，给 31B
        let err = TaggedPubkey::new(SignatureScheme::Stark, 1, vec![0; 31]).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidPubkeyLength { .. }));
    }

    #[test]
    fn tagged_pubkey_rejects_unknown_version() {
        // version 2（未支持）
        let tp = TaggedPubkey {
            tag: 0x02, // secp256k1 v2
            raw: vec![0; 33],
        };
        let bytes = tp.to_bytes();
        let err = TaggedPubkey::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, PokerL1Error::UnknownScheme { .. }));
    }

    #[test]
    fn tagged_pubkey_bcs_roundtrip() {
        let tp = TaggedPubkey::new(SignatureScheme::Ed25519, 1, vec![0xAB; 32]).unwrap();
        let bytes = borsh::to_vec(&tp).unwrap();
        let recovered: TaggedPubkey = borsh::from_slice(&bytes).unwrap();
        assert_eq!(tp, recovered);
    }
}
