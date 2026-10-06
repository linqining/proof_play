//! 多曲线钱包签名统一接口（Task 5 实现）
//!
//! 模块组成：
//! - [`tagged_pubkey`]：TaggedPubkey 编码（SEC-M9 tag 版本化）
//! - [`secp256k1_scheme`]：secp256k1 ECDSA recoverable（NEW-L1 low-s + SEC-L2 时机 + IMPL-SEC-1 常数时间）
//! - [`ed25519_scheme`]：ed25519（SEC2-L1 签名规范化）
//! - [`stark_scheme`]：Stark 曲线 Schnorr（P1-2 确定性身份配套，2026-09-09）
//! - [`ct_util`]：32B big-endian 常数时间比较工具（IMPL-SEC-1）
//! - [`unified`]：统一 `verify_signature(tagged_pubkey, sig, msg_hash)` 按 tag 路由

pub mod ct_util;
pub mod ed25519_scheme;
pub mod secp256k1_scheme;
pub mod stark_scheme;
pub mod tagged_pubkey;
pub mod unified;

pub use tagged_pubkey::{CURRENT_VERSION, SignatureScheme, StarkTxPubkey, TaggedPubkey, encode_tag};
pub use unified::verify_signature;
