//! 统一错误类型。只保留当前存在构造点的变体，便于 validator / RPC 返回精确错误码。
//!
//! 安全路径相关错误（签名 / nonce / ObjectID）须包含足够上下文以供审计追溯。
//!
//! 历史留档（2026-09 死代码清理）：Phase 2/3/4/5/6 规划中的以下变体家族
//! 从未接线（DAG/Bullshark 共识验证、Block 验证器、ValidatorSet/Slashing、
//! rBPF VM/syscalls/合约升级、BLS12-381 预编译、OfflineState/ZK verifier
//! registry、ACK 链、审查截断、强制同步/争议、状态裁剪/DA、治理、跨链桥、
//! 网络层、链上 Verifier Production、gas/余额/nonce 的未用部分）已整体删除；
//! 重新接线时应连同构造点一起恢复，而不是先恢复变体。

use thiserror::Error;

/// 库统一错误类型。
///
/// 注意：enum 变体的命名字段（如 `tag` / `actual` / `expected` 等）
/// 名称已自描述，且每个变体均有文档注释说明语义，故此处允许字段缺文档。
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum PokerL1Error {
    // ===== 签名相关（Task 5 / SEC-M9 / NEW-L1 / SEC2-L1） =====
    /// tagged pubkey tag 字节未识别。SEC-M9：未知 tag 返回 UnknownScheme，禁止隐式 fallback。
    #[error("unknown signature scheme tag: 0x{tag:02x}")]
    UnknownScheme { tag: u8 },
    /// tagged pubkey 长度不匹配该 tag 的预期。
    #[error("tagged pubkey length {actual} != expected {expected} for tag 0x{tag:02x}")]
    InvalidPubkeyLength {
        tag: u8,
        actual: usize,
        expected: usize,
    },
    /// secp256k1 high-s 签名（BIP-62 / NEW-L1）— 拒绝，不规范化转换。
    #[error("secp256k1 signature s > n/2 (high-s rejected per BIP-62)")]
    InvalidSignatureLowS,
    /// ed25519 签名 R 或 S 非规范化编码（SEC2-L1）。
    #[error("ed25519 signature non-canonical encoding")]
    InvalidSignatureCanonical,
    /// 签名验证失败（恢复的 pubkey 与 tagged pubkey 不匹配，或底层 verify 返回 false）。
    #[error("signature verification failed")]
    InvalidSignature,
    /// 签名字节长度错误。
    #[error("signature length {actual} != expected {expected}")]
    InvalidSignatureLength { actual: usize, expected: usize },
    /// tagged pubkey 与签名 scheme tag 不一致（pubkey 是 secp256k1，sig 却声称 ed25519）。
    #[error("curve tag mismatch: pubkey tag 0x{pub_tag:02x} vs sig tag 0x{sig_tag:02x}")]
    CurveMismatch { pub_tag: u8, sig_tag: u8 },
    /// secp256k1 底层错误（解析失败等）。
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    // ===== 重放保护（TableRuntime 会话委托防重放） =====
    /// 按账户 nonce 水位的陈旧/重放交易：
    /// nonce 不高于该账户已应用水位。专用变体供入口队列做确定性死信
    /// 分类（不进重试）。
    #[error("tx nonce {nonce} already applied for this account (replay/stale rejected)")]
    StaleTxNonce { nonce: u64 },

    // ===== 入口队列乱序容忍（TableRuntime 抢跑流水线） =====
    /// 命令早于其相位窗口到达（典型：reveal 令牌抢跑，窗口尚未打开）。
    /// 专用变体供入口队列做**唯一可重试类**分类（继续暂存等窗口）——
    /// 与 [`PokerL1Error::StaleTxNonce`] 同一设计模式：队列按变体分类，
    /// 绝不解析错误文本。窗口状态前进后同一命令可原样应用。
    #[error("phase window closed: {detail}")]
    PhaseWindowClosed { detail: String },

    // ===== 序列化 / 通用 =====
    /// 序列化 / 反序列化错误。
    #[error("serialization error: {0}")]
    Serialization(String),
    /// 其他错误（带字符串上下文）。
    #[error("{0}")]
    Other(String),

    // ===== 合约执行（VM / dispatch） =====
    /// 未知的合约方法选择器（P0-5：GameTurn 原生合约 dispatch）。
    #[error("unknown contract method: selector={selector:?}")]
    UnknownContractMethod { selector: crate::Hash },
    /// 合约执行失败（VM 返回错误）。
    #[error("contract execution failed: {0}")]
    ContractExecutionFailed(String),

    // ===== 曲线点 / 标量反序列化（texas_poker crypto 适配层） =====
    /// 压缩曲线点反序列化失败（长度错误 / 非法编码 / 不在曲线上）。
    #[error("invalid bls point: {0}")]
    InvalidCurvePoint(String),
    /// 域标量反序列化失败（非 canonical 编码）。
    #[error("invalid bls scalar: {0}")]
    InvalidCurveScalar(String),
}

/// Stable category used by RPC and telemetry layers without parsing error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// The request or transaction supplied invalid input.
    ClientInput,
    /// An authenticated proof, signature, or consensus evidence was rejected.
    ProofRejection,
    /// A storage or network operation may succeed when retried.
    Retryable,
    /// An internal invariant or implementation failure occurred.
    Internal,
}

impl PokerL1Error {
    /// Classify an error without parsing its display string.
    ///
    /// The fallback is deliberately conservative: newly added variants are
    /// treated as internal until their retry and trust semantics are reviewed.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::InvalidCurvePoint(_) | Self::InvalidCurveScalar(_) => {
                ErrorCategory::ProofRejection
            }
            Self::PhaseWindowClosed { .. } => ErrorCategory::Retryable,
            Self::UnknownScheme { .. }
            | Self::InvalidPubkeyLength { .. }
            | Self::CurveMismatch { .. }
            | Self::InvalidSignature
            | Self::InvalidSignatureLowS
            | Self::InvalidSignatureCanonical
            | Self::InvalidSignatureLength { .. }
            | Self::StaleTxNonce { .. }
            | Self::UnknownContractMethod { .. } => ErrorCategory::ClientInput,
            _ => ErrorCategory::Internal,
        }
    }

    /// Whether retrying the same request may succeed without changing input.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.category(), ErrorCategory::Retryable)
    }

    /// Whether the error is attributable to untrusted client input.
    #[must_use]
    pub const fn is_client_fault(&self) -> bool {
        matches!(self.category(), ErrorCategory::ClientInput)
    }
}

/// 库统一 Result 别名。
pub type PokerL1Result<T> = Result<T, PokerL1Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_categories_are_stable_and_non_overlapping() {
        assert!(PokerL1Error::InvalidSignature.is_client_fault());
        assert_eq!(
            PokerL1Error::InvalidSignature.category(),
            ErrorCategory::ClientInput
        );
        assert_eq!(
            PokerL1Error::InvalidCurvePoint("bad".into()).category(),
            ErrorCategory::ProofRejection
        );
        assert_eq!(
            PokerL1Error::StaleTxNonce { nonce: 7 }.category(),
            ErrorCategory::ClientInput
        );
        assert_eq!(
            PokerL1Error::PhaseWindowClosed { detail: "w".into() }.category(),
            ErrorCategory::Retryable
        );
        assert!(PokerL1Error::PhaseWindowClosed { detail: "w".into() }.is_retryable());
        assert_eq!(
            PokerL1Error::Serialization("bad payload".into()).category(),
            ErrorCategory::Internal
        );
        assert_eq!(
            PokerL1Error::Other("bug".into()).category(),
            ErrorCategory::Internal
        );
        assert!(!PokerL1Error::Other("bug".into()).is_retryable());
    }
}

impl From<borsh::io::Error> for PokerL1Error {
    fn from(e: borsh::io::Error) -> Self {
        Self::Serialization(format!("borsh: {e}"))
    }
}

impl From<serde_json::Error> for PokerL1Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(format!("json: {e}"))
    }
}

impl From<blake2::digest::InvalidLength> for PokerL1Error {
    fn from(e: blake2::digest::InvalidLength) -> Self {
        Self::Serialization(format!("blake2 invalid length: {e}"))
    }
}

impl From<crate::contracts::texas_poker::betting::BettingError> for PokerL1Error {
    fn from(e: crate::contracts::texas_poker::betting::BettingError) -> Self {
        Self::ContractExecutionFailed(format!("betting error: {e}"))
    }
}
