//! 错误类型定义。

use thiserror::Error;

/// `poker_texas_air` 主错误类型。
#[derive(Debug, Error)]
pub enum TexasAirError {
    /// 业务规约违反（pre/post state 不匹配、字段非法值等）。
    #[error("业务规约违反: {0}")]
    SpecViolation(String),

    /// State root 计算失败（Poseidon252 哈希失败）。
    #[error("State root 计算失败: {0}")]
    StateRootError(String),

    /// Merkle 树构造/验证失败。
    #[error("Merkle 树错误: {0}")]
    MerkleError(String),

    /// AIR 约束不满足（soundness 检查失败）。
    #[error("AIR 约束不满足: {0}")]
    ConstraintUnsatisfied(String),

    /// Trace 生成失败。
    #[error("Trace 生成失败: {0}")]
    TraceGenError(String),

    /// Stwo prover 内部错误。
    #[error("Stwo prover 错误: {0}")]
    StwoProverError(String),

    /// 递归证明失败。
    #[error("递归证明错误: {0}")]
    RecursionError(String),

    /// Descriptor-only Aggregator 未验证子 proof，生产入口默认禁用。
    #[error(
        "不可信聚合已禁用: descriptor-only Aggregator 未在电路内验证子 proof；只能使用显式测试入口"
    )]
    UntrustedAggregationDisabled,

    /// 下注动作触发了当前 AIR 尚未建模的收池、轮次推进或结算分支。
    ///
    /// 生产 prover 必须 fail-closed；不能拿只描述 mid-round seat update 的 AIR
    /// 去证明完整的 end-of-round VM transition。
    #[error("下注转移未覆盖（fail-closed）: {0}")]
    UnsupportedBettingTransition(String),

    /// 序列化/反序列化失败。
    #[error("序列化错误: {0}")]
    SerializationError(String),

    /// 未实现（C 档密码学方法 AIR 在阶段 4 实现）。
    #[error("未实现: {0}")]
    NotImplemented(String),

    /// A verifier composition exists, but accepting it in production would
    /// still rely on an unproven host relation.  Keep the admission boundary
    /// fail-closed until every listed relation is constrained in AIR.
    #[error("host-zero admission unavailable: {0}")]
    HostZeroAdmissionIncomplete(String),

    /// 共识来源锚定失败（P05-H-source）：cert 校验、SMT 包含证明或单桌 snapshot
    /// 绑定未通过。
    #[error("consensus anchor: {0}")]
    ConsensusAnchor(String),

    /// 宿主（EVM 族）事件解码失败（host_evm_settlement）。
    #[error("evm event decode: {0}")]
    EvmEventDecode(String),
}

/// Stable high-level category for telemetry and RPC error mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// The caller supplied an invalid statement, wire value, or transition.
    ClientInput,
    /// A proof or authenticated binding was rejected.
    ProofRejection,
    /// A dependency or transient resource failed.
    Retryable,
    /// An internal implementation or invariant failed.
    Internal,
}

impl TexasAirError {
    /// Classify an error without parsing its human-readable message.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            TexasAirError::EvmEventDecode(_) => ErrorCategory::Internal,
            Self::SpecViolation(_)
            | Self::UnsupportedBettingTransition(_)
            | Self::SerializationError(_)
            | Self::UntrustedAggregationDisabled => ErrorCategory::ClientInput,
            Self::ConstraintUnsatisfied(_)
            | Self::ConsensusAnchor(_)
            | Self::HostZeroAdmissionIncomplete(_) => ErrorCategory::ProofRejection,
            Self::StateRootError(_) | Self::MerkleError(_) | Self::StwoProverError(_) => {
                ErrorCategory::Retryable
            }
            Self::TraceGenError(_) | Self::RecursionError(_) | Self::NotImplemented(_) => {
                ErrorCategory::Internal
            }
        }
    }

    /// Whether retrying the same request may succeed without changing input.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.category(), ErrorCategory::Retryable)
    }
}

/// 主 Result 类型别名。
pub type TexasAirResult<T> = Result<T, TexasAirError>;

#[cfg(test)]
mod category_tests {
    use super::*;

    /// #24⑤ 稳定类别锁：每个变体的归类是 API 的一部分（telemetry/RPC 映射
    /// 依赖其稳定）。match 无通配臂——新增变体必须在此 consciously 归类，
    /// 本测试锁住既有归类不被悄悄改动。
    #[test]
    fn category_mapping_is_stable_and_exhaustive() {
        let cases: &[(TexasAirError, ErrorCategory)] = &[
            (TexasAirError::SpecViolation("x".into()), ErrorCategory::ClientInput),
            (
                TexasAirError::UnsupportedBettingTransition("x".into()),
                ErrorCategory::ClientInput,
            ),
            (TexasAirError::SerializationError("x".into()), ErrorCategory::ClientInput),
            (TexasAirError::UntrustedAggregationDisabled, ErrorCategory::ClientInput),
            (TexasAirError::ConstraintUnsatisfied("x".into()), ErrorCategory::ProofRejection),
            (TexasAirError::ConsensusAnchor("x".into()), ErrorCategory::ProofRejection),
            (
                TexasAirError::HostZeroAdmissionIncomplete("x".into()),
                ErrorCategory::ProofRejection,
            ),
            (TexasAirError::StateRootError("x".into()), ErrorCategory::Retryable),
            (TexasAirError::MerkleError("x".into()), ErrorCategory::Retryable),
            (TexasAirError::StwoProverError("x".into()), ErrorCategory::Retryable),
            (TexasAirError::TraceGenError("x".into()), ErrorCategory::Internal),
            (TexasAirError::RecursionError("x".into()), ErrorCategory::Internal),
            (TexasAirError::NotImplemented("x".into()), ErrorCategory::Internal),
        ];
        for (error, want) in cases {
            assert_eq!(error.category(), *want, "variant drifted: {error}");
        }
        // retryable 标志与类别一致（单一事实来源）。
        for (error, _) in cases {
            assert_eq!(
                error.is_retryable(),
                matches!(error.category(), ErrorCategory::Retryable),
            );
        }
    }
}
