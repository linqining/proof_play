//! 幂等重放分类：吸收 texas submit.rs 旧 `is_register_replay` /
//! `is_settle_replay`（296-303 行，2026-10-01 随 txmgr 切换删除）的合约
//! 错误文案匹配。
//!
//! 语义（submit.rs 原注释）：
//! - **register 重放** =「本手的 aggregate/binding 已在链上注册（此前某次
//!   尝试已成功）。这不是已结算——settle 仍必须继续提交」→ 放行继续；
//! - **settle 重放** =「本手已在链上结算过（真正意义上的已完成）」→
//!   幂等成功收尾。
//!
//! hooks.rs 的 `is_already_settled_error`（现直接调用本层
//! `classify_execution_error` 取非 `NotReplay` 的超集视图，
//! 含 "Binding already registered"）；本层把它拆成两类：
//! dual 合约的 "Binding already registered" 属注册相（尚未结算），归
//! [`ReplayVerdict::RegisterReplay`。

/// 幂等重放判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// 普通失败（重试/熔断路径）。
    NotReplay,
    /// register 幂等重放（Digest/Aggregate/Binding already registered）——
    /// 放行继续 settle 腿。
    RegisterReplay,
    /// settle 幂等重放（Hand already settled）——幂等成功收尾。
    SettleReplay,
}

/// 按合约错误文案分类（旧 is_register_replay / is_settle_replay 的镜像 +
/// dual 合约 "Binding already registered" 归注册相）。
pub fn classify_execution_error(message: &str) -> ReplayVerdict {
    // is_settle_replay 镜像：先判终态，避免
    // "Hand already settled" 被注册相误吞。
    if message.contains("Hand already settled") {
        return ReplayVerdict::SettleReplay;
    }
    // is_register_replay 镜像 + dual 注册相。
    if message.contains("Digest already registered")
        || message.contains("Aggregate already registered")
        || message.contains("Binding already registered")
    {
        return ReplayVerdict::RegisterReplay;
    }
    ReplayVerdict::NotReplay
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 三类文案的判定（与旧 is_register_replay / is_settle_replay /
    /// hooks is_already_settled_error 的文案集对齐）。
    #[test]
    fn classifies_replay_messages() {
        // register 相（旧 is_register_replay + dual binding）。
        assert_eq!(
            classify_execution_error("ExecutionError: Digest already registered"),
            ReplayVerdict::RegisterReplay
        );
        assert_eq!(
            classify_execution_error("Aggregate already registered"),
            ReplayVerdict::RegisterReplay
        );
        assert_eq!(
            classify_execution_error("Binding already registered"),
            ReplayVerdict::RegisterReplay
        );
        // settle 相（旧 is_settle_replay）。
        assert_eq!(
            classify_execution_error("Hand already settled"),
            ReplayVerdict::SettleReplay
        );
        // 普通失败。
        assert_eq!(
            classify_execution_error("rpc: connection refused"),
            ReplayVerdict::NotReplay
        );
        assert_eq!(classify_execution_error(""), ReplayVerdict::NotReplay);
    }
}
