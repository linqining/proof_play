//! `wait_call_visible`：view 调用轮询直至链上可见。
//!
//! 吸收 texas submit.rs 旧 `wait_register_visible`（307-323 行，2026-10-01
//! 随 txmgr 切换删除）的
//! 语义：settle 腿会断言 register 已生效，而两笔交易的提交存在包含时差，
//! 必须等第一笔在链上可见（view 返回非零）再发第二笔；RPC 抖动按轮内
//! 错误容忍（继续轮询），轮数耗尽报错。**可见性判定归属本层**——poster
//! 只记录 RegisterVisible 相位，不自建轮询。

use std::time::Duration;

use starknet_types_core::felt::Felt;

use crate::send::{BoxFuture, StarknetSend};

/// 可见性轮询策略（现状默认 45×1s，对齐旧 wait_register_visible 的常量）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisiblePolicy {
    pub polls: u32,
    pub interval: Duration,
}

impl Default for VisiblePolicy {
    fn default() -> Self {
        Self {
            polls: 45,
            interval: Duration::from_secs(1),
        }
    }
}

/// 轮询 `contract.selector(calldata)` 直至返回首词非零（链上可见）。
///
/// - view 首词非零 = 可见（register_aggregate 已生效的现网判据，
///   旧 wait_register_visible 同式）；
/// - view 报错（RPC 抖动/节点滞后）= 本轮不可见，继续轮询；
/// - 轮数耗尽 = `Err`（含未可见说明——调用方决定重试或降级，本层不自作
///   主张）。
pub fn wait_call_visible<'a, S>(
    send: &'a S,
    contract: Felt,
    selector: Felt,
    calldata: Vec<Felt>,
    policy: &'a VisiblePolicy,
) -> BoxFuture<'a, Result<(), String>>
where
    S: StarknetSend,
{
    Box::pin(async move {
        for poll in 0..policy.polls {
            if let Ok(felts) = send
                .call_contract(contract, selector, calldata.clone())
                .await
                && felts.first().is_some_and(|f| *f != Felt::ZERO)
            {
                return Ok(());
            }
            if poll + 1 < policy.polls {
                tokio::time::sleep(policy.interval).await;
            }
        }
        Err(format!(
            "call not visible on-chain within {} polls ({}s interval)",
            policy.polls,
            policy.interval.as_secs()
        ))
    })
}

#[cfg(all(test, feature = "test-mocks"))]
mod tests {
    use super::*;
    use crate::mock::{MockSend, MockSendScript};
    use starknet_types_core::felt::Felt;

    fn felt(v: u64) -> Felt {
        Felt::from(v)
    }

    /// 首词非零后返回 Ok；轮内 RPC 错误被容忍。
    #[tokio::test]
    async fn waits_until_view_nonzero() {
        let send = MockSend::new(MockSendScript {
            view_results: vec![
                Err("rpc hiccup".into()), // 抖动容忍
                Ok(vec![Felt::ZERO]),     // 尚未可见
                Ok(vec![felt(7)]),        // 可见
            ],
            ..Default::default()
        });
        let policy = VisiblePolicy {
            polls: 5,
            interval: Duration::from_millis(1),
        };
        wait_call_visible(&send, felt(1), felt(2), vec![felt(3)], &policy)
            .await
            .unwrap();
        assert_eq!(send.view_calls(), 3);
    }

    /// 轮数耗尽报错（文案含 polls 口径）。
    #[tokio::test]
    async fn times_out_when_never_visible() {
        let send = MockSend::new(MockSendScript {
            view_results: vec![Ok(vec![Felt::ZERO]); 10],
            ..Default::default()
        });
        let policy = VisiblePolicy {
            polls: 3,
            interval: Duration::from_millis(1),
        };
        let err = wait_call_visible(&send, felt(1), felt(2), vec![], &policy)
            .await
            .unwrap_err();
        assert!(err.contains("not visible"), "err = {err}");
        assert_eq!(send.view_calls(), 3);
    }
}
