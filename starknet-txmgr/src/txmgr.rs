//! [`TxManager`]：nonce 租约 + 在途交易表（SendState）+ 有界重试 + 熔断。
//!
//! 纪律（zkSync eth_tx_manager 的 safety-over-liveness 哲学）：
//!
//! - **nonce 链上推断**：基线 nonce 只信链上 `get_nonce`（本地不盲自增）；
//!   租约按队列顺序分配（`base + 已分配数`）。
//! - **每轮只推进第一笔（保序）**：在途队列队首未决时，后续交易不领
//!   nonce、不广播——`submit_ordered` 排队等待成为队首。乱序上链比停机
//!   更糟（结算顺序 = 链上 hand 顺序的前提）。
//! - **有界重试 + 加价重发**：同 nonce 逐次加价重广播（替换 mempool 旧
//!   变体），上限 [`TxManagerConfig::max_attempts_per_tx`]；回执轮询耗尽
//!   （交易被节点丢弃）同样计入重试。
//! - **失败熔断（fail-closed）**：任一笔交易彻底失败即停机
//!   （[`TxError::Broadcast`]），熔断期内所有提交直接
//!   [`TxError::BreakerOpen`]——对账分歧/持续失败绝不上链；人工
//!   [`TxManager::resume_after_halt`] 恢复并重推 nonce 基线。

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use starknet_types_core::felt::Felt;

use crate::replay::{ReplayVerdict, classify_execution_error};
use crate::send::{BroadcastIntent, Call, ReceiptStatus, ResourceLimits, StarknetSend, TxReceipt};

/// 交易管理层配置。
#[derive(Debug, Clone)]
pub struct TxManagerConfig {
    /// v3 资源上限基线（首次广播）。
    pub limits: ResourceLimits,
    /// 每次重试的加价百分比（RBF 梯度；第 n 次重试 ≈ 基线 ×(1+pct·n)）。
    pub bump_factor_pct: u64,
    /// 单笔交易的有界重试上限。
    pub max_attempts_per_tx: u32,
    /// 回执轮询次数/间隔（轮询耗尽 = 交易被丢弃，计入重试）。
    pub receipt_polls: u32,
    pub receipt_poll_interval: Duration,
    /// 非队首交易的等待上限（yield 次数；防队首宿主崩溃后的自旋）。
    pub head_wait_yields: u32,
}

impl Default for TxManagerConfig {
    fn default() -> Self {
        Self {
            // v3 上限基线：l1/l2 gas 与 fri 价上限的保守起点（运营按链况
            // 调整；骨架缺省值不承诺与现网一致）。
            limits: ResourceLimits {
                l1_gas: 0,
                l1_gas_price_fri: 0,
                l2_gas: 0x5f5e100, // 1e8（texas snip36_l2_gas 缺省同值）
                l2_gas_price_fri: 0,
            },
            bump_factor_pct: 25,
            max_attempts_per_tx: 3,
            receipt_polls: 45,
            receipt_poll_interval: Duration::from_secs(1),
            head_wait_yields: 100_000,
        }
    }
}

/// 提交结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// 拿到执行成功回执。
    Receipted(TxReceipt),
    /// 幂等重放（register/settle 相；旧 submit.rs 文案分类语义——不是失败）。
    IdempotentReplay(ReplayVerdict),
}

/// 单次广播变体（SendState 的 gas 变体记录，op-service/txmgr 语义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptResult {
    /// 广播成功（交易哈希）。
    Broadcast(Felt),
    /// 广播失败/回执 revert（错误原文，供审计）。
    Failed(String),
}

/// 一次尝试的记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    /// 尝试序号（1 起）。
    pub attempt: u32,
    pub limits: ResourceLimits,
    pub result: AttemptResult,
}

/// 在途交易状态（多 gas 变体追踪）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendState {
    pub id: u64,
    /// 调用方标注（如 "register" / "settle"——观测用）。
    pub tag: String,
    pub calls: Vec<Call>,
    /// 分配的 nonce（Felt::ZERO = 尚未分配——只有队首会分配）。
    pub nonce: Felt,
    pub attempts: Vec<AttemptRecord>,
    /// 决议（Some = 已终态）。
    pub outcome: Option<SendOutcome>,
}

/// 观测快照（跨锁拷贝）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightSnapshot {
    pub id: u64,
    pub tag: String,
    pub nonce: Felt,
    pub attempts: Vec<AttemptRecord>,
    pub resolved: bool,
    pub outcome: Option<SendOutcome>,
}

/// 交易管理层错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    #[error("broadcast failed after {attempts} attempts: {last}")]
    Broadcast { attempts: u32, last: String },
    #[error("circuit breaker open（fail-closed 停发；人工 resume_after_halt 恢复）")]
    BreakerOpen,
    #[error("nonce 链上推断失败: {0}")]
    ChainInference(String),
    #[error("排队被取消（{0}）")]
    Cancelled(String),
}

struct Inner {
    base_nonce: Option<Felt>,
    /// 已分配的 nonce 数（相对基线偏移）。
    leased: u64,
    queue: VecDeque<u64>,
    states: HashMap<u64, SendState>,
    /// 已决历史（有界观测窗口）。
    history: VecDeque<SendState>,
    halted: bool,
    next_id: u64,
}

const HISTORY_CAP: usize = 64;

/// 交易管理器（nonce 租约/在途表/熔断的唯一宿主）。
pub struct TxManager<S: StarknetSend> {
    send: Arc<S>,
    cfg: TxManagerConfig,
    inner: std::sync::Mutex<Inner>,
}

impl<S: StarknetSend> TxManager<S> {
    pub fn new(send: Arc<S>, cfg: TxManagerConfig) -> Self {
        Self {
            send,
            cfg,
            inner: std::sync::Mutex::new(Inner {
                base_nonce: None,
                leased: 0,
                queue: VecDeque::new(),
                states: HashMap::new(),
                history: VecDeque::new(),
                halted: false,
                next_id: 0,
            }),
        }
    }

    /// 注入接缝引用（batch-poster 复用同一 send 做 view 轮询）。
    pub fn send(&self) -> &S {
        &self.send
    }

    pub fn config(&self) -> &TxManagerConfig {
        &self.cfg
    }

    /// 熔断状态。
    pub fn halted(&self) -> bool {
        self.inner.lock().map(|g| g.halted).unwrap_or(true)
    }

    /// 人工恢复（逃生口）：清停机位并作废 nonce 基线（下次提交重新从链上
    /// 推断）。排队中的交易被取消（其调用方收到 [`TxError::Cancelled`]）。
    pub fn resume_after_halt(&self) {
        let mut g = self.inner.lock().expect("txmgr lock");
        g.halted = false;
        g.base_nonce = None;
        g.leased = 0;
        let drained: Vec<u64> = g.queue.drain(..).collect();
        for id in drained {
            if let Some(mut st) = g.states.remove(&id) {
                st.outcome = None;
                g.history.push_back(st);
                if g.history.len() > HISTORY_CAP {
                    g.history.pop_front();
                }
            }
        }
    }

    /// 未决在途快照。
    pub fn in_flight(&self) -> Vec<InFlightSnapshot> {
        self.inner
            .lock()
            .map(|g| {
                g.queue
                    .iter()
                    .filter_map(|id| g.states.get(id).map(snapshot))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 已决历史（含 attempts 链；有界窗口）。
    pub fn recent(&self) -> Vec<InFlightSnapshot> {
        self.inner
            .lock()
            .map(|g| g.history.iter().map(snapshot).collect())
            .unwrap_or_default()
    }

    /// 提交一笔（保序：非队首时排队等待队首决议）。
    ///
    /// 返回 [`SendOutcome::IdempotentReplay`] = 合约文案判定为幂等重放
    /// （register 重放放行 / settle 重放幂等收尾——不是失败）；彻底失败返回
    /// Err 并**停机**
    /// （fail-closed）。
    pub async fn submit_ordered(
        &self,
        account: Felt,
        tag: &str,
        calls: Vec<Call>,
    ) -> Result<SendOutcome, TxError> {
        // 登记（队尾）。
        let id = {
            let mut g = self.inner.lock().expect("txmgr lock");
            if g.halted {
                return Err(TxError::BreakerOpen);
            }
            g.next_id += 1;
            let id = g.next_id;
            g.queue.push_back(id);
            g.states.insert(
                id,
                SendState {
                    id,
                    tag: tag.to_string(),
                    calls: calls.clone(),
                    nonce: Felt::ZERO,
                    attempts: Vec::new(),
                    outcome: None,
                },
            );
            id
        };

        let mut yields: u32 = 0;
        loop {
            // 1) 熔断 / 排队被取消。
            let (halted, is_head, alive) = {
                let g = self.inner.lock().expect("txmgr lock");
                let alive = g.states.contains_key(&id);
                (g.halted, g.queue.front() == Some(&id), alive)
            };
            if halted {
                self.abandon(id, "breaker open while queued");
                return Err(TxError::BreakerOpen);
            }
            if !alive {
                return Err(TxError::Cancelled(
                    "resume_after_halt cleared the queue".into(),
                ));
            }
            if !is_head {
                yields += 1;
                if yields > self.cfg.head_wait_yields {
                    let msg = "head stalled (owner not driving)".to_string();
                    self.abandon(id, &msg);
                    return Err(TxError::Cancelled(msg));
                }
                tokio::task::yield_now().await;
                continue;
            }

            // 2) 队首：nonce 基线（链上推断，缓存）+ 租约分配。
            let leased: Option<Felt> = {
                let mut g = self.inner.lock().expect("txmgr lock");
                if let Some(n) = g
                    .states
                    .get(&id)
                    .and_then(|s| (s.nonce != Felt::ZERO).then_some(s.nonce))
                {
                    Some(n)
                } else if let Some(base) = g.base_nonce {
                    let n = add_offset(base, g.leased);
                    g.leased += 1;
                    if let Some(s) = g.states.get_mut(&id) {
                        s.nonce = n;
                    }
                    Some(n)
                } else {
                    None // 需要链上推断（锁外 await）。
                }
            };
            let nonce = match leased {
                Some(n) => n,
                None => {
                    let base = self
                        .send
                        .get_nonce(account)
                        .await
                        .map_err(TxError::ChainInference)?;
                    let mut g = self.inner.lock().expect("txmgr lock");
                    let base = *g.base_nonce.get_or_insert(base);
                    let n = add_offset(base, g.leased);
                    g.leased += 1;
                    if let Some(s) = g.states.get_mut(&id) {
                        s.nonce = n;
                    }
                    n
                }
            };

            // 3) 有界重试 + 加价重发（同 nonce 替换 mempool 变体）。
            let mut last_err = String::new();
            let mut attempt_no: u32 = 0;
            loop {
                attempt_no += 1;
                let limits = self.limits_for_attempt(attempt_no);
                let intent = BroadcastIntent {
                    nonce,
                    calls: calls.clone(),
                    limits,
                };
                let broadcasted: Option<Felt> = match self.send.broadcast(&intent).await {
                    Ok(hash) => {
                        self.record_attempt(id, attempt_no, limits, AttemptResult::Broadcast(hash));
                        Some(hash)
                    }
                    Err(f) => {
                        last_err = f.message.clone();
                        self.record_attempt(
                            id,
                            attempt_no,
                            limits,
                            AttemptResult::Failed(f.message.clone()),
                        );
                        match classify_execution_error(&f.message) {
                            ReplayVerdict::NotReplay => None,
                            verdict => {
                                // 幂等重放 = 成功语义（nonce 已被合约侧消费）。
                                return Ok(self.resolve(id, SendOutcome::IdempotentReplay(verdict)));
                            }
                        }
                    }
                };
                let Some(tx_hash) = broadcasted else {
                    if attempt_no >= self.cfg.max_attempts_per_tx {
                        return Err(self.fail_permanently(id, attempt_no, &last_err));
                    }
                    continue;
                };

                // 4) 回执轮询。
                let mut receipt: Option<TxReceipt> = None;
                for poll in 0..self.cfg.receipt_polls {
                    match self.send.get_transaction_receipt(tx_hash).await {
                        Ok(Some(r)) => {
                            receipt = Some(r);
                            break;
                        }
                        // None = 未入块；Err = RPC 抖动——都继续轮询。
                        _ => {
                            if poll + 1 < self.cfg.receipt_polls {
                                tokio::time::sleep(self.cfg.receipt_poll_interval).await;
                            }
                        }
                    }
                }
                match receipt {
                    Some(r) if matches!(r.status, ReceiptStatus::Succeeded) => {
                        return Ok(self.resolve(id, SendOutcome::Receipted(r)));
                    }
                    Some(TxReceipt {
                        status: ReceiptStatus::Reverted(msg),
                        ..
                    }) => {
                        last_err = msg.clone();
                        self.record_attempt(
                            id,
                            attempt_no,
                            limits,
                            AttemptResult::Failed(format!("reverted: {msg}")),
                        );
                        match classify_execution_error(&msg) {
                            ReplayVerdict::NotReplay => {
                                if attempt_no >= self.cfg.max_attempts_per_tx {
                                    return Err(self.fail_permanently(id, attempt_no, &last_err));
                                }
                                continue;
                            }
                            verdict => {
                                return Ok(self.resolve(id, SendOutcome::IdempotentReplay(verdict)));
                            }
                        }
                    }
                    _ => {
                        // 回执轮询耗尽：交易被节点丢弃——同 nonce 加价重发。
                        last_err = "receipt polling exhausted (tx dropped?)".into();
                        if attempt_no >= self.cfg.max_attempts_per_tx {
                            return Err(self.fail_permanently(id, attempt_no, &last_err));
                        }
                    }
                }
            }
        }
    }

    fn limits_for_attempt(&self, attempt: u32) -> ResourceLimits {
        if attempt <= 1 {
            self.cfg.limits
        } else {
            self.cfg
                .limits
                .bumped_by_pct(self.cfg.bump_factor_pct * (attempt as u64 - 1))
        }
    }

    fn record_attempt(&self, id: u64, attempt: u32, limits: ResourceLimits, result: AttemptResult) {
        let mut g = self.inner.lock().expect("txmgr lock");
        if let Some(s) = g.states.get_mut(&id) {
            s.attempts.push(AttemptRecord {
                attempt,
                limits,
                result,
            });
        }
    }

    /// 决议：出队 + 历史化 + 失败计数清零。
    fn resolve(&self, id: u64, outcome: SendOutcome) -> SendOutcome {
        let mut g = self.inner.lock().expect("txmgr lock");
        g.queue.retain(|x| *x != id);
        if let Some(s) = g.states.get_mut(&id) {
            s.outcome = Some(outcome.clone());
        }
        if let Some(s) = g.states.remove(&id) {
            g.history.push_back(s);
            if g.history.len() > HISTORY_CAP {
                g.history.pop_front();
            }
        }
        outcome
    }

    /// 彻底失败：停机（fail-closed）+ 决议失败态。
    fn fail_permanently(&self, id: u64, attempts: u32, last: &str) -> TxError {
        let mut g = self.inner.lock().expect("txmgr lock");
        g.halted = true;
        g.queue.retain(|x| *x != id);
        if let Some(s) = g.states.remove(&id) {
            g.history.push_back(s);
            if g.history.len() > HISTORY_CAP {
                g.history.pop_front();
            }
        }
        TxError::Broadcast {
            attempts,
            last: last.to_string(),
        }
    }

    /// 放弃排队（熔断/停滞）：出队（保留状态于历史，无决议）。
    fn abandon(&self, id: u64, reason: &str) {
        let mut g = self.inner.lock().expect("txmgr lock");
        g.queue.retain(|x| *x != id);
        if let Some(mut s) = g.states.remove(&id) {
            s.tag = format!("{} [abandoned: {reason}]", s.tag);
            g.history.push_back(s);
            if g.history.len() > HISTORY_CAP {
                g.history.pop_front();
            }
        }
    }
}

fn snapshot(s: &SendState) -> InFlightSnapshot {
    InFlightSnapshot {
        id: s.id,
        tag: s.tag.clone(),
        nonce: s.nonce,
        attempts: s.attempts.clone(),
        resolved: s.outcome.is_some(),
        outcome: s.outcome.clone(),
    }
}

fn add_offset(base: Felt, offset: u64) -> Felt {
    base + Felt::from(offset)
}

#[cfg(all(test, feature = "test-mocks"))]
mod tests {
    use super::*;
    use crate::mock::{MockSend, MockSendScript, ReceiptKind};
    use crate::send::ReceiptStatus;

    fn felt(v: u64) -> Felt {
        Felt::from(v)
    }

    fn manager(script: MockSendScript) -> (Arc<MockSend>, TxManager<MockSend>) {
        let send = Arc::new(MockSend::new(script));
        let cfg = TxManagerConfig {
            receipt_polls: 3,
            receipt_poll_interval: Duration::from_millis(1),
            max_attempts_per_tx: 2,
            head_wait_yields: 200_000,
            ..TxManagerConfig::default()
        };
        let mgr = TxManager::new(send.clone(), cfg);
        (send, mgr)
    }

    fn call(word: u64) -> Vec<Call> {
        vec![Call::new(felt(0xabc), felt(0xdef), vec![felt(word)])]
    }

    /// nonce 保序：队首未决时后续不广播；nonce 依队列顺序分配且与链上
    /// 推断基线对齐。
    #[tokio::test]
    async fn nonce_ordering_first_only() {
        // A 的回执延迟两轮 → B 必须等 A 决议后才广播。
        let (send, mgr) = manager(MockSendScript {
            chain_nonce: 100,
            broadcast_results: vec![Ok(()), Ok(())],
            receipts_by_broadcast: vec![
                vec![None, None, Some(ReceiptKind::Succeeded)],
                vec![Some(ReceiptKind::Succeeded)],
            ],
            view_results: vec![],
        });
        let (a, b) = tokio::join!(
            mgr.submit_ordered(felt(7), "register", call(1)),
            mgr.submit_ordered(felt(7), "settle", call(2)),
        );
        assert!(matches!(a, Ok(SendOutcome::Receipted(_))), "a = {a:?}");
        assert!(matches!(b, Ok(SendOutcome::Receipted(_))), "b = {b:?}");
        let intents = send.intents();
        assert_eq!(intents.len(), 2, "队首决议前不得广播后续");
        assert_eq!(
            intents[0].calls[0].calldata[0],
            felt(1),
            "register 先于 settle"
        );
        assert_eq!(intents[1].calls[0].calldata[0], felt(2));
        let nonces: Vec<Felt> = intents.iter().map(|i| i.nonce).collect();
        assert_eq!(
            nonces,
            vec![felt(100), felt(101)],
            "nonce = 链上基线 + 队列顺序偏移"
        );
    }

    /// 重放分类：register/settle 文案 = 幂等成功（不熔断、不重试耗尽）。
    #[tokio::test]
    async fn replay_errors_are_idempotent_success() {
        let (send, mgr) = manager(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![Err("ExecutionError: Digest already registered".into())],
            ..Default::default()
        });
        let out = mgr
            .submit_ordered(felt(7), "register", call(1))
            .await
            .unwrap();
        assert_eq!(
            out,
            SendOutcome::IdempotentReplay(ReplayVerdict::RegisterReplay)
        );
        assert!(!mgr.halted());
        assert_eq!(send.broadcast_count(), 1, "重放即终止，不再重试");

        let (_send2, mgr2) = manager(MockSendScript {
            chain_nonce: 5,
            broadcast_results: vec![Err("Hand already settled".into())],
            ..Default::default()
        });
        let out = mgr2
            .submit_ordered(felt(7), "settle", call(1))
            .await
            .unwrap();
        assert_eq!(
            out,
            SendOutcome::IdempotentReplay(ReplayVerdict::SettleReplay)
        );
    }

    /// 重试熔断（fail-closed）：有界重试耗尽 → Err + 停机；后续提交直接
    /// BreakerOpen（不再触网）；resume 后恢复。
    #[tokio::test]
    async fn bounded_retry_then_breaker() {
        let (send, mgr) = manager(MockSendScript {
            chain_nonce: 9,
            broadcast_results: vec![Err("rpc: connection refused".into()); 8],
            ..Default::default()
        });
        let err = mgr
            .submit_ordered(felt(7), "register", call(1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, TxError::Broadcast { attempts: 2, .. }),
            "err = {err:?}"
        );
        assert_eq!(send.broadcast_count(), 2, "有界重试上限 2");
        assert!(mgr.halted(), "彻底失败即停机（fail-closed）");

        let before = send.broadcast_count();
        assert_eq!(
            mgr.submit_ordered(felt(7), "settle", call(1))
                .await
                .unwrap_err(),
            TxError::BreakerOpen
        );
        assert_eq!(send.broadcast_count(), before, "熔断期不再广播");

        mgr.resume_after_halt();
        assert!(!mgr.halted());
    }

    /// SendState：多 gas 变体追踪——失败变体 + 加价成功变体都留痕，历史
    /// 可观测（op-service/txmgr SendState 语义）。
    #[tokio::test]
    async fn send_state_tracks_gas_variants() {
        let (send, mgr) = manager(MockSendScript {
            chain_nonce: 1,
            broadcast_results: vec![Err("fee too low".into()), Ok(())],
            receipts_by_broadcast: vec![vec![], vec![Some(ReceiptKind::Succeeded)]],
            ..Default::default()
        });
        let _ = send; // 仅为脚本着色
        let out = mgr
            .submit_ordered(felt(7), "register", call(1))
            .await
            .unwrap();
        assert!(matches!(out, SendOutcome::Receipted(_)));
        let recent = mgr.recent();
        assert_eq!(recent.len(), 1);
        let st = &recent[0];
        assert_eq!(st.attempts.len(), 2, "失败变体 + 重发变体都在链上留痕");
        assert_eq!(st.attempts[0].attempt, 1);
        assert!(matches!(st.attempts[0].result, AttemptResult::Failed(_)));
        assert!(matches!(st.attempts[1].result, AttemptResult::Broadcast(_)));
        // 加价：第二变体 gas 上限严格大于基线。
        let base = mgr.config().limits;
        assert!(st.attempts[1].limits.l2_gas > base.l2_gas);
        assert_eq!(st.outcome, Some(out.clone()));
    }

    /// 回执 Reverted 且非重放：计入重试；重试耗尽停机。
    #[tokio::test]
    async fn reverted_non_replay_counts_as_failure() {
        let (send, mgr) = manager(MockSendScript {
            chain_nonce: 2,
            broadcast_results: vec![Ok(()), Ok(())],
            receipts_by_broadcast: vec![
                vec![Some(ReceiptKind::Reverted("insufficient balance".into()))],
                vec![Some(ReceiptKind::Reverted("insufficient balance".into()))],
            ],
            ..Default::default()
        });
        let err = mgr
            .submit_ordered(felt(7), "register", call(1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, TxError::Broadcast { attempts: 2, .. }),
            "err = {err:?}"
        );
        assert!(mgr.halted());
        assert_eq!(send.broadcast_count(), 2);
    }

    /// 成功回执的状态映射（block/fee 透传）。
    #[tokio::test]
    async fn receipted_maps_receipt_fields() {
        let (_send, mgr) = manager(MockSendScript {
            chain_nonce: 3,
            broadcast_results: vec![Ok(())],
            receipts_by_broadcast: vec![vec![Some(ReceiptKind::Succeeded)]],
            ..Default::default()
        });
        let out = mgr
            .submit_ordered(felt(7), "register", call(1))
            .await
            .unwrap();
        let SendOutcome::Receipted(r) = out else {
            panic!("expected receipted");
        };
        assert!(matches!(r.status, ReceiptStatus::Succeeded));
    }
}
