//! 入口队列（链运行时的乱序容忍语义）。
//!
//! 游戏运行时接受异步乱序提交（reveal 令牌可早于相位窗口到达），而
//! VM 状态机是相位序敏感的。本模块把乱序容忍升格为链运行时的正式
//! 语义：**提前到达的命令入队等待，窗口打开后按序重放**。
//!
//! # 职责边界（模块化约束）
//!
//! 队列是**纯机械件**：暂存、按序重放、死信、背压。它不做任何业务
//! 判断、不解析错误变体或文本——"能否应用"完全由持有 VM 状态的一方
//! 通过 [`ApplyOutcome`] 三态裁决给出：
//! - `Applied`：已应用，出队；
//! - `Hold`：暂不可应用（典型：相位窗口未开）——继续暂存；
//! - `Reject`：确定性失败——submit 路径门口拒绝（不入队），flush 路径
//!   立即死信。可重试与确定性失败的**分类策略**集中在调用方
//!   （[`super::table_runtime`]：只有窗口类变体 + 抢跑白名单命令可 Hold）。
//!
//! 队列泛型于信封 `E`：暂存的不只是 (selector, args)，还有调用方提供的
//! 完整提交材料（签名、caller、时钟等，见 `TableRuntime` 的 `Submission`）。
//! 冲刷时**全量重验**（签名 + nonce 水位 + 业务语义）——不信任任何已入
//! 队状态。
//!
//! # 资源有界性（防泄漏不变量）
//!
//! - 活条目 `entries` ≤ `max_entries`（满则背压直通调用方）；
//! - 死信 `dead` ≤ [`MAX_DEAD`]，超出部分只累计数（`dead_dropped`）——
//!   死信本就是确定性失败条目，仅作审计，截断不影响游戏语义；
//! - 生命周期：每手结束时调用方必须走 [`PendingQueue::clear`]（见
//!   `TableRuntime::reset_for_next_hand`）——未消化的上一手命令绝不允许
//!   泄漏进下一手窗口。
//!
//! 与历史实现的本质区别是收尾语义：历史上未消化的 reveal 只告警放行
//! （mirror.rs 的静默丢弃类缺陷）；这里 [`PendingQueue::deny_unmatched`]
//! 返回显式错误——任何命令都不允许无声消失（fail-closed）。

use crate::error::{PokerL1Error, PokerL1Result};

/// 死信清单容量上限：达到后不再入表，只累计 [`PendingQueue::dead_dropped`]。
/// 每手活条目上限远小于此值；触顶只可能发生在跨手不清死的病态用法下。
pub const MAX_DEAD: usize = 128;

/// 一条暂存的入口命令（相位未开，等待重放）。
#[derive(Debug, Clone)]
pub struct PendingEntry<E> {
    /// 提交信封（签名材料 / caller / 时钟——冲刷时全量重验）。
    pub envelope: E,
    /// 命令 selector（32 字节方法选择子，与 dispatch 层同一编码）。
    pub selector: [u8; 32],
    /// 命令参数（borsh 编码；冲刷时连同信封重新校验）。
    pub args: Vec<u8>,
    /// 被重试过但仍未消化的次数。
    pub hold_count: usize,
    /// 最近一次确定性失败的原因（死信审计用；活条目为 None）。
    pub last_reject: Option<String>,
}

/// 一次应用尝试的裁决——由持有 VM 状态的一方给出，队列按裁决机械执行。
#[derive(Debug)]
pub enum ApplyOutcome {
    /// 命令已应用（出队）。
    Applied,
    /// 暂不可应用（典型：相位窗口未开）——继续暂存，窗口打开后重放。
    Hold,
    /// 确定性失败（认证/重放/畸形载荷等，重试永不过）：`submit` 路径
    /// 门口拒绝原样返回错误（不入队）；`flush` 路径立即死信（附原因）。
    Reject(PokerL1Error),
}

/// 应用闭包类型：持有 VM 状态的一方提供的全量重验入口
/// （信封 + selector + 参数 → 队列裁决）。
pub type ApplyFn<'a, E> = &'a mut dyn FnMut(&E, &[u8; 32], &[u8]) -> ApplyOutcome;

/// 入口命令队列。
///
/// `apply` 闭包由持有 VM 状态的一方提供（通常是
/// [`super::table_runtime::TableRuntime`]）：收到信封 + 命令后做**全量
/// 重验并应用**，返回 [`ApplyOutcome`] 裁决。
#[derive(Debug, Default)]
pub struct PendingQueue<E> {
    entries: Vec<PendingEntry<E>>,
    dead: Vec<PendingEntry<E>>,
    max_entries: usize,
    held_total: usize,
    flushed_total: usize,
    dead_dropped: usize,
}

impl<E: Clone> PendingQueue<E> {
    /// 建队列；`max_entries` 为暂存容量上限（满时背压直通调用方）。
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            dead: Vec::new(),
            max_entries,
            held_total: 0,
            flushed_total: 0,
            dead_dropped: 0,
        }
    }

    /// 死信清单（完整信封 + 最近失败原因保留，供调用方告警/审计——
    /// 不是静默丢弃；超过 [`MAX_DEAD`] 的部分见 [`PendingQueue::dead_dropped`]）。
    pub fn dead(&self) -> &[PendingEntry<E>] {
        &self.dead
    }

    /// 因死信表触顶而未保留的死信条数（仅计数，不保留内容）。
    pub fn dead_dropped(&self) -> usize {
        self.dead_dropped
    }

    /// 当前暂存条数（不含死信）。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 暂存是否为空。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 累计入队总数（观测指标）。
    pub fn held_total(&self) -> usize {
        self.held_total
    }

    /// 累计冲刷成功总数（观测指标）。
    pub fn flushed_total(&self) -> usize {
        self.flushed_total
    }

    /// 提交一条命令：可应用则立即执行；窗口未开则连信封入队（不返回
    /// 错误）；确定性失败门口拒绝（原样返回错误，不入队）。队列已满时
    /// 返回背压错误（不吞、不挤占——直通调用方）。
    pub fn submit(
        &mut self,
        envelope: E,
        selector: &[u8; 32],
        args: &[u8],
        apply: ApplyFn<'_, E>,
    ) -> PokerL1Result<()> {
        match apply(&envelope, selector, args) {
            ApplyOutcome::Applied => Ok(()),
            ApplyOutcome::Hold => {
                if self.entries.len() >= self.max_entries {
                    return Err(PokerL1Error::Other(format!(
                        "pending queue full ({}) — backpressure, retry later",
                        self.max_entries
                    )));
                }
                self.entries.push(PendingEntry {
                    envelope,
                    selector: *selector,
                    args: args.to_vec(),
                    hold_count: 0,
                    last_reject: None,
                });
                self.held_total += 1;
                Ok(())
            }
            ApplyOutcome::Reject(e) => Err(e),
        }
    }

    /// 冲刷：按入队序全量重验重试暂存命令，直到一轮内无进展（消化一条
    /// 可能解锁下一条）。`Reject` 立即死信；`Hold` 满 [`MAX_HOLDS`] 次后
    /// 死信（附最近失败原因）。返回本轮消化的条数。
    pub fn flush(
        &mut self,
        apply: ApplyFn<'_, E>,
    ) -> usize {
        let mut flushed = 0;
        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut i = 0;
            while i < self.entries.len() {
                let entry = &self.entries[i];
                match apply(&entry.envelope, &entry.selector, &entry.args) {
                    ApplyOutcome::Applied => {
                        self.entries.remove(i);
                        self.flushed_total += 1;
                        flushed += 1;
                        progressed = true;
                    }
                    ApplyOutcome::Reject(e) => {
                        // 确定性失败：重试永不过，立即死信（附原因供审计）。
                        let mut entry = self.entries.remove(i);
                        entry.last_reject = Some(e.to_string());
                        self.dead_letter(entry);
                    }
                    ApplyOutcome::Hold => {
                        self.entries[i].hold_count += 1;
                        if self.entries[i].hold_count >= MAX_HOLDS {
                            let entry = self.entries.remove(i);
                            self.dead_letter(entry);
                        } else {
                            i += 1;
                        }
                    }
                }
            }
        }
        flushed
    }

    /// fail-closed 收尾：仍有未消化命令 = 显式错误（附完整清单），
    /// 绝不静默丢弃。
    pub fn deny_unmatched(&self) -> PokerL1Result<()>
    where
        E: std::fmt::Debug,
    {
        if self.entries.is_empty() {
            return Ok(());
        }
        let detail = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "selector={:02x?} hold_count={}{}",
                    e.selector[0..4].to_vec(),
                    e.hold_count,
                    e.last_reject
                        .as_ref()
                        .map(|r| format!(" last_reject={r:?}"))
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(PokerL1Error::Serialization(format!(
            "pending queue has {} unmatched command(s) at hand end — fail-closed: {detail}",
            self.entries.len()
        )))
    }

    /// 手间清空（配合 `deny_unmatched` 使用：先校验后清空）。清空活条目
    /// 与死信——上一手的未消化命令绝不允许泄漏进下一手窗口。
    pub fn clear(&mut self) {
        self.entries.clear();
        self.dead.clear();
    }

    /// 死信入表（有界；超出上限只计数）。
    fn dead_letter(&mut self, entry: PendingEntry<E>) {
        if self.dead.len() >= MAX_DEAD {
            self.dead_dropped += 1;
        } else {
            self.dead.push(entry);
        }
    }
}

/// 非死信失败的重试上限：达到后死信。只作用于 `Hold` 类条目（窗口等待
/// 与抢跑畸形载荷的兜底）；`Reject` 类确定性失败不重试、直接死信。
pub const MAX_HOLDS: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    /// 窗口未开（可重试暂存）。
    fn hold() -> ApplyOutcome {
        ApplyOutcome::Hold
    }

    #[test]
    fn reject_at_door_never_enqueues() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        let err = q
            .submit(1, &[0; 32], &[], &mut |_, _, _| {
                ApplyOutcome::Reject(PokerL1Error::StaleTxNonce { nonce: 7 })
            })
            .expect_err("deterministic reject surfaces at submit");
        assert!(
            matches!(err, PokerL1Error::StaleTxNonce { nonce: 7 }),
            "original error returned, got: {err}"
        );
        assert!(q.is_empty(), "rejected command must not squat in the queue");
        assert!(q.dead().is_empty());
    }

    #[test]
    fn hold_then_apply_on_window_open() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        let mut gate = false;
        q.submit(1, &[0; 32], &[], &mut |_, _, _| {
            if gate {
                ApplyOutcome::Applied
            } else {
                hold()
            }
        })
        .expect("early command held, not rejected");
        assert_eq!(q.len(), 1);
        // 数轮冲刷：仍持有（窗口未开）。
        for _ in 0..3 {
            assert_eq!(q.flush(&mut |_, _, _| hold()), 0);
        }
        assert_eq!(q.len(), 1, "held entry survives until window opens");
        // 窗口打开后消化（复用同一 gate 条件闭包，证明按原始语义应用）。
        gate = true;
        assert_eq!(
            q.flush(&mut |_, _, _| if gate {
                ApplyOutcome::Applied
            } else {
                hold()
            }),
            1
        );
        assert!(q.is_empty() && q.dead().is_empty());
    }

    #[test]
    fn hold_limit_dead_letters_after_max_holds() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        q.submit(1, &[0; 32], &[], &mut |_, _, _| hold()).expect("held");
        // 每次 flush 无进展即止（一轮一个 hold）；到上限的死信在第
        // MAX_HOLDS 次冲刷发生。
        for _ in 0..MAX_HOLDS {
            q.flush(&mut |_, _, _| hold());
        }
        assert!(q.is_empty(), "permanently-held entry dead-lettered after MAX_HOLDS");
        assert_eq!(q.dead().len(), 1);
        assert_eq!(q.dead()[0].hold_count, MAX_HOLDS);
    }

    #[test]
    fn flush_reject_dead_letters_with_reason() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        q.submit(1, &[0; 32], &[], &mut |_, _, _| hold()).expect("held");
        let flushed = q.flush(&mut |_, _, _| {
            ApplyOutcome::Reject(PokerL1Error::StaleTxNonce { nonce: 3 })
        });
        assert_eq!(flushed, 0);
        assert!(q.is_empty(), "rejected entry dead-lettered, not held");
        assert_eq!(q.dead().len(), 1, "dead list keeps the full entry + reason");
        assert_eq!(q.dead()[0].last_reject.as_deref(), Some("tx nonce 3 already applied for this account (replay/stale rejected)"));
        // 死信不影响收尾：fail-closed 门只看活条目。
        q.deny_unmatched().expect("no live entries — finish clean");
    }

    #[test]
    fn dead_list_is_bounded_and_counts_overflow() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        let mut n = 0u8;
        for _ in 0..(MAX_DEAD + 7) {
            q.submit(n, &[0; 32], &[], &mut |_, _, _| hold())
                .expect("held");
            q.flush(&mut |_, _, _| {
                ApplyOutcome::Reject(PokerL1Error::StaleTxNonce { nonce: 1 })
            });
            n += 1;
        }
        assert_eq!(q.dead().len(), MAX_DEAD, "dead list capped");
        assert_eq!(q.dead_dropped(), 7, "overflow counted, not silently lost");
        assert!(q.is_empty());
    }

    #[test]
    fn clear_resets_live_and_dead_for_next_hand() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        q.submit(1, &[0; 32], &[], &mut |_, _, _| hold()).expect("held");
        q.submit(2, &[0; 32], &[], &mut |_, _, _| hold()).expect("held");
        // 信封 1 死信、信封 2 继续 Hold——活条目与死信并存。
        q.flush(&mut |e, _, _| {
            if *e == 1 {
                ApplyOutcome::Reject(PokerL1Error::StaleTxNonce { nonce: 1 })
            } else {
                hold()
            }
        });
        assert!(!q.is_empty() && !q.dead().is_empty(), "fixture: both present");
        q.clear();
        assert!(q.is_empty() && q.dead().is_empty(), "no cross-hand leakage");
    }

    #[test]
    fn submit_backpressure_when_full() {
        let mut q: PendingQueue<u8> = PendingQueue::new(1);
        q.submit(1, &[0; 32], &[], &mut |_, _, _| hold()).expect("first held");
        let err = q
            .submit(2, &[0; 32], &[], &mut |_, _, _| hold())
            .expect_err("queue full — backpressure");
        assert!(err.to_string().contains("pending queue full"), "got: {err}");
        assert_eq!(q.len(), 1, "full queue not crowded by the new entry");
    }

    #[test]
    fn deny_unmatched_lists_live_entries_fail_closed() {
        let mut q: PendingQueue<u8> = PendingQueue::new(8);
        q.submit(1, &[0xAA; 32], &[], &mut |_, _, _| hold()).expect("held");
        let err = q.deny_unmatched().expect_err("live entries fail closed");
        assert!(
            format!("{err}").contains("unmatched command"),
            "fail-closed detail, got: {err}"
        );
    }
}
