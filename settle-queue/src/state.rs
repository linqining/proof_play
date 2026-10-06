//! 投递状态机（纯投递词汇，含写者标注）。
//!
//! ```text
//!   Enqueued ──(poster 拾取)──▶ Picked ──(poster 广播第一笔)──▶ Submitted
//!   Submitted: RegisterSent ─▶ RegisterVisible ─▶ SettleSent（两笔时序子态，
//!   建模 texas submit.rs `submit_settlement` 的 register→等可见→settle）
//!   Submitted ──(poster 拿到回执)──▶ Receipted        （投递终态·非业务终态）
//!   Enqueued/Picked/Submitted ──▶ DeadLetter          （双源，见下）
//! ```
//!
//! **写者标注**（单写者协议，见 crate 文档）：
//!
//! - `Enqueued` / `Downgraded` / 构建期 `DeadLetter` → texas 写 WAL；
//! - `Picked` / `Submitted(phase)` / `Receipted` / 投递期 `DeadLetter` →
//!   poster 写自有 sidecar（poster-state.json 在途快照 + receipts/ + dead/）。
//!
//! **Receipted ≠ 业务终态**：业务终态权威是 settle_receipt 的 `SettleStatus`
//! （`texas/src/starknet/settle_receipt.rs:36`，Settled/Refused/Failed），
//! 队列不重复定义这些词汇。
//!
//! **Dual→Legacy 单向降级**（route 级迁移，非状态机边）：dual 腿重试耗尽时
//! 由 texas 依据 poster 的死信回读触发（建模 hooks.rs `snip36_settle_flow`
//! 失败回退 legacy「结算永不因证明阻塞/失败而丢失」语义），见
//! [`TaskRecord::downgrade_to_legacy`]。

use serde::{Deserialize, Serialize};

use crate::task::{SettleRoute, SettleTask};

/// 两笔时序子态（Legacy 与 Dual 路共用——两路都是「先注册、等链上可见、
/// 再结算」的两笔形态；submit.rs `submit_settlement`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmitPhase {
    /// 第一笔（register_aggregate / register_hand）已广播。写者：poster。
    RegisterSent,
    /// register 已在链上可见（txmgr 的 wait_call_visible 断言；可见性判定
    /// 归属 starknet-txmgr 层，poster 只记录相位）。写者：poster。
    RegisterVisible,
    /// 第二笔（settle_hand / verify_and_settle_dapv*）已广播。写者：poster。
    SettleSent,
}

/// 死信归属源（双源协议）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeadLetterSource {
    /// 构建期死信（对账拒绝/构建失败，发生在 texas 侧）——texas 写 WAL。
    Build,
    /// 投递期死信（重试耗尽，含降级后仍耗尽）——poster 写 dead/<key>.json。
    Delivery,
}

/// 投递状态机（纯投递词汇）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    /// 已入队（WAL，texas 写）。
    Enqueued,
    /// poster 已拾取（sidecar，poster 写）。
    Picked,
    /// 两笔已提交，内嵌保序子态（sidecar，poster 写）。
    Submitted(SubmitPhase),
    /// 已拿到投递回执（sidecar，poster 写）——投递终态，非业务终态。
    Receipted,
    /// 死信（双源：Build=texas 写 WAL；Delivery=poster 写 sidecar）。
    DeadLetter(DeadLetterSource),
}

impl TaskState {
    /// 投递层终态（不再驱动）。
    pub fn is_terminal(&self) -> bool {
        matches!(self, TaskState::Receipted | TaskState::DeadLetter(_))
    }

    /// 子态推进是否合法（RegisterSent → RegisterVisible → SettleSent 单调）。
    pub fn phase_transition_ok(from: SubmitPhase, to: SubmitPhase) -> bool {
        use SubmitPhase::*;
        matches!(
            (from, to),
            (RegisterSent, RegisterVisible) | (RegisterVisible, SettleSent)
        )
    }

    /// 状态机合法边（同层检查，降级迁移见 [`TaskRecord::downgrade_to_legacy`]）。
    pub fn can_transition(&self, to: &TaskState) -> bool {
        use TaskState::*;
        match (self, to) {
            (Enqueued, Picked) => true,
            (Picked, Submitted(_)) => true,
            (Submitted(_), Submitted(to_phase)) => {
                // 子态只能单调前进：取当前相位（任一子态到目标子态按序校验）。
                let cur = self.phase().expect("Submitted always has a phase");
                Self::phase_transition_ok(cur, *to_phase)
            }
            (Submitted(_), Receipted) | (Submitted(_), DeadLetter(_)) => true,
            (Picked, DeadLetter(_)) | (Enqueued, DeadLetter(_)) => true,
            _ => false,
        }
    }

    /// Submitted 的当前子相位。
    pub fn phase(&self) -> Option<SubmitPhase> {
        match self {
            TaskState::Submitted(p) => Some(*p),
            _ => None,
        }
    }
}

/// WAL 重放得到的任务记录（队列当前事实，texas/poster 共读）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task: SettleTask,
    pub state: TaskState,
    /// Dual→Legacy 降级是否已发生（单向；见 downgrade_to_legacy）。
    pub downgraded: bool,
    /// 构建期死信原因（state = DeadLetter(Build) 时存在）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_reason: Option<String>,
}

impl TaskRecord {
    pub fn new(task: SettleTask) -> Self {
        Self {
            task,
            state: TaskState::Enqueued,
            downgraded: false,
            dead_reason: None,
        }
    }

    /// Dual→Legacy 单向降级迁移：dual 腿重试耗尽（poster 死信回读）后由
    /// texas 写 WAL 触发。**单向**：Legacy 条目与二次降级均拒绝（幂等：
    /// 已降级记录重复降级为 no-op Ok）。
    pub fn downgrade_to_legacy(&mut self) -> Result<(), DowngradeError> {
        match self.task.route {
            SettleRoute::Legacy if self.downgraded => Ok(()), // 幂等重放
            SettleRoute::Legacy => Err(DowngradeError::AlreadyLegacy),
            SettleRoute::Dual => {
                self.task.route = SettleRoute::Legacy;
                // 降级重投：清掉 dual 死相、回 Enqueued 交 poster 重拾。
                if matches!(
                    self.state,
                    TaskState::DeadLetter(DeadLetterSource::Delivery)
                ) {
                    self.state = TaskState::Enqueued;
                }
                self.downgraded = true;
                Ok(())
            }
        }
    }
}

/// 降级迁移错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DowngradeError {
    #[error("legacy 条目不可再降级（Dual→Legacy 单向迁移）")]
    AlreadyLegacy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{SettleKey, SettlePayload};

    fn dual_record() -> TaskRecord {
        TaskRecord::new(SettleTask::dual(
            SettleKey::new(1, 1),
            "v2".into(),
            SettlePayload {
                register: crate::task::LegCalldata {
                    selector: "0x1".into(),
                    calldata: vec![],
                },
                settle: crate::task::LegCalldata {
                    selector: "0x2".into(),
                    calldata: vec![],
                },
                fold_statement: None,
            },
            None,
            0,
        ))
    }

    /// 状态机合法边：Enqueued→Picked→Submitted→Receipted|DeadLetter。
    #[test]
    fn state_machine_edges() {
        use SubmitPhase::*;
        use TaskState::*;
        assert!(Enqueued.can_transition(&Picked));
        assert!(Picked.can_transition(&Submitted(RegisterSent)));
        assert!(Submitted(RegisterSent).can_transition(&Submitted(RegisterVisible)));
        assert!(Submitted(RegisterVisible).can_transition(&Submitted(SettleSent)));
        assert!(Submitted(SettleSent).can_transition(&Receipted));
        assert!(Enqueued.can_transition(&DeadLetter(DeadLetterSource::Build)));
        assert!(Picked.can_transition(&DeadLetter(DeadLetterSource::Delivery)));

        // 非法边：跳相/倒退/复入队。
        assert!(!Submitted(RegisterSent).can_transition(&Submitted(SettleSent)));
        assert!(!Submitted(SettleSent).can_transition(&Submitted(RegisterVisible)));
        assert!(!Receipted.can_transition(&Enqueued));
        assert!(!Receipted.can_transition(&Picked));
        assert!(!Picked.can_transition(&Enqueued));
        assert!(Receipted.is_terminal());
        assert!(DeadLetter(DeadLetterSource::Build).is_terminal());
        assert!(!Submitted(SettleSent).is_terminal());
    }

    /// Dual→Legacy 单向降级：dual 成功、legacy 拒绝、二次降级幂等、
    /// 投递期死信降级后回 Enqueued 重投。
    #[test]
    fn downgrade_is_one_way() {
        let mut r = dual_record();
        r.state = TaskState::DeadLetter(DeadLetterSource::Delivery);
        r.downgrade_to_legacy().unwrap();
        assert_eq!(r.task.route, SettleRoute::Legacy);
        assert!(r.downgraded);
        assert_eq!(r.state, TaskState::Enqueued, "降级重投：死信回 Enqueued");

        // 幂等重放。
        r.downgrade_to_legacy().unwrap();

        // Legacy 原生条目不可降级。
        let mut l = dual_record();
        l.task.route = SettleRoute::Legacy;
        assert_eq!(l.downgrade_to_legacy(), Err(DowngradeError::AlreadyLegacy));
    }
}
