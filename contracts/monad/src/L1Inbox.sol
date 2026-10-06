// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";

/// @notice 逃生舱冻结位查询接口（由 EscapeHatch 实现；Inbox 在三个锚定入口
///         挂 Frozen 卫兵——冻结期锚定停摆，恢复走 EscapeHatch.unfreeze 后的
///         正常 cadence）。
interface IEscapeHatch {
    function isFrozen() external view returns (bool);
}

/// @notice 提现根注册/终结接口（由 L1Outbox 实现；Inbox 提交 checkpoint 时
///         原子写入，L1↔L2 无跨链消息依赖，直接同链调用）。
interface IL1Outbox {
    function commitRoot(
        uint64 l2Height,
        uint64 leafCount,
        bytes32 root,
        bool finalized
    ) external;

    function markFinalized(bytes32 digest) external;
}

/// @title L1Inbox — zchain L2 → Monad(L1) 结算收件箱
/// @notice 承接 L2（poker-appchain soft-confirm sequencer）三类锚定数据：
///          1. 批次根（BatchRoot：Poseidon 折叠的结算批次承诺）；
///          2. 聚合根（AggregateRoot：批次根的二级折叠）；
///          3. checkpoint（L2 高度 → state_root + withdrawal_root）。
///         排序纪律：批次/聚合 index 必须严格连续递增（== 当前计数），
///         乱序即 revert（fail-closed，与 L2 侧管道产出序一致）；checkpoint
///         按 L2 高度键控、同高度不可覆写。
///         最终性策略：**上锚前置** —— daemon 只在 L2 侧 BFT finalized 之后
///         才提交 checkpoint，故 withdrawal_root 落地即视为可领取
///         （`finalized = true`）；若运营方选择先提交未终结根，须另行调用
///         Outbox.markFinalized。Monad 侧最终性（MonadBFT 单槽终结）由
///         L1Outbox 的大额延迟参数覆盖（见 L1Outbox）。
contract L1Inbox is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 数据结构
    // ------------------------------------------------------------------

    struct Batch {
        bytes32 root;
        uint64 throughOp; // 批次覆盖的最大帧序号
        uint64 l1Block; // 锚定时的 Monad 高度（审计用）
    }

    struct Aggregate {
        bytes32 root;
        uint64 throughOp;
        uint64 batchCount; // 折叠的批次根数量
        uint64 l1Block;
    }

    struct Checkpoint {
        bytes32 stateRoot;
        bytes32 withdrawalRoot; // 0 = 本 checkpoint 无提现窗
        uint64 leafCount; // 提现窗真实叶子数
        uint64 l1Block;
    }

    // ------------------------------------------------------------------
    // 存储
    // ------------------------------------------------------------------

    /// 下一个期望的批次 index（连续递增纪律的判定基准）。
    uint64 public batchCount;
    /// 下一个期望的聚合 index。
    uint64 public aggregateCount;

    mapping(uint64 index => Batch) public batches;
    mapping(uint64 index => Aggregate) public aggregates;
    /// 按 L2 checkpoint 高度键控；同高度不可覆写（重放即 revert）。
    mapping(uint64 l2Height => Checkpoint) public checkpoints;

    /// Outbox 地址（setOutbox 一次性设置；checkpoint 提交时写入提现根）。
    IL1Outbox public outbox;

    /// EscapeHatch 地址（setEscapeHatch 一次性设置；0 = 未接线，冻结卫兵
    /// 短路为不生效——护既有部署与测试零行为变化）。
    address public escapeHatch;

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    event BatchAnchored(uint64 indexed index, bytes32 root, uint64 throughOp);
    event AggregateAnchored(uint64 indexed index, bytes32 root, uint64 throughOp);
    event CheckpointAnchored(
        uint64 indexed l2Height,
        bytes32 stateRoot,
        bytes32 withdrawalRoot,
        uint64 leafCount
    );
    event OutboxSet(address indexed outbox);
    event EscapeHatchSet(address indexed escapeHatch);

    // ------------------------------------------------------------------
    // 错误
    // ------------------------------------------------------------------

    error OutOfOrder();
    error AlreadyAnchored();
    error OutboxAlreadySet();
    error OutboxNotSet();
    error EscapeHatchAlreadySet();
    error Frozen();

    // ------------------------------------------------------------------
    // 构造
    // ------------------------------------------------------------------

    /// @param initialAuthority_ L2 sequencer/运营方地址（生产 = 多签）。
    constructor(address initialAuthority_) AuthorityOwnable(initialAuthority_) {}

    // ------------------------------------------------------------------
    // 配置（一次性）
    // ------------------------------------------------------------------

    function setOutbox(address outbox_) external onlyAuthority {
        if (outbox_ == address(0)) revert ZeroAddress();
        if (address(outbox) != address(0)) revert OutboxAlreadySet();
        outbox = IL1Outbox(outbox_);
        emit OutboxSet(outbox_);
    }

    /// 一次性接线 EscapeHatch（只读 isFrozen() 卫兵；0 永不回滚为未接线态）。
    function setEscapeHatch(address escapeHatch_) external onlyAuthority {
        if (escapeHatch_ == address(0)) revert ZeroAddress();
        if (escapeHatch != address(0)) revert EscapeHatchAlreadySet();
        escapeHatch = escapeHatch_;
        emit EscapeHatchSet(escapeHatch_);
    }

    // ------------------------------------------------------------------
    // 锚定入口（authority；daemon = monad_settlementd anchor 模式）
    // ------------------------------------------------------------------

    /// 逃生舱冻结卫兵：EscapeHatch.freeze 触发后三类锚定全部停摆（旧根事实
    /// 不再推进），未接线（escapeHatch == 0）时短路为零开销、零行为变化。
    modifier whenNotFrozen() {
        if (escapeHatch != address(0) && IEscapeHatch(escapeHatch).isFrozen()) revert Frozen();
        _;
    }

    /// 提交 L2 批次根。index 必须等于当前 batchCount（严格连续）。
    function submitBatch(uint64 index, bytes32 root, uint64 throughOp)
        external
        onlyAuthority
        whenNotPaused
        whenNotFrozen
    {
        if (index != batchCount) revert OutOfOrder();
        batchCount = index + 1;
        batches[index] = Batch({root: root, throughOp: throughOp, l1Block: _block()});
        emit BatchAnchored(index, root, throughOp);
    }

    /// 提交 L2 聚合根（批次根二级折叠）。index 必须等于当前 aggregateCount。
    function submitAggregate(uint64 index, bytes32 root, uint64 throughOp, uint64 batchCount_)
        external
        onlyAuthority
        whenNotPaused
        whenNotFrozen
    {
        if (index != aggregateCount) revert OutOfOrder();
        aggregateCount = index + 1;
        aggregates[index] = Aggregate({
            root: root,
            throughOp: throughOp,
            batchCount: batchCount_,
            l1Block: _block()
        });
        emit AggregateAnchored(index, root, throughOp);
    }

    /// 提交 L2 checkpoint：state root + 提现窗根。
    ///
    /// - 同一 l2Height 重复提交 revert（不可覆写；daemon 幂等由 daemon 侧
    ///   状态文件保证）；
    /// - `withdrawalRoot != 0` 时原子写入 Outbox：L2 侧 ClaimLedger 语义是
    ///   “checkpoint BFT finalized 之后才可上锚”，daemon 保证这一点，故
    ///   直接以 finalized=true 落地；
    /// - `withdrawalRoot == 0` 表示该 checkpoint 无提现窗，合法。
    function submitCheckpoint(
        uint64 l2Height,
        bytes32 stateRoot,
        bytes32 withdrawalRoot,
        uint64 leafCount
    ) external onlyAuthority whenNotPaused whenNotFrozen {
        if (checkpoints[l2Height].l1Block != 0) revert AlreadyAnchored();
        if (address(outbox) == address(0)) revert OutboxNotSet();

        checkpoints[l2Height] = Checkpoint({
            stateRoot: stateRoot,
            withdrawalRoot: withdrawalRoot,
            leafCount: leafCount,
            l1Block: _block()
        });
        emit CheckpointAnchored(l2Height, stateRoot, withdrawalRoot, leafCount);

        if (withdrawalRoot != bytes32(0)) {
            outbox.commitRoot({l2Height: l2Height, leafCount: leafCount, root: withdrawalRoot, finalized: true});
        }
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    function _block() internal view returns (uint64) {
        return uint64(block.number);
    }
}
