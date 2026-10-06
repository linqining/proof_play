// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @title AuthorityOwnable — zchain L2 结算合约栈的公共权限基座
/// @notice 单一 `authority`（= L2 sequencer/运营方，生产建议多签）+
///         两步转移（transfer → accept，防误填地址锁死）+ 全局暂停。
///         自含实现，不引 OpenZeppelin（离线可编译；代码面小、可全量审计）。
abstract contract AuthorityOwnable {
    // ------------------------------------------------------------------
    // 状态
    // ------------------------------------------------------------------

    /// 当前权限方（ sequencer / 运营多签）。
    address public authority;
    /// 待接受的新权限方（两步转移中间态）。
    address public pendingAuthority;
    /// 全局暂停位（暂停时禁止一切状态变更入口，见各 modifier）。
    /// 注意：EscapeHatch 的逃生/恢复侧入口（escape / unfreeze，及
    /// L1Bridge.escapePayoutNative）**有意不带 whenNotPaused**——逃生与恢复
    /// 路径不被本位卡死（资金面安全阀，见 EscapeHatch.sol 信任边界 4），
    /// 勿当 bug 修回。
    bool public paused;

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    event AuthorityTransferStarted(address indexed from, address indexed to);
    event AuthorityAccepted(address indexed previous, address indexed current);
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    // ------------------------------------------------------------------
    // 错误
    // ------------------------------------------------------------------

    error NotAuthority();
    error NotPendingAuthority();
    error ZeroAddress();
    error IsPaused();

    // ------------------------------------------------------------------
    // Modifier
    // ------------------------------------------------------------------

    modifier onlyAuthority() {
        if (msg.sender != authority) revert NotAuthority();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert IsPaused();
        _;
    }

    // ------------------------------------------------------------------
    // 构造 / 权限管理
    // ------------------------------------------------------------------

    constructor(address initialAuthority_) {
        if (initialAuthority_ == address(0)) revert ZeroAddress();
        authority = initialAuthority_;
    }

    /// 发起权限转移（两步之第一步：只有当前 authority 可发起）。
    function transferAuthority(address next) external onlyAuthority {
        if (next == address(0)) revert ZeroAddress();
        pendingAuthority = next;
        emit AuthorityTransferStarted(authority, next);
    }

    /// 接受权限转移（两步之第二步：只有被指定方接受才生效）。
    function acceptAuthority() external {
        if (msg.sender != pendingAuthority) revert NotPendingAuthority();
        address previous = authority;
        pendingAuthority = address(0);
        authority = msg.sender;
        emit AuthorityAccepted(previous, msg.sender);
    }

    /// 全局暂停（提现/入金/上锚全部停摆；治理应急开关）。EscapeHatch 的
    /// escape/unfreeze 与 L1Bridge.escapePayoutNative 有意不受本开关约束
    /// （逃生/恢复不被 pause 卡死，见 natspec——勿当 bug 修回）。
    function pause() external onlyAuthority {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyAuthority {
        paused = false;
        emit Unpaused(msg.sender);
    }
}
