// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {AuthorityOwnable} from "./AuthorityOwnable.sol";

/// @notice 逃生舱冻结位查询接口（由 EscapeHatch 实现；两个入金口挂 Frozen
///         卫兵——冻结期新入金停摆（新入金进不了根，逃生覆盖面会漏账）；
///         payout 通道与 forceOp **有意不挂**：claim 预冻结窗保留可领，
///         forceOp 是另一条独立审查通道）。
interface IEscapeHatch {
    function isFrozen() external view returns (bool);
}

/// @title L1Bridge — Monad(L1) 侧资产资金库（deposit 锁仓 / withdrawal 支付）
/// @notice 资产路径：
///          - 入金：用户 `depositNative(to)` 锁 MON → `DepositInitiated` 事件
///            → monad_settlementd bridge 模式监听 → L2 sequencer 以
///            `DepositV2` op 铸 note（deposit_id 幂等，防重复铸造）；
///            ERC-20 同理走 `depositToken`；
///          - 出金：L1Outbox.claim 验证 Merkle 证明后调 `payoutNative` /
///            `payoutToken`（onlyOutbox，单向授权），资金只出不进旁路；
///            另有 `escapePayoutNative`（onlyEscapeHatch，单向授权）——
///            EscapeHatch.freeze 触发后按余额根证明把玩家余额打回。
///         安全要点：入金 nonce 单调递增（L2 侧以此幂等）；支付仅限
///         outbox 与 escapeHatch（两条单向授权，无 owner 提款）；暂停时
///         入金/支付全部停摆（escapePayoutNative 有意除外——逃生路径不被
///         pause 卡死）；资金只能经 Outbox 证明路径或 EscapeHatch 冻结逃生
///         路径流出。
contract L1Bridge is AuthorityOwnable {
    // ------------------------------------------------------------------
    // 存储
    // ------------------------------------------------------------------

    /// 入金 nonce（单调递增；L2 侧 DepositV2.deposit_id 幂等键的原料之一）。
    uint256 public depositNonce;

    /// 强制包含序号（单调递增；L2 侧必须按 seq 升序消费，防审查逃生通道）。
    uint256 public forcedOpSeq;

    /// L1Outbox 地址（唯一支付通道；一次性设置）。
    address public outbox;

    /// EscapeHatch 地址（逃生支付通道；一次性设置。0 = 未接线，冻结卫兵
    /// 短路为零开销、escapePayoutNative 不可用——护既有部署零行为变化）。
    address public escapeHatch;

    // ------------------------------------------------------------------
    // 事件
    // ------------------------------------------------------------------

    /// token = address(0) 表示原生 MON。
    event DepositInitiated(
        uint256 indexed nonce,
        address indexed token,
        address indexed to,
        uint256 amount
    );

    /// 强制包含操作：用户绕过 L2 运营方审查的逃生通道（Phase 1 原语）。
    /// L2 侧必须按 seq 升序消费；未消费由 watcher 审计暴露（validity 结算
    /// 落地后由证明自动强制）。payload 语义 = poker-appchain borsh Operation，
    /// 合约不解释（fail-closed 的解释权在 L2 引擎 + 证明）。
    event ForcedOp(
        uint256 indexed seq,
        address indexed submitter,
        bytes payload
    );
    event OutboxSet(address indexed outbox);
    event EscapeHatchSet(address indexed escapeHatch);

    // ------------------------------------------------------------------
    // 错误
    // ------------------------------------------------------------------

    error NotOutbox();
    error OutboxAlreadySet();
    error OutboxNotSet();
    error NotEscapeHatch();
    error EscapeHatchAlreadySet();
    error BadAmount();
    error BadRecipient();
    error TokenTransferFailed();
    error Frozen();

    // ------------------------------------------------------------------
    // 构造 / 一次性配置
    // ------------------------------------------------------------------

    constructor(address initialAuthority_) AuthorityOwnable(initialAuthority_) {}

    function setOutbox(address outbox_) external onlyAuthority {
        if (outbox_ == address(0)) revert ZeroAddress();
        if (outbox != address(0)) revert OutboxAlreadySet();
        outbox = outbox_;
        emit OutboxSet(outbox_);
    }

    /// 一次性接线 EscapeHatch（0 永不回滚为未接线态）。
    function setEscapeHatch(address escapeHatch_) external onlyAuthority {
        if (escapeHatch_ == address(0)) revert ZeroAddress();
        if (escapeHatch != address(0)) revert EscapeHatchAlreadySet();
        escapeHatch = escapeHatch_;
        emit EscapeHatchSet(escapeHatch_);
    }

    // ------------------------------------------------------------------
    // 入金（用户入口）
    // ------------------------------------------------------------------

    /// 逃生舱冻结卫兵：冻结期入金停摆（新入金进不了余额根，逃生覆盖面会
    /// 漏账）；未接线时短路为零开销、零行为变化。
    modifier whenNotFrozen() {
        if (escapeHatch != address(0) && IEscapeHatch(escapeHatch).isFrozen()) revert Frozen();
        _;
    }

    /// 锁定原生 MON，指定 L2 收款人（<address to> 为 L2 owner 的 EVM 地址
    /// 投影；L2 侧按运营配置映射到 OwnerRef）。
    function depositNative(address to) external payable whenNotPaused whenNotFrozen {
        if (msg.value == 0) revert BadAmount();
        if (to == address(0)) revert BadRecipient();
        uint256 nonce = depositNonce;
        depositNonce = nonce + 1;
        emit DepositInitiated(nonce, address(0), to, msg.value);
    }

    /// 锁定 ERC-20（须先 approve；USDT 等不返回 bool 的代币兼容）。
    function depositToken(address token, address to, uint256 amount) external whenNotPaused whenNotFrozen {
        if (amount == 0) revert BadAmount();
        if (to == address(0)) revert BadRecipient();
        if (token == address(0)) revert BadRecipient();
        _pullToken(token, msg.sender, amount);
        uint256 nonce = depositNonce;
        depositNonce = nonce + 1;
        emit DepositInitiated(nonce, token, to, amount);
    }

    /// 强制包含：把一个 L2 操作（borsh Operation 字节）直接钉在宿主链上。
    /// 任何地址可为任意 L2 账户提交（代办）；L2 引擎消费时按其自身语义校验。
    /// gas 由提交者承担；不锁资金（资金动作仍走 deposit/withdraw 路径）。
    function forceOp(bytes calldata payload) external whenNotPaused {
        if (payload.length == 0) revert BadAmount();
        if (payload.length > 4096) revert BadAmount(); // 单 op 上限（对齐 L2 object 限制面）
        uint256 seq = forcedOpSeq;
        forcedOpSeq = seq + 1;
        emit ForcedOp(seq, msg.sender, payload);
    }

    // ------------------------------------------------------------------
    // 支付通道（仅 Outbox；提现证明验证发生在 Outbox 侧）
    // ------------------------------------------------------------------

    function payoutNative(address to, uint256 amount) external onlyOutbox whenNotPaused {
        if (to == address(0)) revert BadRecipient();
        // 重入面：Outbox 在调用本函数前已写入 claimed 状态；本合约无状态
        // 依赖，回拨重入最多重复请求同一笔支付 → Outbox nonReentrant 面
        // （claimed 已置位 → AlreadyClaimed）兜底。
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TokenTransferFailed();
    }

    function payoutToken(address token, address to, uint256 amount)
        external
        onlyOutbox
        whenNotPaused
    {
        if (to == address(0)) revert BadRecipient();
        _pushToken(token, to, amount);
    }

    /// 逃生通道：EscapeHatch 冻结期按余额根 Merkle 证明直接支付玩家余额
    /// （onlyEscapeHatch 单向授权；**有意不带 whenNotPaused**——逃生路径
    /// 不被 pause 卡死，勿当 bug 修回）。资金面兜底与 payoutNative 同式：
    /// Bridge 余额不足即 revert（fail-closed），escape×claim 交叉双花只改
    /// 分配不增总支出（总流出 ≤ Bridge 浮存）。
    function escapePayoutNative(address to, uint256 amount) external onlyEscapeHatch {
        if (to == address(0)) revert BadRecipient();
        // 重入面同 payoutNative：EscapeHatch 侧 CEI（escaped 台账先置位），
        // 回拨重入撞 AlreadyEscaped；收款人主动 revert 会毒化本次打款
        // （ok=false → 整笔 escape 回滚、台账还原，可重试）。
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TokenTransferFailed();
    }

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    modifier onlyOutbox() {
        if (msg.sender != outbox) revert NotOutbox();
        _;
    }

    modifier onlyEscapeHatch() {
        if (msg.sender != escapeHatch) revert NotEscapeHatch();
        _;
    }

    /// USDT 兼容的 transferFrom：调用成功且（无返回值 或 返回 true）即认成。
    function _pullToken(address token, address from, uint256 amount) private {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, address(this), amount));
        if (!ok || (ret.length != 0 && !(ret.length == 32 && abi.decode(ret, (bool))))) {
            revert TokenTransferFailed();
        }
    }

    function _pushToken(address token, address to, uint256 amount) private {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!ok || (ret.length != 0 && !(ret.length == 32 && abi.decode(ret, (bool))))) {
            revert TokenTransferFailed();
        }
    }
}
