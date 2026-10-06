// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @dev L1Outbox 对资金库（L1Bridge）的支付通道。
interface IL1Bridge {
    /// 原生 MON 支付（仅 Outbox 可调，见 L1Bridge.onlyOutbox）。
    function payoutNative(address to, uint256 amount) external;

    /// ERC-20 支付（仅 Outbox 可调）。
    function payoutToken(address token, address to, uint256 amount) external;

    /// 原生 MON 逃生支付（仅 EscapeHatch 可调，见 L1Bridge.onlyEscapeHatch）。
    function escapePayoutNative(address to, uint256 amount) external;
}
