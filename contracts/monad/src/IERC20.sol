// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// @dev 最小 ERC-20 面（Outbox/Bridge 只需 transfer/transferFrom）。
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);

    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
