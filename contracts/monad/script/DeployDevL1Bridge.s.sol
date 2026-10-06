// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {L1Bridge} from "../src/L1Bridge.sol";

/// @title DeployDevL1Bridge — dev/testnet 单合约部署（买入闭环最小件）
/// @notice authority = 部署者（dev 单签；testnet 演进为运营多签后换正式
///         部署脚本）。本地 anvil 全流程：
///
///         anvil --chain-id 10143
///         forge script script/DeployDevL1Bridge.s.sol \
///           --rpc-url http://127.0.0.1:8545 --broadcast
///
///         输出地址写入两端 env：
///         server: MONAD_L1BRIDGE_ADDRESS=0x… TEXAS_APPCHAIN_PROVIDER=monad
///                 MONAD_RPC_URL=http://127.0.0.1:8545
///         client: VITE_MONAD_L1BRIDGE_ADDRESS=0x… VITE_DEV_ANVIL_RPC=http://127.0.0.1:8545
contract DeployDevL1Bridge is Script {
    /// anvil 预置账户 #0（默认；DEPLOY_PRIVATE_KEY 可覆盖，testnet 用）。
    uint256 private constant ANVIL_KEY0 =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external {
        uint256 pk = vm.envOr("DEPLOY_PRIVATE_KEY", ANVIL_KEY0);
        vm.startBroadcast(pk);
        L1Bridge bridge = new L1Bridge(vm.addr(pk));
        vm.stopBroadcast();
        console.log("L1Bridge:", address(bridge));
    }
}
