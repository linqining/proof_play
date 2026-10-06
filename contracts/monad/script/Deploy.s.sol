// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {L1Inbox} from "../src/L1Inbox.sol";
import {L1Outbox} from "../src/L1Outbox.sol";
import {L1Bridge} from "../src/L1Bridge.sol";
import {EscapeHatch} from "../src/EscapeHatch.sol";

/// @notice zchain L2 → Monad 结算合约栈一键部署 + 互联。
///
/// 环境变量（`source .env` 或 forge --env-file）：
///   - AUTHORITY_ADDRESS      L2 sequencer/运营方（生产建议多签）——必填；
///   - USDT_ADDRESS/USDC_ADDRESS  可选：配置 tag 3/4 的 L1 代币；
///   - PRIVATE_KEY            部署私钥（默认取 forge 默认 anvil key 便于 devnet）。
///
/// 部署后把打印出的地址写入 monad_settlementd 配置（见
/// docs/monad-l2-settlement.md §runbook）。
contract Deploy is Script {
    // 大额提现延迟基准：Monad 单槽终结（亚秒级），30 块 ≈ 30s 出块窗口，
    // 覆盖异步执行极端情形；主网上线后按审计意见复核。
    uint64 public constant CLAIM_DELAY_BLOCKS = 30;

    function run() external {
        address authority = vm.envOr("AUTHORITY_ADDRESS", address(0));
        if (authority == address(0)) {
            // 未配置时 fail-closed（不静默用 deployer 充当 authority）。
            revert("AUTHORITY_ADDRESS not set");
        }

        uint256 deployerKey = vm.envOr(
            "PRIVATE_KEY",
            uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80) // anvil[0]
        );
        // 互联调用全是 onlyAuthority：部署者必须就是 authority（生产多签
        // 场景请先以 authority 身份完成 wire 步骤，见 README）。
        if (vm.addr(deployerKey) != authority) {
            revert("PRIVATE_KEY must be the authority key (wiring is onlyAuthority)");
        }

        vm.startBroadcast(deployerKey);

        L1Bridge bridge = new L1Bridge(authority);
        L1Outbox outbox = new L1Outbox(authority);
        L1Inbox inbox = new L1Inbox(authority);
        // 逃生舱（第四合约）：依赖 Bridge（escapePayoutNative 支付出口）与
        // Inbox（余额根锚定只读对账）。
        EscapeHatch escapeHatch = new EscapeHatch(authority, address(bridge), address(inbox));

        // 互联：一次性授权边（Inbox → Outbox 写根；Outbox → Bridge 支付；
        // Bridge → 仅 Outbox 可支付；三兄弟 → 只读 EscapeHatch.isFrozen()
        // 冻结卫兵；EscapeHatch → Bridge 逃生支付）。
        outbox.setInbox(address(inbox));
        outbox.setBridge(address(bridge));
        inbox.setOutbox(address(outbox));
        bridge.setOutbox(address(outbox));
        inbox.setEscapeHatch(address(escapeHatch));
        outbox.setEscapeHatch(address(escapeHatch));
        bridge.setEscapeHatch(address(escapeHatch));

        // genesis 余额根（batchIndex 0，豁免 Inbox 对账）：空账本规范根 =
        // 空叶哈希（leafCount=0 → escape 对任意 leafIndex
        // IndexBeyondLeafCount，正确语义）。消「根从零开始」的悬崖——
        // 否则冻结期逃生在首批登记前无根可锚。
        escapeHatch.registerBalanceRoot(0, escapeHatch.emptyLeafHash(), 0);

        // 大额延迟：默认对原生 MON 启用（阈值 100 MON）；代币标签待配置。
        outbox.setClaimDelayBlocks(CLAIM_DELAY_BLOCKS);
        outbox.setLargePayoutThreshold(1, 100 ether);

        // 可选：L1 代币标签映射。
        address usdt = vm.envOr("USDT_ADDRESS", address(0));
        if (usdt != address(0)) outbox.setTokenForTag(3, usdt);
        address usdc = vm.envOr("USDC_ADDRESS", address(0));
        if (usdc != address(0)) outbox.setTokenForTag(4, usdc);

        vm.stopBroadcast();

        console2.log("zchain-monad settlement stack deployed");
        console2.log("  authority  : %s", authority);
        console2.log("  L1Bridge   : %s", address(bridge));
        console2.log("  L1Outbox   : %s", address(outbox));
        console2.log("  L1Inbox    : %s", address(inbox));
        console2.log("  EscapeHatch: %s", address(escapeHatch));
    }
}
