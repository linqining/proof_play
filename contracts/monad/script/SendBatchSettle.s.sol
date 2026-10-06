// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {SettleBatch, BatchProof} from "../src/SettleBatch.sol";
import {L1Inbox} from "../src/L1Inbox.sol";
import {BatchGolden} from "../test/WrapBatchGolden.sol";

/// @notice E2E 批量腿上链广播：anchor（L1Inbox.submitBatch）+ settle（SettleBatch.settleBatch）。
/// @dev 编码与本地测试同一 Solidity 路径（避免手写 ABI 的字序/偏移错误）；
///      calldata 证明取自 WrapBatchGolden.sol 常量（gen-sol-batch 重写后的真实语句版本）。
///      gas 纪律（est×1.1 + 节点价）由调用侧 env 传入：
///        ANCHOR_LIMIT / SETTLE_LIMIT / GAS_PRICE（wei，三值均必填）。
///      ANCHOR_INDEX = L1Inbox 当前 batchCount（严格连续纪律）；
///      ANCHOR_THROUGH_OP = 本批覆盖的最大 WAL 帧号。
contract SendBatchSettle is Script {
    function run() external {
        address settleBatchAddr = vm.envAddress("SETTLEBATCH_ADDR");
        address inboxAddr = vm.envAddress("INBOX_ADDR");
        uint256 anchorIndex = vm.envUint("ANCHOR_INDEX");
        uint256 anchorThroughOp = vm.envUint("ANCHOR_THROUGH_OP");
        bytes32 root = BatchGolden.KECCAK_ROOT;
        uint256 gasPrice = vm.envUint("GAS_PRICE");
        uint256 anchorLimit = vm.envUint("ANCHOR_LIMIT");
        uint256 settleLimit = vm.envUint("SETTLE_LIMIT");
        string memory mode = vm.envOr("MODE", string("all"));

        uint256 broadcasterKey = vm.envUint("PRIVATE_KEY");
        vm.txGasPrice(gasPrice);
        vm.startBroadcast(broadcasterKey);

        if (keccak256(bytes(mode)) == keccak256("anchor") || keccak256(bytes(mode)) == keccak256("all")) {
            L1Inbox(inboxAddr).submitBatch{gas: anchorLimit}(
                uint64(anchorIndex), root, uint64(anchorThroughOp)
            );
        }
        if (keccak256(bytes(mode)) == keccak256("settle") || keccak256(bytes(mode)) == keccak256("all")) {
            BatchProof[] memory proofs = new BatchProof[](BatchGolden.SUB_COUNT);
            uint256[][] memory pubLists = new uint256[][](BatchGolden.SUB_COUNT);
            for (uint256 j = 0; j < BatchGolden.SUB_COUNT; ++j) {
                (proofs[j].a, proofs[j].b, proofs[j].c, pubLists[j]) = BatchGolden.proofCalldata(j);
            }
            SettleBatch(settleBatchAddr).settleBatch{gas: settleLimit}(root, proofs, pubLists);
        }
        vm.stopBroadcast();
    }
}
