// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {SettleBatch, BatchProof} from "../src/SettleBatch.sol";
import {BatchGolden} from "../test/WrapBatchGolden.sol";

/// @notice 把 64 语句批的 `settleBatch` calldata 落盘，供 monad-settlement
///         执行器 `monad_settle_batch` 按「限 gas eth_call 二分 → limit =
///         need×1.1 → 节点价」纪律发送。
///
/// 产物 `/tmp/settle64_plan/plan.json`（或 env DUMP_PATH）：
///   {"batches":[
///     {"name":"full","root":"0x…","calldata":"0x…","hbs":[64],"facts":[64]},
///     {"name":"sub0",…,"hbs":[8],"facts":[8]},   // 8 个 8 语句子批
///     … {"name":"sub7",…}]}
///
/// calldata 编码与本地测试同一 Solidity 路径（abi.encodeWithSelector），
/// 避免手写 ABI 的字序/偏移错误；子批根 = 该子批语句集的两两折叠（与
/// SettleBatch 链上重算同式），全批根对拍 BatchGolden.KECCAK_ROOT。
contract DumpBatchCalldata is Script {
    function run() external {
        string memory path = vm.envOr("DUMP_PATH", string("/tmp/settle64_plan/plan.json"));

        // 全量批根自洽：脚本折叠 == gen-sol-batch 注入常量
        require(_fold(BatchGolden.leafs()) == BatchGolden.KECCAK_ROOT, "golden keccak root mismatch");

        string memory plan = string.concat('{"batches":[');
        plan = string.concat(plan, _batchJson("full", 0, BatchGolden.SUB_COUNT));
        for (uint256 k = 0; k < BatchGolden.SUB_COUNT / 2; ++k) {
            plan = string.concat(
                plan, ",", _batchJson(string.concat("sub", vm.toString(k)), k * 2, 2)
            );
        }
        plan = string.concat(plan, "]}");
        vm.writeFile(path, plan);
        console2.log("plan written:", path);
        console2.log("  full: 16 proofs, 64 statements");
        console2.log("  sub:  8 x (2 proofs, 8 statements)");
    }

    /// proofs[j0..j0+proofCount) 的 settleBatch calldata + 子批根 + 语句清单。
    function _batchJson(string memory name, uint256 j0, uint256 proofCount)
        internal
        pure
        returns (string memory)
    {
        uint256 n = BatchGolden.SUB_N;
        BatchProof[] memory proofs = new BatchProof[](proofCount);
        uint256[][] memory pubLists = new uint256[][](proofCount);
        for (uint256 j = 0; j < proofCount; ++j) {
            (proofs[j].a, proofs[j].b, proofs[j].c, pubLists[j]) = BatchGolden.proofCalldata(j0 + j);
        }
        // 子批根：叶子必须按 **tx 内局部序号** 重算（leaf = keccak(uint32(i) ‖ ph ‖ hb ‖
        // fact)，i = j*n+i 为本 tx 内的语句槽位——SettleBatch 链上重算口径；
        // 全批 64 语句时局部序号 == 金向量全局序号，拆子批时二者分叉，不能
        // 复用 BatchGolden.leafs() 的全局序号叶子）。
        uint256 ph = pubLists[0][0];
        bytes32[] memory leafs = new bytes32[](proofCount * n);
        for (uint256 j = 0; j < proofCount; ++j) {
            for (uint256 i = 0; i < n; ++i) {
                uint256 idx = j * n + i;
                leafs[idx] = keccak256(
                    abi.encodePacked(uint32(idx), ph, pubLists[j][1 + 2 * i], pubLists[j][2 + 2 * i])
                );
            }
        }
        bytes32 root = _fold(leafs);
        bytes memory cd = abi.encodeWithSelector(SettleBatch.settleBatch.selector, root, proofs, pubLists);

        string memory hbs = "[";
        string memory facts = "[";
        for (uint256 j = 0; j < proofCount; ++j) {
            for (uint256 i = 0; i < n; ++i) {
                if (bytes(hbs).length > 1) {
                    hbs = string.concat(hbs, ",");
                    facts = string.concat(facts, ",");
                }
                uint256 hb = pubLists[j][1 + 2 * i];
                uint256 fact = pubLists[j][2 + 2 * i];
                hbs = string.concat(hbs, '"', vm.toString(bytes32(hb)), '"');
                facts = string.concat(facts, '"', vm.toString(bytes32(fact)), '"');
            }
        }
        return string.concat(
            '{"name":"', name,
            '","root":"', vm.toString(root),
            '","calldata":"', vm.toString(cd),
            '","hbs":', hbs, ']',
            ',"facts":', facts, ']',
            '}'
        );
    }

    /// 两两折叠根（镜像 SettleBatch 链上重算路径）。
    function _fold(bytes32[] memory leafs) internal pure returns (bytes32) {
        bytes32[] memory level = leafs;
        while (level.length > 1) {
            uint256 nextLen = level.length / 2;
            for (uint256 i = 0; i < nextLen; ++i) {
                level[i] = keccak256(abi.encodePacked(level[2 * i], level[2 * i + 1]));
            }
            assembly {
                mstore(level, nextLen)
            }
        }
        return level[0];
    }
}
