// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Groth16VerifierBatch} from "../src/Groth16VerifierBatch.sol";
import {SettleBatch, BatchProof} from "../src/SettleBatch.sol";
import {BatchGolden} from "./WrapBatchGolden.sol";

/// @notice groth16-wrap 批量金向量链上验证测试（实现 C，扩容口径
///         16 × K4 = 64 条语句，对齐 stark-recursion K=64 桶）。
///
/// # 与 8 条缩样口径的关系
/// - **同一电路族 / 同一 VK**：BatchCircuit 是 sub_n 份单手语句的并列（共享
///   program_hash 绑定）；同形状（sub_n=4）电路共享同一 VK（R1CS 只由形状
///   决定）——16 个证明由同一次 seeded setup 出证，与旧 2 × N4 缩样的
///   verifier 逐字节同钥。
/// - **容量语义**：SettleBatch 对 count = proofs.length × batchN 只要求
///   「≤maxStatements 且为 2 的幂」——扩容实例 maxStatements=64 单 tx 吃下
///   16 证明；旧实例（maxStatements=8）同批会被 BadBatchShape 拒绝（负例
///   test_OldCapacityContractRejects64）。
/// - **同一结算语义**：keccak 根重算（覆盖全批语句）、根一次性、
///   hand_binding 全局一次性与 N 无关。
/// - **批次根口径**：链上 keccak 根锚定「已验证语句集合」；与 poker-appchain
///   Poseidon 批根的对应关系在链下由 groth16-wrap `batch::appchain_batch_root`
///   对拍（Monad 无 Poseidon 预编译）。
contract WrapBatchSettleTest is Test {
    // BN254 标量域 r（篡改测试取模用）
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// settledFact 在 SettleBatch 的存储槽（slot 0 = settledRoots）。
    uint256 internal constant SLOT_SETTLED_FACT = 1;

    Groth16VerifierBatch verifier;
    SettleBatch settle;

    function setUp() public {
        verifier = new Groth16VerifierBatch();
        // 扩容实例：maxStatements 8 → 64（batchN=4 = 证明产源形状：K4）
        settle = new SettleBatch(address(verifier), BatchGolden.SUB_N, 64);
    }

    function _proof(uint256 j) internal pure returns (BatchProof memory p) {
        (p.a, p.b, p.c, ) = BatchGolden.proofCalldata(j);
    }

    function _pubs(uint256 j) internal pure returns (uint256[] memory) {
        (, , , uint256[] memory p) = BatchGolden.proofCalldata(j);
        return p;
    }

    function _allProofs() internal pure returns (BatchProof[] memory proofs, uint256[][] memory pubLists) {
        proofs = new BatchProof[](BatchGolden.SUB_COUNT);
        pubLists = new uint256[][](BatchGolden.SUB_COUNT);
        for (uint256 j = 0; j < BatchGolden.SUB_COUNT; ++j) {
            proofs[j] = _proof(j);
            pubLists[j] = _pubs(j);
        }
    }

    /// leafs[start..start+len] 的两两折叠根（镜像合约重算路径）。
    function _fold(bytes32[] memory leafs, uint256 start, uint256 len) internal pure returns (bytes32) {
        bytes32[] memory level = new bytes32[](len);
        for (uint256 i = 0; i < len; ++i) level[i] = leafs[start + i];
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

    /// 16 个批量证明（16 × K4 = 64 条语句）逐证明链上 verifyProof == true。
    function test_BatchGoldenVerifiesOnEvm() public view {
        for (uint256 j = 0; j < BatchGolden.SUB_COUNT; ++j) {
            assertTrue(verifier.verifyProof(_proof(j).a, _proof(j).b, _proof(j).c, _pubs(j)));
        }
    }

    /// 公开输入长度错误 → verifier 拒绝。
    function test_BadPublicsLengthReverts() public {
        uint256[] memory short = new uint256[](2 * BatchGolden.SUB_N);
        for (uint256 i = 0; i < short.length; ++i) {
            short[i] = _pubs(0)[i];
        }
        vm.expectRevert(Groth16VerifierBatch.BadPublicInputsLength.selector);
        verifier.verifyProof(_proof(0).a, _proof(0).b, _proof(0).c, short);
    }

    /// settleBatch：16 证明 + 64 语句 + keccak 根 → 事件 + 逐手入账 + 根登记。
    function test_SettleBatchRegistersAndEmits() public {
        uint256 count = BatchGolden.SUB_COUNT * BatchGolden.SUB_N;
        vm.expectEmit(true, true, true, true, address(settle));
        emit SettleBatch.BatchSettled(
            address(this), BatchGolden.KECCAK_ROOT, BatchGolden.PROGRAM_HASH,
            BatchGolden.SUB_COUNT, count
        );
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
        // 入账抽查：批首手 / 批末手（pubs[j] = [ph, hb0, fact0, …]）
        (, , , uint256[] memory p0) = BatchGolden.proofCalldata(0);
        (, , , uint256[] memory pLast) = BatchGolden.proofCalldata(BatchGolden.SUB_COUNT - 1);
        assertEq(settle.batchFactOf(p0[1]), p0[2]);
        assertEq(settle.batchFactOf(pLast[pLast.length - 2]), pLast[pLast.length - 1]);
        // 根登记
        assertTrue(settle.settledRoots(BatchGolden.KECCAK_ROOT));
        // 金向量全批根 == 合约重算路径（叶子折叠）自洽
        assertEq(_fold(BatchGolden.leafs(), 0, BatchGolden.TOTAL_STATEMENTS), BatchGolden.KECCAK_ROOT);
        // 叶子非退化
        bytes32[] memory leafs = BatchGolden.leafs();
        assertNotEq(leafs[0], leafs[BatchGolden.TOTAL_STATEMENTS - 1]);
    }

    /// 扩容实例允许子批粒度：单证明（4 语句）独立结算，root 取语句 0..3 子折叠。
    function test_SingleProofSettlesUnderExpandedCapacity() public {
        bytes32 subRoot = _fold(BatchGolden.leafs(), 0, BatchGolden.SUB_N);
        BatchProof[] memory proofs = new BatchProof[](1);
        uint256[][] memory pubLists = new uint256[][](1);
        proofs[0] = _proof(0);
        pubLists[0] = _pubs(0);
        settle.settleBatch(subRoot, proofs, pubLists);
        (, , , uint256[] memory p0) = BatchGolden.proofCalldata(0);
        assertEq(settle.batchFactOf(p0[1]), p0[2]);
        assertTrue(settle.settledRoots(subRoot));
    }

    /// 同一批根二次结算 → AlreadySettledRoot。
    function test_DoubleSettleReverts() public {
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
        vm.expectRevert(SettleBatch.AlreadySettledRoot.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// 篡改批内 fact（第二证明的 fact_0 +1）→ 该证明配平失败 → BadProof。
    function test_TamperedStatementReverts() public {
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        pubLists[1][2] = (pubLists[1][2] + 1) % R;
        vm.expectRevert(SettleBatch.BadProof.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// 假根（真证明 + 不符的 keccakRoot）→ RootMismatch。
    function test_WrongRootReverts() public {
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        vm.expectRevert(SettleBatch.RootMismatch.selector);
        settle.settleBatch(keccak256("wrong"), proofs, pubLists);
    }

    /// 跨证明 program_hash 不一致 → BadBatchShape。
    function test_ProgramHashMismatchReverts() public {
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        pubLists[1][0] = (pubLists[1][0] + 1) % R;
        vm.expectRevert(SettleBatch.BadBatchShape.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// 超容量：17 证明 × 4 = 68 > maxStatements=64 → BadBatchShape（配平前拒）。
    function test_OverCapacityReverts() public {
        BatchProof[] memory proofs = new BatchProof[](BatchGolden.SUB_COUNT + 1);
        uint256[][] memory pubLists = new uint256[][](BatchGolden.SUB_COUNT + 1);
        for (uint256 j = 0; j < BatchGolden.SUB_COUNT; ++j) {
            proofs[j] = _proof(j);
            pubLists[j] = _pubs(j);
        }
        proofs[BatchGolden.SUB_COUNT] = _proof(0);
        pubLists[BatchGolden.SUB_COUNT] = _pubs(0);
        vm.expectRevert(SettleBatch.BadBatchShape.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// count 非 2 的幂：3 证明 × 4 = 12 → BadBatchShape。
    function test_NonPowerOfTwoCountReverts() public {
        BatchProof[] memory proofs = new BatchProof[](3);
        uint256[][] memory pubLists = new uint256[][](3);
        for (uint256 j = 0; j < 3; ++j) {
            proofs[j] = _proof(j);
            pubLists[j] = _pubs(j);
        }
        vm.expectRevert(SettleBatch.BadBatchShape.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// 旧实例容量（maxStatements=8）拒 64 语句批 → BadBatchShape（扩容必须
    /// 换新部署：参数是 immutable 构造项，不能原地改）。
    function test_OldCapacityContractRejects64() public {
        SettleBatch legacy = new SettleBatch(address(verifier), BatchGolden.SUB_N, 8);
        (BatchProof[] memory proofs, uint256[][] memory pubLists) = _allProofs();
        vm.expectRevert(SettleBatch.BadBatchShape.selector);
        legacy.settleBatch(BatchGolden.KECCAK_ROOT, proofs, pubLists);
    }

    /// 跨批 binding 重复：settledFact[hb] 预置非零（镜像先前批已入账）→
    /// DuplicateBinding（根检查通过后逐手入账处 fail）。
    function test_DuplicateBindingAcrossBatchesReverts() public {
        (, uint256[][] memory pubLists) = _allProofs();
        uint256 hb = pubLists[0][1];
        bytes32 slot = keccak256(abi.encode(hb, SLOT_SETTLED_FACT));
        vm.store(address(settle), slot, bytes32(uint256(1)));
        (BatchProof[] memory proofs, uint256[][] memory lists) = _allProofs();
        vm.expectRevert(SettleBatch.DuplicateBinding.selector);
        settle.settleBatch(BatchGolden.KECCAK_ROOT, proofs, lists);
    }

    /// 构造参数校验：batchN 非 2 的幂 / maxStatements < batchN。
    function test_ConstructorRejectsBadParams() public {
        vm.expectRevert(bytes("batchN must be 2^k"));
        new SettleBatch(address(verifier), 3, 64);
        vm.expectRevert(bytes("maxStatements"));
        new SettleBatch(address(verifier), 4, 2);
    }
}
