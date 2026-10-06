// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StarkVerifier} from "../src/StarkVerifier.sol";

/// @dev StarkVerifier 金向量测试 —— Rust↔Solidity ABI 交叉钉扎 + 骨架 fail-closed。
///
/// 金向量出处：poker_texas_air stark-recursion
/// `src/onchain.rs::submit_final_calldata_layout` 测试（cargo test -- --nocapture
/// 打印 GOLDEN_FINAL_CALLDATA，2026-09-29）——同一 (root, acc, fact, commit, proof)
/// 输入下 Rust `encode_submit_final_calldata` 与 Solidity `abi.encodeWithSelector`
/// 逐字节一致；selector 双侧 keccak 一致。
contract StarkVerifierGoldenTest is Test {
    StarkVerifier internal verifier;

    address internal constant AUTHORITY = 0xa11ce00000000000000000000000000000000001;
    address internal constant INBOX = 0x60eCdDD1359356A43a69de84a1CF235A69A30E71;

    // 与 Rust onchain 测试相同的金向量输入
    bytes32 internal constant ROOT =
        0x01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979c;
    bytes32 internal constant ACC_PREV =
        0x000000000000000000000000000000000000000000000000000000000000acc1;
    bytes32 internal constant BATCH_FACT =
        0x0000000000000000000000000000000000000000000000000000000000004c1f;
    bytes32 internal constant OUTPUT_COMMIT =
        0x000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d;
    bytes internal constant PROOF = hex"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    /// Rust 侧 GOLDEN_FINAL_CALLDATA（逐字节 fixture）
    bytes internal constant GOLDEN_CALLDATA =
        hex"e8faf28501060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979c000000000000000000000000000000000000000000000000000000000000acc10000000000000000000000000000000000000000000000000000000000004c1f000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000405a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

    function setUp() public {
        verifier = new StarkVerifier(AUTHORITY, INBOX);
    }

    /// selector 金向量：keccak("submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)")
    /// 必须等于 Rust 侧 calldata 头 4 字节。
    function test_selector_matches_rust_golden() public pure {
        bytes4 sel = StarkVerifier.submitFinalProof.selector;
        assertEq(bytes4(GOLDEN_CALLDATA), sel, "rust golden calldata head must equal solidity selector");
        assertEq(sel, bytes4(keccak256("submitFinalProof(bytes32,bytes32,bytes32,bytes32,bytes)")));
    }

    /// Solidity 侧重编码（同输入）与 Rust 金向量逐字节一致（head 落位 + 动态
    /// bytes 偏移 0xa0 + 长度 0x40）。
    function test_solidity_reencode_matches_rust_bytes() public pure {
        bytes memory cd = abi.encodeWithSelector(
            StarkVerifier.submitFinalProof.selector, ROOT, ACC_PREV, BATCH_FACT, OUTPUT_COMMIT, PROOF
        );
        assertEq(cd, GOLDEN_CALLDATA, "reencoded calldata must equal rust golden bytes");
    }

    /// 部署面：authority/Inbox/累加链 genesis。
    function test_deployment_state() public view {
        assertEq(verifier.authority(), AUTHORITY);
        assertEq(verifier.l1Inbox(), INBOX);
        assertEq(verifier.latestFact(), 0, "genesis latestFact is zero");
        assertEq(
            verifier.BATCH_PROGRAM_HASH(),
            uint256(0x05c400b46a261c6672cd7581436754e05da2287ba8ecdc69778d06e4ef831803),
            "program hash pinning must equal stark_final BATCH_PROGRAM_HASH_HEX"
        );
    }

    /// fail-closed 骨架：FRI 核心未交付 → 一律 revert（绝不伪造验证通过）。
    function test_submit_reverts_until_fri_core_delivered() public {
        // genesis 链头 = 0 → accPrev=0 通过链检查，断言落在 FRI 骨架 fail-closed
        vm.prank(AUTHORITY);
        vm.expectRevert(StarkVerifier.FRIVerifierNotDelivered.selector);
        verifier.submitFinalProof(ROOT, bytes32(0), BATCH_FACT, OUTPUT_COMMIT, PROOF);
        // 无状态变更
        assertEq(verifier.latestFact(), 0);
        assertEq(verifier.settledFact(ROOT), 0);
    }

    /// acc 链负例：accPrev != latestFact 先于 FRI 检查拒绝。
    function test_submit_reverts_on_acc_chain_mismatch() public {
        bytes32 wrongAcc = bytes32(uint256(0xdead));
        vm.prank(AUTHORITY);
        vm.expectRevert(StarkVerifier.AccChainMismatch.selector);
        verifier.submitFinalProof(ROOT, wrongAcc, BATCH_FACT, OUTPUT_COMMIT, PROOF);
    }

    /// 空 proof 拒绝。
    function test_submit_reverts_on_empty_proof() public {
        vm.prank(AUTHORITY);
        vm.expectRevert(StarkVerifier.EmptyProof.selector);
        verifier.submitFinalProof(ROOT, bytes32(0), BATCH_FACT, OUTPUT_COMMIT, "");
    }

    /// 非 authority 拒绝。
    function test_submit_reverts_on_non_authority() public {
        vm.prank(address(0xB0B));
        vm.expectRevert();
        verifier.submitFinalProof(ROOT, ACC_PREV, BATCH_FACT, OUTPUT_COMMIT, PROOF);
    }
}
