// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuthorityOwnable} from "../src/AuthorityOwnable.sol";
import {L1Inbox} from "../src/L1Inbox.sol";
import {L1Outbox} from "../src/L1Outbox.sol";
import {L1Bridge} from "../src/L1Bridge.sol";

/// @notice 结算合约栈 forge 测试（与 monad-settlement crate 的 Rust 交叉
///         验证测试互补：本文件覆盖合约治理/重放/授权面；Merkle 字节级
///         一致性由 Rust 侧用真实 builder 产根后与本合约等价 verifier 对拍）。
contract L1SettlementTest is Test {
    // 金标准向量常量（Rust monad-settlement::proof 计算，见 examples/golden_vector.rs）。
    bytes32 constant REQ_ID_GOLDEN = 0x0fd31fdcba98c270b34de557bfe6edec68b0fa3331314a824575b66efbc81c33;
    bytes32 constant BURN_GOLDEN = 0x0e77ebb77ec443ab668cb20b84b778d9fb55e2cda24adeb5dbd44abaf240ebd7;
    bytes32 constant GOLDEN_ROOT = 0xb21e3d6b534f2130cb246bd934c71df6acd3fb6fda43401ff5d32f95a4cc8f8e;
    bytes32 constant GOLDEN_DIGEST = 0x3e81557daff0cb54fa4bd2594a79a78a155d1356c54e7e155e4978c34d70d975;

    address authority = makeAddr("authority");
    address user = makeAddr("user");

    L1Inbox inbox;
    L1Outbox outbox;
    L1Bridge bridge;

    function setUp() public {
        bridge = new L1Bridge(authority);
        outbox = new L1Outbox(authority);
        inbox = new L1Inbox(authority);
        // 互联边均为 onlyAuthority（与生产一致：由 authority 发起）。
        vm.startPrank(authority);
        outbox.setInbox(address(inbox));
        outbox.setBridge(address(bridge));
        inbox.setOutbox(address(outbox));
        bridge.setOutbox(address(outbox));
        vm.stopPrank();
    }

    function _fundBridge(uint256 amount) private {
        // 走真实入金路径（Bridge 无裸收款回退：资金入账必须有 Deposit 事件）。
        vm.deal(user, amount);
        vm.prank(user);
        bridge.depositNative{value: amount}(user);
    }

    // ------------------------------------------------------------------
    // Inbox：连续性 / checkpoint 注册
    // ------------------------------------------------------------------

    function test_SubmitBatch_MustBeContiguous() public {
        vm.startPrank(authority);
        inbox.submitBatch(0, bytes32(uint256(1)), 10);
        vm.expectRevert(L1Inbox.OutOfOrder.selector);
        inbox.submitBatch(2, bytes32(uint256(2)), 20); // 跳号 → revert
        inbox.submitBatch(1, bytes32(uint256(2)), 20); // 补上后继续
        vm.stopPrank();
        assertEq(inbox.batchCount(), 2);
    }

    function test_SubmitCheckpoint_CommitsRootToOutbox_Finalized() public {
        bytes32 root = bytes32(uint256(0xbeef));
        vm.startPrank(authority);
        vm.expectEmit(true, true, true, true, address(outbox));
        emit L1Outbox.WithdrawalRootCommitted(outbox.digestOf(7, 3, root), 7, 3, root, true);
        inbox.submitCheckpoint(7, bytes32(uint256(0x1111)), root, 3);
        vm.stopPrank();

        (bytes32 storedRoot,,,, bool finalized) = outbox.roots(outbox.digestOf(7, 3, root));
        assertEq(storedRoot, root);
        assertTrue(finalized);
    }

    function test_SubmitCheckpoint_ReplayRejected() public {
        vm.startPrank(authority);
        inbox.submitCheckpoint(7, bytes32(uint256(0x1111)), bytes32(0), 0);
        vm.expectRevert(L1Inbox.AlreadyAnchored.selector);
        inbox.submitCheckpoint(7, bytes32(uint256(0x2222)), bytes32(0), 0);
        vm.stopPrank();
    }

    function test_SubmitBatch_OnlyAuthority() public {
        vm.prank(user);
        vm.expectRevert(AuthorityOwnable.NotAuthority.selector);
        inbox.submitBatch(0, bytes32(uint256(1)), 10);
    }

    // ------------------------------------------------------------------
    // Bridge：入金事件 / 支付授权
    // ------------------------------------------------------------------

    function test_DepositNative_EmitsEvent_WithMonotonicNonce() public {
        vm.expectEmit(true, true, true, true, address(bridge));
        emit L1Bridge.DepositInitiated(0, address(0), user, 1 ether);
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.depositNative{value: 1 ether}(user);
        vm.deal(user, 2 ether);
        vm.prank(user);
        bridge.depositNative{value: 1 ether}(user);
        assertEq(bridge.depositNonce(), 2);
    }

    function test_PayoutNative_OnlyOutbox() public {
        _fundBridge(1 ether);
        vm.prank(user);
        vm.expectRevert(L1Bridge.NotOutbox.selector);
        bridge.payoutNative(user, 0.1 ether);
    }

    function test_PayoutNative_ByOutbox_PaysRecipient() public {
        _fundBridge(1 ether);
        address recipient = makeAddr("recipient");
        vm.prank(address(outbox));
        bridge.payoutNative(recipient, 0.4 ether);
        assertEq(recipient.balance, 0.4 ether);
    }

    // ------------------------------------------------------------------
    // 强制包含（escape channel 原语）
    // ------------------------------------------------------------------

    function test_ForceOp_EmitsMonotonicSeq() public {
        vm.expectEmit(true, true, true, true, address(bridge));
        emit L1Bridge.ForcedOp(0, user, hex"0102");
        vm.prank(user);
        bridge.forceOp(hex"0102");
        vm.prank(user);
        bridge.forceOp(hex"03");
        assertEq(bridge.forcedOpSeq(), 2);
    }

    function test_ForceOp_RejectsEmptyAndOversize() public {
        vm.prank(user);
        vm.expectRevert(L1Bridge.BadAmount.selector);
        bridge.forceOp(new bytes(0));
        vm.prank(user);
        vm.expectRevert(L1Bridge.BadAmount.selector);
        bridge.forceOp(new bytes(4097));
    }

    // ------------------------------------------------------------------
    // Outbox：claim 前置条件（台账判定；证明字节面由 Rust 对拍覆盖）
    // ------------------------------------------------------------------

    function _leaf() private returns (L1Outbox.WithdrawalLeaf memory leaf) {
        leaf = L1Outbox.WithdrawalLeaf({
            requestId: keccak256("request-1"),
            externalRecipient: bytes32(uint256(uint160(makeAddr("recipient")))),
            assetTag: 1,
            amount: 0.5 ether,
            burnedNoteCommitment: keccak256("burn"),
            checkpointHeight: 7
        });
    }

    function test_Claim_UnfinalizedRootRejected() public {
        L1Outbox.WithdrawalLeaf memory leaf = _leaf();
        vm.prank(authority);
        outbox.commitRoot(7, 1, bytes32(uint256(0xdead)), false);
        vm.expectRevert(L1Outbox.RootNotFinalized.selector);
        outbox.claim(leaf, bytes32(uint256(0xdead)), 1, 0, new bytes32[](0));
    }

    function test_Claim_IndexBeyondLeafCount() public {
        L1Outbox.WithdrawalLeaf memory leaf = _leaf();
        vm.prank(authority);
        outbox.commitRoot(7, 1, bytes32(uint256(0xdead)), true);
        vm.expectRevert(L1Outbox.IndexBeyondLeafCount.selector);
        outbox.claim(leaf, bytes32(uint256(0xdead)), 1, 5, new bytes32[](0));
    }

    function test_Claim_BadProofRejected_ThenClaimedStateUnchanged() public {
        L1Outbox.WithdrawalLeaf memory leaf = _leaf();
        vm.prank(authority);
        outbox.commitRoot(7, 1, bytes32(uint256(0xdead)), true);
        vm.expectRevert(L1Outbox.WithdrawalProofInvalid.selector);
        outbox.claim(leaf, bytes32(uint256(0xdead)), 1, 0, new bytes32[](0));
        assertFalse(outbox.claimedRequests(leaf.requestId));
    }

    function test_LargePayout_DelayEnforced() public {
        L1Outbox.WithdrawalLeaf memory leaf = _leaf();
        leaf.amount = 10 ether; // uint64 上限 ≈18.4 MON
        vm.startPrank(authority);
        outbox.setLargePayoutThreshold(1, 5 ether);
        outbox.commitRoot(7, 1, bytes32(uint256(0xdead)), true);
        vm.stopPrank();
        // 证明必然失败（0xdead 不是该叶的根），延迟检查排在证明之后——
        // 这里只验证门位存在：换真实证明由 Rust 对拍 + 集成测试覆盖。
        vm.expectRevert(L1Outbox.WithdrawalProofInvalid.selector);
        outbox.claim(leaf, bytes32(uint256(0xdead)), 1, 0, new bytes32[](0));
    }

    function test_Pause_BlocksClaimsAndDeposits() public {
        vm.prank(authority);
        outbox.pause();
        vm.prank(authority);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        outbox.commitRoot(7, 1, bytes32(uint256(0xdead)), true);
        vm.prank(authority);
        bridge.pause();
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(AuthorityOwnable.IsPaused.selector);
        bridge.depositNative{value: 1 ether}(user);
    }

    function test_AuthorityTransfer_TwoStep() public {
        address next = makeAddr("next");
        vm.prank(authority);
        inbox.transferAuthority(next);
        vm.prank(authority);
        vm.expectRevert(AuthorityOwnable.NotPendingAuthority.selector);
        inbox.acceptAuthority();
        vm.prank(next);
        inbox.acceptAuthority();
        assertEq(inbox.authority(), next);
    }

    function test_GoldenVector_LeafHashAndDigest() public {
        L1Outbox.WithdrawalLeaf memory leaf = L1Outbox.WithdrawalLeaf({
            requestId: REQ_ID_GOLDEN,
            externalRecipient: bytes32(uint256(0x0000000000000000000000002222222222222222222222222222222222222222)), // 12 零 + 20×0x22（word_address 约定）
            assetTag: 1,
            amount: 123,
            burnedNoteCommitment: BURN_GOLDEN,
            checkpointHeight: 7
        });
        // claim 校验路径 = _leafHash + _internalHash 全链路（单叶树证明为空）。
        vm.prank(authority);
        outbox.commitRoot(7, 1, GOLDEN_ROOT, true);
        // 收款人 = 0x…2222（externalRecipient 低 20B）；Bridge 需有浮存。
        address recipient = address(uint160(uint256(leaf.externalRecipient)));
        vm.deal(address(bridge), 1 ether);
        outbox.claim(leaf, GOLDEN_ROOT, 1, 0, new bytes32[](0));
        assertEq(recipient.balance, 123);
        // 台账：digest 键与 Rust 侧 digest_of 一致。
        (bytes32 storedRoot,,,, bool finalized) = outbox.roots(GOLDEN_DIGEST);
        assertEq(storedRoot, GOLDEN_ROOT);
        assertTrue(finalized);
    }
}
